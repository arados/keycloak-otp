package hr.delmisoft.keycloak.otp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;

/**
 * Per-(realm, user, channel) cooldown for OTP send operations.
 * Backed by {@link SingleUseObjectProvider} (Infinispan / cluster-safe).
 *
 * <p>Use {@link #tryReserve} before sending. If it returns false, do not send —
 * the previous send is still within the cooldown window. Use
 * {@link #remainingSeconds} for UI countdowns or HTTP {@code Retry-After} headers.
 */
public final class OtpSendThrottle {

    public static final String CHANNEL_EMAIL = "email";
    public static final String CHANNEL_SMS = "sms";

    public static final String CONFIG_SEND_COOLDOWN = "otp.sendCooldown";
    public static final int DEFAULT_SEND_COOLDOWN = 60;

    private static final String KEY_PREFIX = "otp-throttle:";
    private static final String NOTE_EXPIRES_AT = "expiresAt";
    private static final String NOTE_CODE_HASH = "codeHash";
    private static final String NOTE_CODE_SALT = "codeSalt";
    private static final String NOTE_CODE_EXPIRES_AT = "codeExpiresAt";

    private OtpSendThrottle() {}

    /**
     * Hash + salt + expiry of the most-recently-sent OTP for a (realm, user, channel) tuple.
     * Used to recover validatable state into a fresh auth session when the cooldown blocks a
     * new send, so a legitimate user who restarts login within the cooldown can still
     * complete it with the code that was actually delivered to them. The raw OTP is never
     * persisted — submissions are verified against the stored hash.
     */
    public static final class RecentCode {
        public final String codeHash;
        public final String codeSalt;
        public final int expiresAt;

        public RecentCode(String codeHash, String codeSalt, int expiresAt) {
            this.codeHash = codeHash;
            this.codeSalt = codeSalt;
            this.expiresAt = expiresAt;
        }
    }

    /**
     * Attempt to reserve a send slot. Returns {@code true} if the caller may send,
     * {@code false} if the previous send is still within {@code cooldownSec}.
     */
    public static boolean tryReserve(KeycloakSession session, RealmModel realm, UserModel user,
                                     String channel, int cooldownSec) {
        return tryReserveWithCodeHash(session, realm, user, channel, cooldownSec, null, null, 0);
    }

    /**
     * Like {@link #tryReserve} but, on success, also stashes the {@code codeHash} (salted SHA-256
     * of the OTP, see {@link OtpHash}), its {@code codeSalt}, and the absolute expiry timestamp
     * (epoch seconds) alongside the cooldown so that later sessions blocked by the cooldown can
     * recover validatable state via {@link #getRecentCode}.
     */
    public static boolean tryReserveWithCodeHash(KeycloakSession session, RealmModel realm, UserModel user,
                                                 String channel, int cooldownSec,
                                                 String codeHash, String codeSalt, int codeExpiresAt) {
        if (cooldownSec <= 0) {
            return true;
        }
        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        String key = buildKey(realm, user, channel);
        if (!store.putIfAbsent(key, cooldownSec)) {
            return false;
        }
        Map<String, String> notes = new HashMap<>();
        notes.put(NOTE_EXPIRES_AT, String.valueOf(Time.currentTime() + cooldownSec));
        if (codeHash != null && codeSalt != null) {
            notes.put(NOTE_CODE_HASH, codeHash);
            notes.put(NOTE_CODE_SALT, codeSalt);
            notes.put(NOTE_CODE_EXPIRES_AT, String.valueOf(codeExpiresAt));
        }
        // Keep the meta entry alive at least as long as the code TTL so a later, throttled
        // session can still recover the code after the cooldown sub-window elapses.
        int metaTtl = Math.max(cooldownSec, Math.max(0, codeExpiresAt - Time.currentTime()));
        store.put(key + ":meta", metaTtl, notes);
        return true;
    }

    /**
     * Releases an existing reservation. Used when delivery fails after a successful
     * {@link #tryReserveWithCodeHash} so the user is not locked out of retries by a
     * cooldown protecting an OTP that was never delivered.
     */
    public static void release(KeycloakSession session, RealmModel realm, UserModel user, String channel) {
        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        String key = buildKey(realm, user, channel);
        store.remove(key);
        store.remove(key + ":meta");
    }

    /**
     * Returns the most recently stashed hash/salt/expiry for this (realm, user, channel)
     * tuple, or {@code null} if there is no active stash or the code has expired.
     */
    public static RecentCode getRecentCode(KeycloakSession session, RealmModel realm, UserModel user,
                                           String channel) {
        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        Map<String, String> meta = store.get(buildKey(realm, user, channel) + ":meta");
        if (meta == null) {
            return null;
        }
        String codeHash = meta.get(NOTE_CODE_HASH);
        String codeSalt = meta.get(NOTE_CODE_SALT);
        String expiryStr = meta.get(NOTE_CODE_EXPIRES_AT);
        if (codeHash == null || codeSalt == null || expiryStr == null) {
            return null;
        }
        try {
            int expiresAt = Integer.parseInt(expiryStr);
            if (Time.currentTime() >= expiresAt) {
                return null;
            }
            return new RecentCode(codeHash, codeSalt, expiresAt);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Remaining cooldown seconds (clamped to 0). Returns 0 if no active reservation.
     */
    public static int remainingSeconds(KeycloakSession session, RealmModel realm, UserModel user, String channel) {
        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        Map<String, String> meta = store.get(buildKey(realm, user, channel) + ":meta");
        if (meta == null) {
            return 0;
        }
        String expiresAtStr = meta.get(NOTE_EXPIRES_AT);
        if (expiresAtStr == null) {
            return 0;
        }
        try {
            int remaining = Integer.parseInt(expiresAtStr) - Time.currentTime();
            return Math.max(0, remaining);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Atomically reserves one verification attempt against a specific delivered code
     * (identified by its {@code codeHash}), shared by every auth session for this
     * (realm, user, channel) tuple. Call it <em>before</em> verifying a submission.
     *
     * <p>Attempts are tracked as numbered slot keys
     * ({@code ...:attempt:{codeHash}:{n}} for {@code n} in {@code 0..maxAttempts-1}) reserved
     * with {@link SingleUseObjectProvider#putIfAbsent}, so concurrent submissions from any
     * number of sessions or cluster nodes can never consume more than {@code maxAttempts}
     * slots — there is no read-modify-write. Slots live until {@code codeExpiresAt}, so
     * neither a Resend within the cooldown nor a fresh auth session that recovers the
     * same code via {@link #getRecentCode} can restore the attempt budget.
     *
     * @return the 1-based attempt number reserved, or {@code 0} if the code has no attempts
     *         left (callers must then reject the submission without verifying it)
     */
    public static int tryConsumeAttempt(KeycloakSession session, RealmModel realm, UserModel user,
                                        String channel, String codeHash, int maxAttempts, int codeExpiresAt) {
        if (codeHash == null || maxAttempts <= 0) {
            return 0;
        }
        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        long lifespan = Math.max(1, codeExpiresAt - Time.currentTime());
        String prefix = buildKey(realm, user, channel) + ":attempt:" + codeHash + ":";
        for (int n = 0; n < maxAttempts; n++) {
            if (store.putIfAbsent(prefix + n, lifespan)) {
                return n + 1;
            }
        }
        return 0;
    }

    /**
     * Burns a code that has used up its attempts: if the recoverable stash written by
     * {@link #tryReserveWithCodeHash} still holds {@code codeHash}, its code fields are
     * dropped so {@link #getRecentCode} returns {@code null} and no later session (or Resend
     * within the cooldown) can recover it. The cooldown itself is preserved, so a new code is
     * only sent once the cooldown allows. A stash holding a different (newer) code is left
     * untouched. Defense in depth: even if a burned code were recovered, its attempt slots
     * (see {@link #tryConsumeAttempt}) are exhausted.
     */
    public static void burnCode(KeycloakSession session, RealmModel realm, UserModel user,
                                String channel, String codeHash) {
        if (codeHash == null) {
            return;
        }
        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        String metaKey = buildKey(realm, user, channel) + ":meta";
        Map<String, String> meta = store.get(metaKey);
        String stashedHash = meta == null ? null : meta.get(NOTE_CODE_HASH);
        if (stashedHash == null || !MessageDigest.isEqual(codeHash.getBytes(StandardCharsets.UTF_8),
                stashedHash.getBytes(StandardCharsets.UTF_8))) {
            return;
        }
        Map<String, String> scrubbed = new HashMap<>(meta);
        scrubbed.remove(NOTE_CODE_HASH);
        scrubbed.remove(NOTE_CODE_SALT);
        scrubbed.remove(NOTE_CODE_EXPIRES_AT);
        int remainingCooldown = remainingSeconds(session, realm, user, channel);
        if (remainingCooldown > 0) {
            store.put(metaKey, remainingCooldown, scrubbed);
        } else {
            store.remove(metaKey);
        }
    }

    private static String buildKey(RealmModel realm, UserModel user, String channel) {
        return KEY_PREFIX + realm.getId() + ":" + user.getId() + ":" + channel;
    }

    // ---------------------------------------------------------------------------------------
    // Per-(realm, submitted identifier, channel) throttle.
    //
    // Used by the public OTP grant types, where every phase-1 request must be throttled the
    // same way whether or not the submitted username/email resolves to an account — otherwise
    // the presence or absence of a 429 reveals that the account exists. The key is derived
    // only from the normalized identifier string the client sent, never from a user id.
    // ---------------------------------------------------------------------------------------

    private static final String IDENTIFIER_KEY_PREFIX = KEY_PREFIX + "id:";

    /**
     * Attempt to reserve a send slot for the submitted {@code identifier} (username or email,
     * as typed). Returns {@code true} if the caller may proceed, {@code false} if a previous
     * request for the same normalized identifier is still within {@code cooldownSec}.
     * The identifier is trimmed and lower-cased, matching Keycloak's case-insensitive
     * username/email lookups, so case variations share one slot.
     */
    public static boolean tryReserveForIdentifier(KeycloakSession session, RealmModel realm, String identifier,
                                                  String channel, int cooldownSec) {
        if (cooldownSec <= 0) {
            return true;
        }
        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        String key = buildIdentifierKey(realm, identifier, channel);
        if (!store.putIfAbsent(key, cooldownSec)) {
            return false;
        }
        Map<String, String> notes = new HashMap<>();
        notes.put(NOTE_EXPIRES_AT, String.valueOf(Time.currentTime() + cooldownSec));
        store.put(key + ":meta", cooldownSec, notes);
        return true;
    }

    /**
     * Remaining cooldown seconds (clamped to 0) for the submitted {@code identifier}.
     * Returns 0 if there is no active reservation.
     */
    public static int remainingSecondsForIdentifier(KeycloakSession session, RealmModel realm, String identifier,
                                                    String channel) {
        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        Map<String, String> meta = store.get(buildIdentifierKey(realm, identifier, channel) + ":meta");
        if (meta == null) {
            return 0;
        }
        String expiresAtStr = meta.get(NOTE_EXPIRES_AT);
        if (expiresAtStr == null) {
            return 0;
        }
        try {
            return Math.max(0, Integer.parseInt(expiresAtStr) - Time.currentTime());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * Releases a reservation taken by {@link #tryReserveForIdentifier}, e.g. when OTP delivery
     * failed and the caller should be allowed to retry immediately.
     */
    public static void releaseIdentifier(KeycloakSession session, RealmModel realm, String identifier,
                                         String channel) {
        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        String key = buildIdentifierKey(realm, identifier, channel);
        store.remove(key);
        store.remove(key + ":meta");
    }

    /**
     * {@code otp-throttle:id:<realmId>:<sha256(realmId, normalized identifier, channel)>}.
     * Hashed so raw usernames / email addresses are not kept in cache keys, and prefixed
     * distinctly from the per-user key so an identifier can never collide with a user id.
     */
    private static String buildIdentifierKey(RealmModel realm, String identifier, String channel) {
        String normalized = identifier == null ? "" : identifier.trim().toLowerCase(java.util.Locale.ROOT);
        String material = realm.getId() + "\n" + normalized + "\n" + channel;
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(material.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return IDENTIFIER_KEY_PREFIX + realm.getId() + ":" + java.util.HexFormat.of().formatHex(digest);
        } catch (java.security.NoSuchAlgorithmException e) {
            // SHA-256 is mandatory in every JRE.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}