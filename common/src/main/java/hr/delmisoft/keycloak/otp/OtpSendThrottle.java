package hr.delmisoft.keycloak.otp;

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

    private static String buildKey(RealmModel realm, UserModel user, String channel) {
        return KEY_PREFIX + realm.getId() + ":" + user.getId() + ":" + channel;
    }
}