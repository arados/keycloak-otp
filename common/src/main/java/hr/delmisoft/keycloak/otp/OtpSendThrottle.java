package hr.delmisoft.keycloak.otp;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

import org.jboss.logging.Logger;
import org.keycloak.common.ClientConnection;
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

    // ------------------------------------------------------------------------------------
    // Per-(realm, client IP) send limit
    //
    // The per-user cooldown above stops one account from being spammed faster than once per
    // cooldown, but on its own it lets a single client trigger sends for an unbounded number
    // of accounts (SMS pumping / toll fraud) and keep one victim's phone buzzing forever.
    // This limiter caps the number of sends one source IP may trigger per window, across all
    // users and both channels.
    //
    // Implementation: N numbered slot keys "otp-ip:{realm}:{ip}:{0..N-1}", each reserved with
    // SingleUseObjectProvider.putIfAbsent and the window as TTL. A send needs a free slot; a
    // slot frees itself when its TTL expires (sliding window per slot). putIfAbsent is atomic
    // and cluster-safe, so there is no read-modify-write race on a shared counter.
    // ------------------------------------------------------------------------------------

    /** Realm attribute: max sends per source IP per window. {@code 0} disables the limit. */
    public static final String CONFIG_IP_SEND_LIMIT = "otp.ipSendLimit";
    /** Realm attribute: IP-limit window in seconds. */
    public static final String CONFIG_IP_SEND_WINDOW = "otp.ipSendWindow";
    public static final int DEFAULT_IP_SEND_LIMIT = 10;
    public static final int DEFAULT_IP_SEND_WINDOW = 3600;

    /** Login-theme message key shown when the browser flow is blocked by the IP limit. */
    public static final String ERROR_IP_SEND_LIMITED = "otpSendIpLimited";

    private static final Logger LOG = Logger.getLogger(OtpSendThrottle.class);
    private static final String IP_KEY_PREFIX = "otp-ip:";
    private static final Pattern IPV6_LITERAL = Pattern.compile("[0-9A-Fa-f:.]+");

    /**
     * Outcome of {@link #tryReserveIpSlot}. {@link #isAllowed()} tells the caller whether it may
     * send. An allowed slot that was actually recorded can be handed back with
     * {@link #releaseIpSlot} when nothing ends up being sent.
     */
    public static final class IpSlot {
        private static final IpSlot UNTRACKED = new IpSlot(true, null, 0);

        private final boolean allowed;
        private final String key;
        private final int retryAfterSeconds;

        private IpSlot(boolean allowed, String key, int retryAfterSeconds) {
            this.allowed = allowed;
            this.key = key;
            this.retryAfterSeconds = retryAfterSeconds;
        }

        public boolean isAllowed() {
            return allowed;
        }

        /** Seconds until a slot frees up; only meaningful when {@link #isAllowed()} is false. */
        public int retryAfterSeconds() {
            return retryAfterSeconds;
        }
    }

    /**
     * Reserve one send for the request's source IP using the realm's {@code otp.ipSendLimit} /
     * {@code otp.ipSendWindow} attributes. The IP comes from
     * {@link ClientConnection#getRemoteAddr()}, which honors forwarding headers only when
     * Keycloak's proxy configuration says to.
     */
    public static IpSlot tryReserveIpSlot(KeycloakSession session, RealmModel realm, ClientConnection connection) {
        String ip = connection == null ? null : connection.getRemoteAddr();
        return tryReserveIpSlot(session, realm, ip, resolveIpSendLimit(realm), resolveIpSendWindow(realm));
    }

    /**
     * Reserve one of {@code limit} send slots for {@code clientIp} in this realm for
     * {@code windowSec} seconds. A {@code limit <= 0} or a missing IP is not tracked and always
     * allowed.
     */
    public static IpSlot tryReserveIpSlot(KeycloakSession session, RealmModel realm, String clientIp,
                                          int limit, int windowSec) {
        String ip = normalizeIp(clientIp);
        if (limit <= 0 || windowSec <= 0 || ip == null) {
            return IpSlot.UNTRACKED;
        }
        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        String prefix = IP_KEY_PREFIX + realm.getId() + ":" + ip + ":";
        for (int slot = 0; slot < limit; slot++) {
            String key = prefix + slot;
            if (store.putIfAbsent(key, windowSec)) {
                Map<String, String> meta = new HashMap<>();
                meta.put(NOTE_EXPIRES_AT, String.valueOf(Time.currentTime() + windowSec));
                store.put(key + ":meta", windowSec, meta);
                return new IpSlot(true, key, 0);
            }
        }
        LOG.debugf("OTP send blocked by per-IP limit: realm=%s ip=%s limit=%d window=%ds",
                realm.getId(), ip, limit, windowSec);
        return new IpSlot(false, null, ipRetryAfter(store, prefix, limit, windowSec));
    }

    /**
     * Hand back a slot obtained from {@link #tryReserveIpSlot} when nothing was sent (per-user
     * cooldown blocked, or delivery failed). No-op for blocked/untracked slots or {@code null}.
     */
    public static void releaseIpSlot(KeycloakSession session, IpSlot slot) {
        if (slot == null || slot.key == null) {
            return;
        }
        SingleUseObjectProvider store = session.getProvider(SingleUseObjectProvider.class);
        store.remove(slot.key);
        store.remove(slot.key + ":meta");
    }

    /** {@code otp.ipSendLimit}; {@code 0} disables, negative/invalid falls back to the default. */
    public static int resolveIpSendLimit(RealmModel realm) {
        int value = parseIntAttribute(realm, CONFIG_IP_SEND_LIMIT, DEFAULT_IP_SEND_LIMIT);
        return value >= 0 ? value : DEFAULT_IP_SEND_LIMIT;
    }

    /** {@code otp.ipSendWindow} in seconds; non-positive/invalid falls back to the default. */
    public static int resolveIpSendWindow(RealmModel realm) {
        int value = parseIntAttribute(realm, CONFIG_IP_SEND_WINDOW, DEFAULT_IP_SEND_WINDOW);
        return value > 0 ? value : DEFAULT_IP_SEND_WINDOW;
    }

    private static int parseIntAttribute(RealmModel realm, String name, int defaultValue) {
        String configured = realm.getAttribute(name);
        if (configured == null || configured.isBlank()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(configured.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /** Seconds until the earliest slot expires (at least 1, at most the window). */
    private static int ipRetryAfter(SingleUseObjectProvider store, String prefix, int limit, int windowSec) {
        int now = Time.currentTime();
        int earliest = windowSec;
        for (int slot = 0; slot < limit; slot++) {
            Map<String, String> meta = store.get(prefix + slot + ":meta");
            if (meta == null || meta.get(NOTE_EXPIRES_AT) == null) {
                continue;
            }
            try {
                earliest = Math.min(earliest, Integer.parseInt(meta.get(NOTE_EXPIRES_AT)) - now);
            } catch (NumberFormatException ignored) {
                // treat as a full window
            }
        }
        return Math.max(1, earliest);
    }

    /**
     * Canonical bucket for a client address. IPv6 addresses are collapsed to their /64 prefix
     * (a single subscriber usually controls a whole /64, so per-address buckets would be
     * trivially bypassed); IPv4-mapped IPv6 addresses collapse to their IPv4 form. Returns
     * {@code null} when no address is available.
     */
    static String normalizeIp(String clientIp) {
        if (clientIp == null || clientIp.isBlank()) {
            return null;
        }
        String ip = clientIp.trim();
        if (ip.startsWith("[") && ip.endsWith("]")) {
            ip = ip.substring(1, ip.length() - 1);
        }
        int zone = ip.indexOf('%');
        if (zone >= 0) {
            ip = ip.substring(0, zone);
        }
        // Only hand strings that are syntactically IPv6 literals to InetAddress, so it can
        // never fall back to a DNS lookup.
        if (ip.indexOf(':') >= 0 && IPV6_LITERAL.matcher(ip).matches()) {
            try {
                InetAddress addr = InetAddress.getByName(ip);
                if (addr instanceof Inet6Address) {
                    byte[] b = addr.getAddress();
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 8; i += 2) {
                        sb.append(Integer.toHexString(((b[i] & 0xff) << 8) | (b[i + 1] & 0xff))).append(':');
                    }
                    return sb.append(":/64").toString();
                }
                return addr.getHostAddress();
            } catch (UnknownHostException e) {
                // not a valid literal; fall through and bucket on the raw string
            }
        }
        return ip.toLowerCase(Locale.ROOT);
    }
}