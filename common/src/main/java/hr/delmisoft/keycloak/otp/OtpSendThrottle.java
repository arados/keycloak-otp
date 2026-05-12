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

    private OtpSendThrottle() {}

    /**
     * Attempt to reserve a send slot. Returns {@code true} if the caller may send,
     * {@code false} if the previous send is still within {@code cooldownSec}.
     */
    public static boolean tryReserve(KeycloakSession session, RealmModel realm, UserModel user,
                                     String channel, int cooldownSec) {
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
        store.put(key + ":meta", cooldownSec, notes);
        return true;
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