package hr.delmisoft.keycloak.otp.sms;

import java.security.SecureRandom;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import hr.delmisoft.keycloak.otp.OtpHash;
import hr.delmisoft.keycloak.otp.OtpSendThrottle;

public class SmsOtpAuthenticator implements Authenticator {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String storedHash = authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_CODE_HASH);
        String storedSalt = authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_CODE_SALT);
        String expiryStr = authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY);

        if (storedHash != null && storedSalt != null && expiryStr != null) {
            try {
                if (Time.currentTime() < Integer.parseInt(expiryStr)) {
                    challengeOtpForm(context);
                    return;
                }
            } catch (NumberFormatException ignored) {
                // fall through and try a fresh send
            }
        }

        // All sends — including the first send for a fresh auth session — honor the
        // per-(realm, user, channel) cooldown to prevent OTP spam via rapid session restarts.
        sendCode(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String resendParam = context.getHttpRequest().getDecodedFormParameters().getFirst(SmsOtpConst.PARAM_RESEND);
        if ("true".equalsIgnoreCase(resendParam)) {
            sendCode(context);
            return;
        }

        String enteredOtp = context.getHttpRequest().getDecodedFormParameters().getFirst(SmsOtpConst.PARAM_OTP);
        if (enteredOtp == null || enteredOtp.isBlank()) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(SmsOtpConst.ERROR_OTP_INVALID).createForm(SmsOtpConst.LOGIN_TEMPLATE));
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String storedHash = authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_CODE_HASH);
        String storedSalt = authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_CODE_SALT);
        String expiryStr = authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY);
        String attemptsStr = authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS);

        if (storedHash == null || storedSalt == null || expiryStr == null || attemptsStr == null) {
            sendCode(context);
            return;
        }

        int expiry;
        int attempts;
        try {
            expiry = Integer.parseInt(expiryStr);
            attempts = Integer.parseInt(attemptsStr);
        } catch (NumberFormatException e) {
            sendCode(context);
            return;
        }
        int maxRetries = getConfigInt(context, SmsOtpConst.CONFIG_MAX_RETRIES, SmsOtpConst.DEFAULT_MAX_RETRIES);

        if (Time.currentTime() > expiry) {
            sendNewCodeOnExpiry(context);
            return;
        }

        if (attempts >= maxRetries) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(SmsOtpConst.ERROR_OTP_MAX_RETRIES).createForm(SmsOtpConst.LOGIN_TEMPLATE));
            return;
        }

        if (OtpHash.verify(enteredOtp, storedHash, storedSalt)) {
            context.success();
        } else {
            authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS, String.valueOf(attempts + 1));
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(SmsOtpConst.ERROR_OTP_INVALID).createForm(SmsOtpConst.LOGIN_TEMPLATE));
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        String phoneAttr = resolvePhoneAttribute(realm);
        if (user.getFirstAttribute(phoneAttr) == null) {
            return false;
        }
        if (requireVerifiedPhone(realm)) {
            String verifiedAttr = resolveVerifiedPhoneAttribute(realm);
            return "true".equalsIgnoreCase(user.getFirstAttribute(verifiedAttr));
        }
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

    private void sendCode(AuthenticationFlowContext context) {
        int cooldown = getCooldownConfig(context);
        int codeLength = getConfigInt(context, SmsOtpConst.CONFIG_CODE_LENGTH, SmsOtpConst.DEFAULT_CODE_LENGTH);
        int ttl = getConfigInt(context, SmsOtpConst.CONFIG_TTL, SmsOtpConst.DEFAULT_TTL);
        String code = generateCode(codeLength);
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash(code, salt);
        int codeExpiresAt = Time.currentTime() + ttl;

        boolean reserved = OtpSendThrottle.tryReserveWithCodeHash(context.getSession(), context.getRealm(),
                context.getUser(), OtpSendThrottle.CHANNEL_SMS, cooldown, hash, salt, codeExpiresAt);

        if (!reserved) {
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            OtpSendThrottle.RecentCode recent = OtpSendThrottle.getRecentCode(context.getSession(),
                    context.getRealm(), context.getUser(), OtpSendThrottle.CHANNEL_SMS);
            if (recent != null) {
                authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_CODE_HASH, recent.codeHash);
                authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_CODE_SALT, recent.codeSalt);
                authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY, String.valueOf(recent.expiresAt));
                authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS, "0");
            }
            challengeOtpForm(context);
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_CODE_HASH, hash);
        authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_CODE_SALT, salt);
        authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY, String.valueOf(codeExpiresAt));
        authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS, "0");
        authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_LAST_SENT, String.valueOf(Time.currentTime()));

        if (!sendSms(context, code)) {
            OtpSendThrottle.release(context.getSession(), context.getRealm(), context.getUser(),
                    OtpSendThrottle.CHANNEL_SMS);
            authSession.removeAuthNote(SmsOtpConst.AUTH_NOTE_CODE_HASH);
            authSession.removeAuthNote(SmsOtpConst.AUTH_NOTE_CODE_SALT);
            authSession.removeAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY);
            authSession.removeAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS);
            authSession.removeAuthNote(SmsOtpConst.AUTH_NOTE_LAST_SENT);
            return;
        }

        challengeOtpForm(context);
    }

    private void sendNewCodeOnExpiry(AuthenticationFlowContext context) {
        int cooldown = getCooldownConfig(context);
        int codeLength = getConfigInt(context, SmsOtpConst.CONFIG_CODE_LENGTH, SmsOtpConst.DEFAULT_CODE_LENGTH);
        int ttl = getConfigInt(context, SmsOtpConst.CONFIG_TTL, SmsOtpConst.DEFAULT_TTL);
        String newCode = generateCode(codeLength);
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash(newCode, salt);
        int codeExpiresAt = Time.currentTime() + ttl;
        boolean reserved = OtpSendThrottle.tryReserveWithCodeHash(context.getSession(), context.getRealm(),
                context.getUser(), OtpSendThrottle.CHANNEL_SMS, cooldown, hash, salt, codeExpiresAt);
        if (reserved) {
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_CODE_HASH, hash);
            authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_CODE_SALT, salt);
            authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY, String.valueOf(codeExpiresAt));
            authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS, "0");
            authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_LAST_SENT, String.valueOf(Time.currentTime()));
            if (!sendSms(context, newCode)) {
                OtpSendThrottle.release(context.getSession(), context.getRealm(), context.getUser(),
                        OtpSendThrottle.CHANNEL_SMS);
                authSession.removeAuthNote(SmsOtpConst.AUTH_NOTE_CODE_HASH);
                authSession.removeAuthNote(SmsOtpConst.AUTH_NOTE_CODE_SALT);
                authSession.removeAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY);
                authSession.removeAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS);
                authSession.removeAuthNote(SmsOtpConst.AUTH_NOTE_LAST_SENT);
                return;
            }
        }
        context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                context.form()
                        .setAttribute("resendAvailableInSeconds", resendAvailableInSeconds(context))
                        .setError(SmsOtpConst.ERROR_OTP_EXPIRED)
                        .createForm(SmsOtpConst.LOGIN_TEMPLATE));
    }

    private void challengeOtpForm(AuthenticationFlowContext context) {
        context.challenge(context.form()
                .setAttribute("resendAvailableInSeconds", resendAvailableInSeconds(context))
                .createForm(SmsOtpConst.LOGIN_TEMPLATE));
    }

    private int resendAvailableInSeconds(AuthenticationFlowContext context) {
        return OtpSendThrottle.remainingSeconds(context.getSession(), context.getRealm(),
                context.getUser(), OtpSendThrottle.CHANNEL_SMS);
    }

    private boolean sendSms(AuthenticationFlowContext context, String code) {
        // Phone attribute is realm-scoped only; matches the eligibility check in
        // configuredFor() so admins cannot configure a flow where "is the user set up?"
        // and "where do we actually send?" diverge.
        String phoneAttr = resolvePhoneAttribute(context.getRealm());
        String phoneNumber = context.getUser().getFirstAttribute(phoneAttr);
        if (phoneNumber == null || phoneNumber.isBlank()) {
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("smsSendError").createErrorPage(jakarta.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR));
            return false;
        }

        try {
            String message = "Your verification code is: " + code;
            context.getSession().getProvider(SmsProvider.class).send(phoneNumber, message);
            return true;
        } catch (SmsException e) {
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("smsSendError").createErrorPage(jakarta.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR));
            return false;
        }
    }

    static String generateCode(int length) {
        int bound = (int) Math.pow(10, length);
        int code = RANDOM.nextInt(bound);
        return String.format("%0" + length + "d", code);
    }

    static int getConfigInt(AuthenticationFlowContext context, String key, int defaultValue) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null) {
            return defaultValue;
        }
        String value = config.getConfig().get(key);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value);
            return parsed > 0 ? parsed : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    static String getConfigString(AuthenticationFlowContext context, String key, String defaultValue) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null) {
            return defaultValue;
        }
        String value = config.getConfig().get(key);
        return (value == null || value.isBlank()) ? defaultValue : value;
    }

    /**
     * Cooldown reads accept {@code 0} (disable throttling) as documented; values below 0
     * fall back to the default.
     */
    private static int getCooldownConfig(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config != null && config.getConfig() != null) {
            String value = config.getConfig().get(SmsOtpConst.CONFIG_SEND_COOLDOWN);
            if (value != null && !value.isBlank()) {
                try {
                    int parsed = Integer.parseInt(value);
                    if (parsed >= 0) {
                        return parsed;
                    }
                } catch (NumberFormatException ignored) {
                    // fall through
                }
            }
        }
        return SmsOtpConst.DEFAULT_SEND_COOLDOWN;
    }

    private String resolvePhoneAttribute(RealmModel realm) {
        return SmsOtpConst.resolvePhoneAttribute(realm);
    }

    private static boolean requireVerifiedPhone(RealmModel realm) {
        String configured = realm.getAttribute(SmsOtpConst.CONFIG_REQUIRE_VERIFIED_PHONE);
        if (configured == null || configured.isBlank()) {
            return SmsOtpConst.DEFAULT_REQUIRE_VERIFIED_PHONE;
        }
        return Boolean.parseBoolean(configured);
    }

    private static String resolveVerifiedPhoneAttribute(RealmModel realm) {
        String configured = realm.getAttribute(SmsOtpConst.CONFIG_VERIFIED_PHONE_ATTRIBUTE);
        if (configured == null || configured.isBlank()) {
            return SmsOtpConst.DEFAULT_VERIFIED_PHONE_ATTRIBUTE;
        }
        return configured;
    }
}
