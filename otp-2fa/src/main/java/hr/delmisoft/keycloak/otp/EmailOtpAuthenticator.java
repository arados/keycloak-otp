package hr.delmisoft.keycloak.otp;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

public class EmailOtpAuthenticator implements Authenticator {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String storedHash = authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE_HASH);
        String storedSalt = authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE_SALT);
        String expiryStr = authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY);

        // Refresh / re-entry: if a valid hash already exists in this auth session,
        // re-render the form without sending again.
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
        String resendParam = context.getHttpRequest().getDecodedFormParameters().getFirst(EmailOtpConst.PARAM_RESEND);
        if ("true".equalsIgnoreCase(resendParam)) {
            sendCode(context);
            return;
        }

        String enteredOtp = context.getHttpRequest().getDecodedFormParameters().getFirst(EmailOtpConst.PARAM_OTP);
        if (enteredOtp == null || enteredOtp.isBlank()) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(EmailOtpConst.ERROR_OTP_INVALID).createForm(EmailOtpConst.LOGIN_TEMPLATE));
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String storedHash = authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE_HASH);
        String storedSalt = authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE_SALT);
        String expiryStr = authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY);
        String attemptsStr = authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS);

        if (storedHash == null || storedSalt == null || expiryStr == null || attemptsStr == null) {
            // Session state is missing or corrupted — recover by sending (still throttled).
            sendCode(context);
            return;
        }

        int expiry;
        int attempts;
        try {
            expiry = Integer.parseInt(expiryStr);
            attempts = Integer.parseInt(attemptsStr);
        } catch (NumberFormatException e) {
            // Stored state is malformed — treat as corrupt and recover via a throttled resend.
            sendCode(context);
            return;
        }
        int maxRetries = getConfigInt(context, EmailOtpConst.CONFIG_MAX_RETRIES, EmailOtpConst.DEFAULT_MAX_RETRIES);

        // Check expiry — resend a new code if expired (subject to throttle)
        if (Time.currentTime() > expiry) {
            sendNewCodeOnExpiry(context);
            return;
        }

        // Check attempts
        if (attempts >= maxRetries) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(EmailOtpConst.ERROR_OTP_MAX_RETRIES).createForm(EmailOtpConst.LOGIN_TEMPLATE));
            return;
        }

        if (OtpHash.verify(enteredOtp, storedHash, storedSalt)) {
            context.success();
        } else {
            authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS, String.valueOf(attempts + 1));
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(EmailOtpConst.ERROR_OTP_INVALID).createForm(EmailOtpConst.LOGIN_TEMPLATE));
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        if (user.getEmail() == null) {
            return false;
        }
        // Default: only consider the user "configured for" email OTP if Keycloak has verified
        // the address. Admins can opt out by setting emailOtp.requireVerifiedEmail=false on
        // either the authenticator config or as a realm attribute (back-compat for setups
        // that pre-date the verification gate).
        if (requireVerifiedEmail(realm)) {
            return user.isEmailVerified();
        }
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // no required actions
    }

    @Override
    public void close() {
        // no-op
    }

    private void sendCode(AuthenticationFlowContext context) {
        int cooldown = getCooldownConfig(context);
        int codeLength = getConfigInt(context, EmailOtpConst.CONFIG_CODE_LENGTH, EmailOtpConst.DEFAULT_CODE_LENGTH);
        int ttl = getConfigInt(context, EmailOtpConst.CONFIG_TTL, EmailOtpConst.DEFAULT_TTL);
        String code = generateCode(codeLength);
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash(code, salt);
        int codeExpiresAt = Time.currentTime() + ttl;

        boolean reserved = OtpSendThrottle.tryReserveWithCodeHash(context.getSession(), context.getRealm(),
                context.getUser(), OtpSendThrottle.CHANNEL_EMAIL, cooldown, hash, salt, codeExpiresAt);

        if (!reserved) {
            // Throttled. Recover the most recently delivered code's hash/salt into this session
            // so a user who legitimately restarted their login within the cooldown can complete
            // it with what was sent to their inbox. If no stash is available (e.g. cooldown=0
            // and no prior send), just re-render the form.
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            OtpSendThrottle.RecentCode recent = OtpSendThrottle.getRecentCode(context.getSession(),
                    context.getRealm(), context.getUser(), OtpSendThrottle.CHANNEL_EMAIL);
            if (recent != null) {
                authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_CODE_HASH, recent.codeHash);
                authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_CODE_SALT, recent.codeSalt);
                authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY, String.valueOf(recent.expiresAt));
                authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS, "0");
            }
            challengeOtpForm(context);
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_CODE_HASH, hash);
        authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_CODE_SALT, salt);
        authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY, String.valueOf(codeExpiresAt));
        authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS, "0");
        authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_LAST_SENT, String.valueOf(Time.currentTime()));

        if (!sendEmail(context, code)) {
            // Delivery failed. Roll back the throttle reservation so the user is not locked
            // out by a cooldown protecting an OTP they never received, and clear the auth notes
            // we just wrote so this session does not later "recover" a code that was not sent.
            OtpSendThrottle.release(context.getSession(), context.getRealm(), context.getUser(),
                    OtpSendThrottle.CHANNEL_EMAIL);
            authSession.removeAuthNote(EmailOtpConst.AUTH_NOTE_CODE_HASH);
            authSession.removeAuthNote(EmailOtpConst.AUTH_NOTE_CODE_SALT);
            authSession.removeAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY);
            authSession.removeAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS);
            authSession.removeAuthNote(EmailOtpConst.AUTH_NOTE_LAST_SENT);
            return;
        }

        challengeOtpForm(context);
    }

    private void sendNewCodeOnExpiry(AuthenticationFlowContext context) {
        // Code expired in this session — treat like an automatic resend (subject to throttle).
        int cooldown = getCooldownConfig(context);
        int codeLength = getConfigInt(context, EmailOtpConst.CONFIG_CODE_LENGTH, EmailOtpConst.DEFAULT_CODE_LENGTH);
        int ttl = getConfigInt(context, EmailOtpConst.CONFIG_TTL, EmailOtpConst.DEFAULT_TTL);
        String newCode = generateCode(codeLength);
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash(newCode, salt);
        int codeExpiresAt = Time.currentTime() + ttl;
        boolean reserved = OtpSendThrottle.tryReserveWithCodeHash(context.getSession(), context.getRealm(),
                context.getUser(), OtpSendThrottle.CHANNEL_EMAIL, cooldown, hash, salt, codeExpiresAt);
        if (reserved) {
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_CODE_HASH, hash);
            authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_CODE_SALT, salt);
            authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY, String.valueOf(codeExpiresAt));
            authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS, "0");
            authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_LAST_SENT, String.valueOf(Time.currentTime()));
            if (!sendEmail(context, newCode)) {
                OtpSendThrottle.release(context.getSession(), context.getRealm(), context.getUser(),
                        OtpSendThrottle.CHANNEL_EMAIL);
                authSession.removeAuthNote(EmailOtpConst.AUTH_NOTE_CODE_HASH);
                authSession.removeAuthNote(EmailOtpConst.AUTH_NOTE_CODE_SALT);
                authSession.removeAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY);
                authSession.removeAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS);
                authSession.removeAuthNote(EmailOtpConst.AUTH_NOTE_LAST_SENT);
                return;
            }
        }
        context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                context.form()
                        .setAttribute("resendAvailableInSeconds", resendAvailableInSeconds(context))
                        .setError(EmailOtpConst.ERROR_OTP_EXPIRED)
                        .createForm(EmailOtpConst.LOGIN_TEMPLATE));
    }

    private void challengeOtpForm(AuthenticationFlowContext context) {
        context.challenge(context.form()
                .setAttribute("resendAvailableInSeconds", resendAvailableInSeconds(context))
                .createForm(EmailOtpConst.LOGIN_TEMPLATE));
    }

    private int resendAvailableInSeconds(AuthenticationFlowContext context) {
        return OtpSendThrottle.remainingSeconds(context.getSession(), context.getRealm(),
                context.getUser(), OtpSendThrottle.CHANNEL_EMAIL);
    }

    private boolean sendEmail(AuthenticationFlowContext context, String code) {
        try {
            context.getSession().getProvider(EmailTemplateProvider.class)
                    .setRealm(context.getRealm())
                    .setUser(context.getUser())
                    .send(EmailOtpConst.EMAIL_SUBJECT_KEY, EmailOtpConst.EMAIL_TEMPLATE, new HashMap<>(Map.of("code", code)));
            return true;
        } catch (EmailException e) {
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("emailSendError").createErrorPage(jakarta.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR));
            return false;
        }
    }

    private static String generateCode(int length) {
        int bound = (int) Math.pow(10, length);
        int code = RANDOM.nextInt(bound);
        return String.format("%0" + length + "d", code);
    }

    private static int getConfigInt(AuthenticationFlowContext context, String key, int defaultValue) {
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

    /**
     * Cooldown reads accept {@code 0} (disable throttling) as documented in the README
     * and the authenticator's help text; values below 0 fall back to the default.
     */
    private static int getCooldownConfig(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config != null && config.getConfig() != null) {
            String value = config.getConfig().get(EmailOtpConst.CONFIG_SEND_COOLDOWN);
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
        return EmailOtpConst.DEFAULT_SEND_COOLDOWN;
    }

    private static boolean requireVerifiedEmail(RealmModel realm) {
        // Realm attribute is the only place we can read this consistently from configuredFor()
        // (Keycloak does not expose AuthenticatorConfig in that callback). Per-authenticator
        // config can still tighten or relax the gate inside the send/verify paths, but
        // configuredFor() drives whether the authenticator is even offered to the user.
        String configured = realm.getAttribute(EmailOtpConst.CONFIG_REQUIRE_VERIFIED_EMAIL);
        if (configured == null || configured.isBlank()) {
            return EmailOtpConst.DEFAULT_REQUIRE_VERIFIED_EMAIL;
        }
        return Boolean.parseBoolean(configured);
    }
}
