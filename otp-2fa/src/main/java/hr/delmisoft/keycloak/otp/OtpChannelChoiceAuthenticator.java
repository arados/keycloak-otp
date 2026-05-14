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

import org.jboss.logging.Logger;

import hr.delmisoft.keycloak.otp.sms.SmsException;
import hr.delmisoft.keycloak.otp.sms.SmsOtpConst;
import hr.delmisoft.keycloak.otp.sms.SmsProvider;

/**
 * Combined OTP authenticator that lets the user choose between Email and SMS
 * on a single selection screen before sending the code.
 *
 * Flow: selection screen → send OTP via chosen channel → OTP input form → verify.
 */
public class OtpChannelChoiceAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(OtpChannelChoiceAuthenticator.class);

    static final String TEMPLATE_CHANNEL_SELECT = "login-otp-channel-select.ftl";

    static final String AUTH_NOTE_CHANNEL = "otpChannel";
    static final String AUTH_NOTE_CODE_HASH = "otpChoiceCodeHash";
    static final String AUTH_NOTE_CODE_SALT = "otpChoiceCodeSalt";
    static final String AUTH_NOTE_EXPIRY = "otpChoiceExpiry";
    static final String AUTH_NOTE_ATTEMPTS = "otpChoiceAttempts";
    static final String AUTH_NOTE_LAST_SENT = "otpChoiceLastSent";

    static final String PARAM_CHANNEL = "channel";
    static final String PARAM_OTP = "otp";
    static final String PARAM_RESEND = "resend";

    static final String CHANNEL_EMAIL = "email";
    static final String CHANNEL_SMS = "sms";

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        boolean emailAllowed = isEmailUsable(realm, user);
        boolean smsAllowed = isSmsUsable(realm, user);

        context.challenge(context.form()
                .setAttribute("emailAllowed", emailAllowed)
                .setAttribute("smsAllowed", smsAllowed)
                .createForm(TEMPLATE_CHANNEL_SELECT));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String channelParam = context.getHttpRequest().getDecodedFormParameters().getFirst(PARAM_CHANNEL);
        String resendParam = context.getHttpRequest().getDecodedFormParameters().getFirst(PARAM_RESEND);

        if (channelParam != null) {
            handleChannelSelection(context);
        } else if ("true".equalsIgnoreCase(resendParam)) {
            handleResend(context);
        } else {
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            String selectedChannel = authSession.getAuthNote(AUTH_NOTE_CHANNEL);
            if (selectedChannel == null) {
                authenticate(context);
            } else {
                handleOtpVerification(context, selectedChannel);
            }
        }
    }

    private void handleChannelSelection(AuthenticationFlowContext context) {
        String channel = context.getHttpRequest().getDecodedFormParameters().getFirst(PARAM_CHANNEL);
        if (channel == null || (!CHANNEL_EMAIL.equals(channel) && !CHANNEL_SMS.equals(channel))) {
            rejectChannelSelection(context);
            return;
        }

        // Per-channel verification gate. configuredFor() only requires *some* channel to be
        // usable — without this re-check, a user verified on one channel could pick the
        // other (unverified) channel from the selection screen and receive an OTP there.
        // See SEC-001.
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        if (CHANNEL_EMAIL.equals(channel) && !isEmailUsable(realm, user)) {
            rejectChannelSelection(context);
            return;
        }
        if (CHANNEL_SMS.equals(channel) && !isSmsUsable(realm, user)) {
            rejectChannelSelection(context);
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        clearCodeNotes(authSession);
        authSession.setAuthNote(AUTH_NOTE_CHANNEL, channel);

        // First send is throttled too — defends against OTP spam via repeated channel-select restarts.
        sendCodeAndChallenge(context, channel);
    }

    private void rejectChannelSelection(AuthenticationFlowContext context) {
        boolean emailAllowed = isEmailUsable(context.getRealm(), context.getUser());
        boolean smsAllowed = isSmsUsable(context.getRealm(), context.getUser());
        context.challenge(context.form()
                .setAttribute("emailAllowed", emailAllowed)
                .setAttribute("smsAllowed", smsAllowed)
                .setError("otpChannelInvalid")
                .createForm(TEMPLATE_CHANNEL_SELECT));
    }

    private void handleResend(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String channel = authSession.getAuthNote(AUTH_NOTE_CHANNEL);
        if (channel == null) {
            authenticate(context);
            return;
        }
        sendCodeAndChallenge(context, channel);
    }

    private void sendCodeAndChallenge(AuthenticationFlowContext context, String channel) {
        String throttleChannel = CHANNEL_EMAIL.equals(channel) ? OtpSendThrottle.CHANNEL_EMAIL : OtpSendThrottle.CHANNEL_SMS;
        String template = CHANNEL_EMAIL.equals(channel) ? EmailOtpConst.LOGIN_TEMPLATE : SmsOtpConst.LOGIN_TEMPLATE;

        int cooldown = getCooldownConfig(context);
        int codeLength = getConfigInt(context, OtpChannelChoiceConst.CONFIG_CODE_LENGTH, OtpChannelChoiceConst.DEFAULT_CODE_LENGTH);
        int ttl = getConfigInt(context, OtpChannelChoiceConst.CONFIG_TTL, OtpChannelChoiceConst.DEFAULT_TTL);
        String code = generateCode(codeLength);
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash(code, salt);
        int codeExpiresAt = Time.currentTime() + ttl;

        boolean canSend = OtpSendThrottle.tryReserveWithCodeHash(context.getSession(), context.getRealm(),
                context.getUser(), throttleChannel, cooldown, hash, salt, codeExpiresAt);

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        if (canSend) {
            authSession.setAuthNote(AUTH_NOTE_CODE_HASH, hash);
            authSession.setAuthNote(AUTH_NOTE_CODE_SALT, salt);
            authSession.setAuthNote(AUTH_NOTE_EXPIRY, String.valueOf(codeExpiresAt));
            authSession.setAuthNote(AUTH_NOTE_ATTEMPTS, "0");
            authSession.setAuthNote(AUTH_NOTE_LAST_SENT, String.valueOf(Time.currentTime()));

            boolean sent = CHANNEL_EMAIL.equals(channel) ? sendEmail(context, code) : sendSms(context, code);
            if (!sent) {
                OtpSendThrottle.release(context.getSession(), context.getRealm(), context.getUser(), throttleChannel);
                clearCodeNotes(authSession);
                return;
            }
        } else {
            // Throttled. Recover the most recently delivered code's hash/salt for this channel
            // into this session so a user who legitimately re-selected the channel within the
            // cooldown can still complete login with the code that was actually sent.
            OtpSendThrottle.RecentCode recent = OtpSendThrottle.getRecentCode(context.getSession(),
                    context.getRealm(), context.getUser(), throttleChannel);
            if (recent != null) {
                authSession.setAuthNote(AUTH_NOTE_CODE_HASH, recent.codeHash);
                authSession.setAuthNote(AUTH_NOTE_CODE_SALT, recent.codeSalt);
                authSession.setAuthNote(AUTH_NOTE_EXPIRY, String.valueOf(recent.expiresAt));
                authSession.setAuthNote(AUTH_NOTE_ATTEMPTS, "0");
            }
        }

        int remaining = OtpSendThrottle.remainingSeconds(context.getSession(), context.getRealm(),
                context.getUser(), throttleChannel);
        context.challenge(context.form()
                .setAttribute("resendAvailableInSeconds", remaining)
                .createForm(template));
    }

    private void handleOtpVerification(AuthenticationFlowContext context, String channel) {
        String enteredOtp = context.getHttpRequest().getDecodedFormParameters().getFirst(PARAM_OTP);
        String template = CHANNEL_EMAIL.equals(channel) ? EmailOtpConst.LOGIN_TEMPLATE : SmsOtpConst.LOGIN_TEMPLATE;
        String errorInvalid = CHANNEL_EMAIL.equals(channel) ? EmailOtpConst.ERROR_OTP_INVALID : SmsOtpConst.ERROR_OTP_INVALID;
        String errorExpired = CHANNEL_EMAIL.equals(channel) ? EmailOtpConst.ERROR_OTP_EXPIRED : SmsOtpConst.ERROR_OTP_EXPIRED;
        String errorMaxRetries = CHANNEL_EMAIL.equals(channel) ? EmailOtpConst.ERROR_OTP_MAX_RETRIES : SmsOtpConst.ERROR_OTP_MAX_RETRIES;
        String throttleChannel = CHANNEL_EMAIL.equals(channel) ? OtpSendThrottle.CHANNEL_EMAIL : OtpSendThrottle.CHANNEL_SMS;

        if (enteredOtp == null || enteredOtp.isBlank()) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(errorInvalid).createForm(template));
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String storedHash = authSession.getAuthNote(AUTH_NOTE_CODE_HASH);
        String storedSalt = authSession.getAuthNote(AUTH_NOTE_CODE_SALT);
        String expiryStr = authSession.getAuthNote(AUTH_NOTE_EXPIRY);
        String attemptsStr = authSession.getAuthNote(AUTH_NOTE_ATTEMPTS);

        if (storedHash == null || storedSalt == null || expiryStr == null || attemptsStr == null) {
            authSession.removeAuthNote(AUTH_NOTE_CHANNEL);
            authenticate(context);
            return;
        }

        int expiry;
        int attempts;
        try {
            expiry = Integer.parseInt(expiryStr);
            attempts = Integer.parseInt(attemptsStr);
        } catch (NumberFormatException e) {
            authSession.removeAuthNote(AUTH_NOTE_CHANNEL);
            authenticate(context);
            return;
        }
        int maxRetries = getConfigInt(context, OtpChannelChoiceConst.CONFIG_MAX_RETRIES, OtpChannelChoiceConst.DEFAULT_MAX_RETRIES);

        if (Time.currentTime() > expiry) {
            int cooldown = getCooldownConfig(context);
            int codeLength = getConfigInt(context, OtpChannelChoiceConst.CONFIG_CODE_LENGTH, OtpChannelChoiceConst.DEFAULT_CODE_LENGTH);
            int ttl = getConfigInt(context, OtpChannelChoiceConst.CONFIG_TTL, OtpChannelChoiceConst.DEFAULT_TTL);
            String newCode = generateCode(codeLength);
            String newSalt = OtpHash.newSalt();
            String newHash = OtpHash.hash(newCode, newSalt);
            int codeExpiresAt = Time.currentTime() + ttl;
            boolean reserved = OtpSendThrottle.tryReserveWithCodeHash(context.getSession(), context.getRealm(),
                    context.getUser(), throttleChannel, cooldown, newHash, newSalt, codeExpiresAt);
            if (reserved) {
                authSession.setAuthNote(AUTH_NOTE_CODE_HASH, newHash);
                authSession.setAuthNote(AUTH_NOTE_CODE_SALT, newSalt);
                authSession.setAuthNote(AUTH_NOTE_EXPIRY, String.valueOf(codeExpiresAt));
                authSession.setAuthNote(AUTH_NOTE_ATTEMPTS, "0");
                authSession.setAuthNote(AUTH_NOTE_LAST_SENT, String.valueOf(Time.currentTime()));
                boolean sent = CHANNEL_EMAIL.equals(channel) ? sendEmail(context, newCode) : sendSms(context, newCode);
                if (!sent) {
                    OtpSendThrottle.release(context.getSession(), context.getRealm(), context.getUser(), throttleChannel);
                    clearCodeNotes(authSession);
                    return;
                }
            }
            int remaining = OtpSendThrottle.remainingSeconds(context.getSession(), context.getRealm(),
                    context.getUser(), throttleChannel);
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                    context.form()
                            .setAttribute("resendAvailableInSeconds", remaining)
                            .setError(errorExpired)
                            .createForm(template));
            return;
        }

        if (attempts >= maxRetries) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(errorMaxRetries).createForm(template));
            return;
        }

        if (OtpHash.verify(enteredOtp, storedHash, storedSalt)) {
            context.success();
        } else {
            authSession.setAuthNote(AUTH_NOTE_ATTEMPTS, String.valueOf(attempts + 1));
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(errorInvalid).createForm(template));
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return isEmailUsable(realm, user) || isSmsUsable(realm, user);
    }

    /**
     * Whether Email OTP can be sent to this user under the realm's verification policy.
     * Shared with {@link #authenticate} and {@link #handleChannelSelection} so eligibility
     * and per-selection enforcement read the same predicate.
     */
    private static boolean isEmailUsable(RealmModel realm, UserModel user) {
        if (user.getEmail() == null) {
            return false;
        }
        String reqVerified = realm.getAttribute(EmailOtpConst.CONFIG_REQUIRE_VERIFIED_EMAIL);
        boolean requireVerified = (reqVerified == null || reqVerified.isBlank())
                ? EmailOtpConst.DEFAULT_REQUIRE_VERIFIED_EMAIL
                : Boolean.parseBoolean(reqVerified);
        return !requireVerified || user.isEmailVerified();
    }

    /**
     * Whether SMS OTP can be sent to this user under the realm's verification policy.
     */
    private static boolean isSmsUsable(RealmModel realm, UserModel user) {
        String phoneAttr = SmsOtpConst.resolvePhoneAttribute(realm);
        if (user.getFirstAttribute(phoneAttr) == null) {
            return false;
        }
        String reqVerified = realm.getAttribute(SmsOtpConst.CONFIG_REQUIRE_VERIFIED_PHONE);
        boolean requireVerified = (reqVerified == null || reqVerified.isBlank())
                ? SmsOtpConst.DEFAULT_REQUIRE_VERIFIED_PHONE
                : Boolean.parseBoolean(reqVerified);
        if (!requireVerified) {
            return true;
        }
        String verifiedAttr = realm.getAttribute(SmsOtpConst.CONFIG_VERIFIED_PHONE_ATTRIBUTE);
        if (verifiedAttr == null || verifiedAttr.isBlank()) {
            verifiedAttr = SmsOtpConst.DEFAULT_VERIFIED_PHONE_ATTRIBUTE;
        }
        return "true".equalsIgnoreCase(user.getFirstAttribute(verifiedAttr));
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

    private boolean sendEmail(AuthenticationFlowContext context, String code) {
        try {
            context.getSession().getProvider(EmailTemplateProvider.class)
                    .setRealm(context.getRealm())
                    .setUser(context.getUser())
                    .send(EmailOtpConst.EMAIL_SUBJECT_KEY, EmailOtpConst.EMAIL_TEMPLATE, new HashMap<>(Map.of("code", code)));
            return true;
        } catch (EmailException e) {
            LOG.error("Failed to send OTP email", e);
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("emailSendError")
                            .createErrorPage(jakarta.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR));
            return false;
        }
    }

    private boolean sendSms(AuthenticationFlowContext context, String code) {
        String phoneAttr = getConfigString(context, OtpChannelChoiceConst.CONFIG_PHONE_ATTRIBUTE,
                SmsOtpConst.resolvePhoneAttribute(context.getRealm()));
        String phoneNumber = context.getUser().getFirstAttribute(phoneAttr);
        if (phoneNumber == null || phoneNumber.isBlank()) {
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("smsSendError")
                            .createErrorPage(jakarta.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR));
            return false;
        }
        try {
            String message = "Your verification code is: " + code;
            context.getSession().getProvider(SmsProvider.class).send(phoneNumber, message);
            return true;
        } catch (SmsException e) {
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
                    context.form().setError("smsSendError")
                            .createErrorPage(jakarta.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR));
            return false;
        }
    }

    private static void clearCodeNotes(AuthenticationSessionModel authSession) {
        authSession.removeAuthNote(AUTH_NOTE_CODE_HASH);
        authSession.removeAuthNote(AUTH_NOTE_CODE_SALT);
        authSession.removeAuthNote(AUTH_NOTE_EXPIRY);
        authSession.removeAuthNote(AUTH_NOTE_ATTEMPTS);
        authSession.removeAuthNote(AUTH_NOTE_LAST_SENT);
    }

    static String generateCode(int length) {
        int bound = (int) Math.pow(10, length);
        int code = RANDOM.nextInt(bound);
        return String.format("%0" + length + "d", code);
    }

    static int getConfigInt(AuthenticationFlowContext context, String key, int defaultValue) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null) return defaultValue;
        String value = config.getConfig().get(key);
        if (value == null || value.isBlank()) return defaultValue;
        try {
            int parsed = Integer.parseInt(value);
            return parsed > 0 ? parsed : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    static String getConfigString(AuthenticationFlowContext context, String key, String defaultValue) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null) return defaultValue;
        String value = config.getConfig().get(key);
        return (value == null || value.isBlank()) ? defaultValue : value;
    }

    private static int getCooldownConfig(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config != null && config.getConfig() != null) {
            String value = config.getConfig().get(OtpChannelChoiceConst.CONFIG_SEND_COOLDOWN);
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
        return OtpChannelChoiceConst.DEFAULT_SEND_COOLDOWN;
    }
}
