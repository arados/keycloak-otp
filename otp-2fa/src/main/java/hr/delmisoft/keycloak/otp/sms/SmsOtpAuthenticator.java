package hr.delmisoft.keycloak.otp.sms;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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

public class SmsOtpAuthenticator implements Authenticator {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        int codeLength = getConfigInt(context, SmsOtpConst.CONFIG_CODE_LENGTH, SmsOtpConst.DEFAULT_CODE_LENGTH);
        int ttl = getConfigInt(context, SmsOtpConst.CONFIG_TTL, SmsOtpConst.DEFAULT_TTL);

        String code = generateCode(codeLength);

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_CODE, code);
        authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY, String.valueOf(Time.currentTime() + ttl));
        authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS, "0");

        if (!sendSms(context, code)) {
            return;
        }

        context.challenge(context.form().createForm(SmsOtpConst.LOGIN_TEMPLATE));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String enteredOtp = context.getHttpRequest().getDecodedFormParameters().getFirst(SmsOtpConst.PARAM_OTP);
        if (enteredOtp == null || enteredOtp.isBlank()) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(SmsOtpConst.ERROR_OTP_INVALID).createForm(SmsOtpConst.LOGIN_TEMPLATE));
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String storedCode = authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_CODE);
        String expiryStr = authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY);
        String attemptsStr = authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS);

        if (storedCode == null || expiryStr == null || attemptsStr == null) {
            authenticate(context);
            return;
        }

        int expiry = Integer.parseInt(expiryStr);
        int attempts = Integer.parseInt(attemptsStr);
        int maxRetries = getConfigInt(context, SmsOtpConst.CONFIG_MAX_RETRIES, SmsOtpConst.DEFAULT_MAX_RETRIES);

        // Check expiry — resend a new code if expired
        if (Time.currentTime() > expiry) {
            int codeLength = getConfigInt(context, SmsOtpConst.CONFIG_CODE_LENGTH, SmsOtpConst.DEFAULT_CODE_LENGTH);
            int newTtl = getConfigInt(context, SmsOtpConst.CONFIG_TTL, SmsOtpConst.DEFAULT_TTL);
            String newCode = generateCode(codeLength);
            authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_CODE, newCode);
            authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY, String.valueOf(Time.currentTime() + newTtl));
            authSession.setAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS, "0");
            sendSms(context, newCode);
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                    context.form().setError(SmsOtpConst.ERROR_OTP_EXPIRED).createForm(SmsOtpConst.LOGIN_TEMPLATE));
            return;
        }

        // Check attempts
        if (attempts >= maxRetries) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(SmsOtpConst.ERROR_OTP_MAX_RETRIES).createForm(SmsOtpConst.LOGIN_TEMPLATE));
            return;
        }

        // Constant-time comparison
        if (MessageDigest.isEqual(storedCode.getBytes(StandardCharsets.UTF_8), enteredOtp.getBytes(StandardCharsets.UTF_8))) {
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
        String phoneAttr = SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE;
        return user.getFirstAttribute(phoneAttr) != null;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

    private boolean sendSms(AuthenticationFlowContext context, String code) {
        String phoneAttr = getConfigString(context, SmsOtpConst.CONFIG_PHONE_ATTRIBUTE, SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE);
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
}
