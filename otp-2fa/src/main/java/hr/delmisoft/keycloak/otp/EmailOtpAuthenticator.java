package hr.delmisoft.keycloak.otp;

import java.security.MessageDigest;
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
        int codeLength = getConfigInt(context, EmailOtpConst.CONFIG_CODE_LENGTH, EmailOtpConst.DEFAULT_CODE_LENGTH);
        int ttl = getConfigInt(context, EmailOtpConst.CONFIG_TTL, EmailOtpConst.DEFAULT_TTL);

        String code = generateCode(codeLength);

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_CODE, code);
        authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY, String.valueOf(Time.currentTime() + ttl));
        authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS, "0");

        if (!sendEmail(context, code)) {
            return;
        }

        context.challenge(context.form().createForm(EmailOtpConst.LOGIN_TEMPLATE));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String enteredOtp = context.getHttpRequest().getDecodedFormParameters().getFirst(EmailOtpConst.PARAM_OTP);
        if (enteredOtp == null || enteredOtp.isBlank()) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(EmailOtpConst.ERROR_OTP_INVALID).createForm(EmailOtpConst.LOGIN_TEMPLATE));
            return;
        }

        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String storedCode = authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE);
        String expiryStr = authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY);
        String attemptsStr = authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS);

        if (storedCode == null || expiryStr == null || attemptsStr == null) {
            // Session state is missing or corrupted — restart OTP flow
            authenticate(context);
            return;
        }

        int expiry = Integer.parseInt(expiryStr);
        int attempts = Integer.parseInt(attemptsStr);
        int maxRetries = getConfigInt(context, EmailOtpConst.CONFIG_MAX_RETRIES, EmailOtpConst.DEFAULT_MAX_RETRIES);

        // Check expiry — resend a new code if expired
        if (Time.currentTime() > expiry) {
            int codeLength = getConfigInt(context, EmailOtpConst.CONFIG_CODE_LENGTH, EmailOtpConst.DEFAULT_CODE_LENGTH);
            int ttl = getConfigInt(context, EmailOtpConst.CONFIG_TTL, EmailOtpConst.DEFAULT_TTL);
            String newCode = generateCode(codeLength);
            authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_CODE, newCode);
            authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY, String.valueOf(Time.currentTime() + ttl));
            authSession.setAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS, "0");
            sendEmail(context, newCode);
            context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
                    context.form().setError(EmailOtpConst.ERROR_OTP_EXPIRED).createForm(EmailOtpConst.LOGIN_TEMPLATE));
            return;
        }

        // Check attempts
        if (attempts >= maxRetries) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(EmailOtpConst.ERROR_OTP_MAX_RETRIES).createForm(EmailOtpConst.LOGIN_TEMPLATE));
            return;
        }

        // Constant-time comparison
        if (MessageDigest.isEqual(storedCode.getBytes(), enteredOtp.getBytes())) {
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
        return user.getEmail() != null;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // no required actions
    }

    @Override
    public void close() {
        // no-op
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
}
