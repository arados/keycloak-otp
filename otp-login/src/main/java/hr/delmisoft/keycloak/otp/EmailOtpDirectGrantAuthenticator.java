package hr.delmisoft.keycloak.otp;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

public class EmailOtpDirectGrantAuthenticator extends AbstractDirectGrantAuthenticator {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        if (user == null || user.getEmail() == null) {
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_USER,
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "User has no email configured"));
            return;
        }

        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        String otp = params.getFirst(EmailOtpConst.PARAM_OTP);
        String otpSessionId = params.getFirst(EmailOtpConst.PARAM_OTP_SESSION_ID);

        if (otp == null || otp.isBlank()) {
            // Phase 1: Send OTP email
            handlePhase1(context);
        } else {
            // Phase 2: Validate OTP
            handlePhase2(context, otp, otpSessionId);
        }
    }

    private void handlePhase1(AuthenticationFlowContext context) {
        int codeLength = getConfigInt(context, EmailOtpConst.CONFIG_CODE_LENGTH, EmailOtpConst.DEFAULT_CODE_LENGTH);
        int ttl = getConfigInt(context, EmailOtpConst.CONFIG_TTL, EmailOtpConst.DEFAULT_TTL);

        String code = generateCode(codeLength);
        String sessionId = UUID.randomUUID().toString();

        Map<String, String> notes = new HashMap<>();
        notes.put(EmailOtpConst.NOTE_CODE, code);
        notes.put(EmailOtpConst.NOTE_USER_ID, context.getUser().getId());
        notes.put(EmailOtpConst.NOTE_ATTEMPTS, "0");

        SingleUseObjectProvider store = context.getSession().getProvider(SingleUseObjectProvider.class);
        store.put(sessionId, ttl, notes);

        try {
            context.getSession().getProvider(EmailTemplateProvider.class)
                    .setRealm(context.getRealm())
                    .setUser(context.getUser())
                    .send(EmailOtpConst.EMAIL_SUBJECT_KEY, EmailOtpConst.EMAIL_TEMPLATE, new HashMap<>(Map.of("code", code)));
        } catch (EmailException e) {
            store.remove(sessionId);
            context.getEvent().error(Errors.EMAIL_SEND_FAILED);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR,
                    errorResponse(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "email_send_failed", "Failed to send OTP email"));
            return;
        }

        // Return 401 with otp_session_id
        Map<String, String> body = new HashMap<>();
        body.put("error", EmailOtpConst.ERROR_EMAIL_OTP_REQUIRED);
        body.put("error_description", "An OTP code has been sent to your email address.");
        body.put(EmailOtpConst.PARAM_OTP_SESSION_ID, sessionId);

        Response response = Response.status(Response.Status.UNAUTHORIZED)
                .entity(body)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, response);
    }

    private void handlePhase2(AuthenticationFlowContext context, String otp, String otpSessionId) {
        if (otpSessionId == null || otpSessionId.isBlank()) {
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Missing otp_session_id"));
            return;
        }

        SingleUseObjectProvider store = context.getSession().getProvider(SingleUseObjectProvider.class);
        Map<String, String> notes = store.get(otpSessionId);

        if (notes == null) {
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), EmailOtpConst.ERROR_SESSION_EXPIRED, "OTP session has expired"));
            return;
        }

        // Verify user binding
        String storedUserId = notes.get(EmailOtpConst.NOTE_USER_ID);
        if (storedUserId == null || !context.getUser().getId().equals(storedUserId)) {
            store.remove(otpSessionId);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_USER,
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid OTP session"));
            return;
        }

        int attempts = Integer.parseInt(notes.get(EmailOtpConst.NOTE_ATTEMPTS));
        int maxRetries = getConfigInt(context, EmailOtpConst.CONFIG_MAX_RETRIES, EmailOtpConst.DEFAULT_MAX_RETRIES);

        // Check max retries
        if (attempts >= maxRetries) {
            store.remove(otpSessionId);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), EmailOtpConst.ERROR_OTP_MAX_RETRIES, "Too many failed attempts"));
            return;
        }

        String storedCode = notes.get(EmailOtpConst.NOTE_CODE);
        if (storedCode == null) {
            store.remove(otpSessionId);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), EmailOtpConst.ERROR_SESSION_EXPIRED, "OTP session is corrupt"));
            return;
        }

        if (MessageDigest.isEqual(storedCode.getBytes(), otp.getBytes())) {
            store.remove(otpSessionId);
            context.success();
        } else {
            // Increment attempts
            notes.put(EmailOtpConst.NOTE_ATTEMPTS, String.valueOf(attempts + 1));
            store.replace(otpSessionId, notes);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), EmailOtpConst.ERROR_OTP_INVALID, "Invalid OTP code"));
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
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getDisplayType() {
        return "Email OTP";
    }

    @Override
    public String getReferenceCategory() {
        return "otp";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getHelpText() {
        return "Validates email OTP for direct grant (Resource Owner Password Credentials) flow.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty codeLength = new ProviderConfigProperty();
        codeLength.setName(EmailOtpConst.CONFIG_CODE_LENGTH);
        codeLength.setLabel("Code Length");
        codeLength.setHelpText("Number of digits in the OTP code.");
        codeLength.setType(ProviderConfigProperty.STRING_TYPE);
        codeLength.setDefaultValue(String.valueOf(EmailOtpConst.DEFAULT_CODE_LENGTH));

        ProviderConfigProperty ttl = new ProviderConfigProperty();
        ttl.setName(EmailOtpConst.CONFIG_TTL);
        ttl.setLabel("Code TTL (seconds)");
        ttl.setHelpText("Time-to-live in seconds for the OTP code.");
        ttl.setType(ProviderConfigProperty.STRING_TYPE);
        ttl.setDefaultValue(String.valueOf(EmailOtpConst.DEFAULT_TTL));

        ProviderConfigProperty maxRetries = new ProviderConfigProperty();
        maxRetries.setName(EmailOtpConst.CONFIG_MAX_RETRIES);
        maxRetries.setLabel("Max Retries");
        maxRetries.setHelpText("Maximum number of failed attempts before the code is invalidated.");
        maxRetries.setType(ProviderConfigProperty.STRING_TYPE);
        maxRetries.setDefaultValue(String.valueOf(EmailOtpConst.DEFAULT_MAX_RETRIES));

        return List.of(codeLength, ttl, maxRetries);
    }

    @Override
    public String getId() {
        return EmailOtpConst.DIRECT_GRANT_PROVIDER_ID;
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
