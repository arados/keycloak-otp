package hr.delmisoft.keycloak.otp.sms;

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
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

public class SmsOtpDirectGrantAuthenticator extends AbstractDirectGrantAuthenticator {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String phoneAttr = getConfigString(context, SmsOtpConst.CONFIG_PHONE_ATTRIBUTE, SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE);
        String phoneNumber = user != null ? user.getFirstAttribute(phoneAttr) : null;

        if (user == null || phoneNumber == null || phoneNumber.isBlank()) {
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_USER,
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "User has no phone number configured"));
            return;
        }

        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();
        String otp = params.getFirst(SmsOtpConst.PARAM_OTP);
        String otpSessionId = params.getFirst(SmsOtpConst.PARAM_OTP_SESSION_ID);

        if (otp == null || otp.isBlank()) {
            handlePhase1(context, phoneNumber);
        } else {
            handlePhase2(context, otp, otpSessionId);
        }
    }

    private void handlePhase1(AuthenticationFlowContext context, String phoneNumber) {
        int codeLength = getConfigInt(context, SmsOtpConst.CONFIG_CODE_LENGTH, SmsOtpConst.DEFAULT_CODE_LENGTH);
        int ttl = getConfigInt(context, SmsOtpConst.CONFIG_TTL, SmsOtpConst.DEFAULT_TTL);

        String code = generateCode(codeLength);
        String sessionId = UUID.randomUUID().toString();

        Map<String, String> notes = new HashMap<>();
        notes.put(SmsOtpConst.NOTE_CODE, code);
        notes.put(SmsOtpConst.NOTE_USER_ID, context.getUser().getId());
        notes.put(SmsOtpConst.NOTE_ATTEMPTS, "0");

        SingleUseObjectProvider store = context.getSession().getProvider(SingleUseObjectProvider.class);
        store.put(sessionId, ttl, notes);

        try {
            String message = "Your verification code is: " + code;
            context.getSession().getProvider(SmsProvider.class).send(phoneNumber, message);
        } catch (SmsException e) {
            store.remove(sessionId);
            context.getEvent().error(Errors.USER_NOT_FOUND);
            context.failure(AuthenticationFlowError.INTERNAL_ERROR,
                    errorResponse(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(), "sms_send_failed", "Failed to send OTP SMS"));
            return;
        }

        Map<String, String> body = new HashMap<>();
        body.put("error", SmsOtpConst.ERROR_SMS_OTP_REQUIRED);
        body.put("error_description", "An OTP code has been sent to your phone number.");
        body.put(SmsOtpConst.PARAM_OTP_SESSION_ID, sessionId);

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
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), SmsOtpConst.ERROR_SESSION_EXPIRED, "OTP session has expired"));
            return;
        }

        // Verify user binding
        String storedUserId = notes.get(SmsOtpConst.NOTE_USER_ID);
        if (storedUserId == null || !context.getUser().getId().equals(storedUserId)) {
            store.remove(otpSessionId);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_USER,
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid OTP session"));
            return;
        }

        int attempts = Integer.parseInt(notes.get(SmsOtpConst.NOTE_ATTEMPTS));
        int maxRetries = getConfigInt(context, SmsOtpConst.CONFIG_MAX_RETRIES, SmsOtpConst.DEFAULT_MAX_RETRIES);

        if (attempts >= maxRetries) {
            store.remove(otpSessionId);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), SmsOtpConst.ERROR_OTP_MAX_RETRIES, "Too many failed attempts"));
            return;
        }

        String storedCode = notes.get(SmsOtpConst.NOTE_CODE);
        if (storedCode == null) {
            store.remove(otpSessionId);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), SmsOtpConst.ERROR_SESSION_EXPIRED, "OTP session is corrupt"));
            return;
        }

        if (MessageDigest.isEqual(storedCode.getBytes(), otp.getBytes())) {
            store.remove(otpSessionId);
            context.success();
        } else {
            notes.put(SmsOtpConst.NOTE_ATTEMPTS, String.valueOf(attempts + 1));
            store.replace(otpSessionId, notes);
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                    errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), SmsOtpConst.ERROR_OTP_INVALID, "Invalid OTP code"));
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE) != null;
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
        return "SMS OTP";
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
        return "Validates SMS OTP for direct grant (Resource Owner Password Credentials) flow.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty codeLength = new ProviderConfigProperty();
        codeLength.setName(SmsOtpConst.CONFIG_CODE_LENGTH);
        codeLength.setLabel("Code Length");
        codeLength.setHelpText("Number of digits in the OTP code.");
        codeLength.setType(ProviderConfigProperty.STRING_TYPE);
        codeLength.setDefaultValue(String.valueOf(SmsOtpConst.DEFAULT_CODE_LENGTH));

        ProviderConfigProperty ttl = new ProviderConfigProperty();
        ttl.setName(SmsOtpConst.CONFIG_TTL);
        ttl.setLabel("Code TTL (seconds)");
        ttl.setHelpText("Time-to-live in seconds for the OTP code.");
        ttl.setType(ProviderConfigProperty.STRING_TYPE);
        ttl.setDefaultValue(String.valueOf(SmsOtpConst.DEFAULT_TTL));

        ProviderConfigProperty maxRetries = new ProviderConfigProperty();
        maxRetries.setName(SmsOtpConst.CONFIG_MAX_RETRIES);
        maxRetries.setLabel("Max Retries");
        maxRetries.setHelpText("Maximum number of failed attempts before the code is invalidated.");
        maxRetries.setType(ProviderConfigProperty.STRING_TYPE);
        maxRetries.setDefaultValue(String.valueOf(SmsOtpConst.DEFAULT_MAX_RETRIES));

        ProviderConfigProperty phoneAttr = new ProviderConfigProperty();
        phoneAttr.setName(SmsOtpConst.CONFIG_PHONE_ATTRIBUTE);
        phoneAttr.setLabel("Phone Number Attribute");
        phoneAttr.setHelpText("User attribute that stores the phone number.");
        phoneAttr.setType(ProviderConfigProperty.STRING_TYPE);
        phoneAttr.setDefaultValue(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE);

        return List.of(codeLength, ttl, maxRetries, phoneAttr);
    }

    @Override
    public String getId() {
        return SmsOtpConst.DIRECT_GRANT_PROVIDER_ID;
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

    private static String getConfigString(AuthenticationFlowContext context, String key, String defaultValue) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null) {
            return defaultValue;
        }
        String value = config.getConfig().get(key);
        return (value == null || value.isBlank()) ? defaultValue : value;
    }
}
