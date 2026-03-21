package hr.delmisoft.keycloak.otp.grant;

import java.util.HashMap;
import java.util.Map;

import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.UserModel;

import hr.delmisoft.keycloak.otp.EmailOtpConst;

/**
 * Custom OAuth2 grant type for Email OTP authentication.
 * <p>
 * Usage:
 * <pre>
 * grant_type=urn:otp:email
 * client_id=...
 * username=...
 * password=...       (optional — if present, validates password + OTP; if absent, OTP only)
 * otp=...            (phase 2 only)
 * otp_session_id=... (phase 2 only)
 * </pre>
 */
public class EmailOtpGrantType extends AbstractOtpGrantType {

    @Override
    protected void sendOtp(UserModel user, String code) throws Exception {
        session.getProvider(EmailTemplateProvider.class)
                .setRealm(realm)
                .setUser(user)
                .send(EmailOtpConst.EMAIL_SUBJECT_KEY, EmailOtpConst.EMAIL_TEMPLATE,
                        new HashMap<>(Map.of("code", code)));
    }

    @Override
    protected String getOtpRequiredError() {
        return EmailOtpConst.ERROR_EMAIL_OTP_REQUIRED;
    }

    @Override
    protected String getOtpSentDescription() {
        return "An OTP code has been sent to your email address.";
    }

    @Override
    protected String getSessionExpiredError() {
        return EmailOtpConst.ERROR_SESSION_EXPIRED;
    }

    @Override
    protected String getOtpInvalidError() {
        return EmailOtpConst.ERROR_OTP_INVALID;
    }

    @Override
    protected String getMaxRetriesError() {
        return EmailOtpConst.ERROR_OTP_MAX_RETRIES;
    }
}
