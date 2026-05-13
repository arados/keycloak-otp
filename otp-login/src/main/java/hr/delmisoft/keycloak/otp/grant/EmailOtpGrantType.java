package hr.delmisoft.keycloak.otp.grant;

import java.util.HashMap;
import java.util.Map;

import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.models.UserModel;

import hr.delmisoft.keycloak.otp.EmailOtpConst;
import hr.delmisoft.keycloak.otp.OtpSendThrottle;

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

    @Override
    protected String getChannel() {
        return OtpSendThrottle.CHANNEL_EMAIL;
    }

    @Override
    protected boolean isChannelVerified(UserModel user) {
        if (user.getEmail() == null) {
            return false;
        }
        String configured = realm.getAttribute(EmailOtpConst.CONFIG_REQUIRE_VERIFIED_EMAIL);
        boolean requireVerified = (configured == null || configured.isBlank())
                ? EmailOtpConst.DEFAULT_REQUIRE_VERIFIED_EMAIL
                : Boolean.parseBoolean(configured);
        return !requireVerified || user.isEmailVerified();
    }
}
