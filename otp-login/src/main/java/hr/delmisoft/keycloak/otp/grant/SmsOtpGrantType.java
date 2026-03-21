package hr.delmisoft.keycloak.otp.grant;

import org.keycloak.models.UserModel;

import hr.delmisoft.keycloak.otp.sms.SmsOtpConst;
import hr.delmisoft.keycloak.otp.sms.SmsProvider;

/**
 * Custom OAuth2 grant type for SMS OTP authentication.
 * <p>
 * Usage:
 * <pre>
 * grant_type=urn:otp:sms
 * client_id=...
 * username=...
 * password=...       (optional — if present, validates password + OTP; if absent, OTP only)
 * otp=...            (phase 2 only)
 * otp_session_id=... (phase 2 only)
 * </pre>
 */
public class SmsOtpGrantType extends AbstractOtpGrantType {

    @Override
    protected void sendOtp(UserModel user, String code) throws Exception {
        String phoneNumber = user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE);
        if (phoneNumber == null || phoneNumber.isBlank()) {
            throw new IllegalStateException("User has no phone number configured");
        }
        String message = "Your verification code is: " + code;
        session.getProvider(SmsProvider.class).send(phoneNumber, message);
    }

    @Override
    protected String getOtpRequiredError() {
        return SmsOtpConst.ERROR_SMS_OTP_REQUIRED;
    }

    @Override
    protected String getOtpSentDescription() {
        return "An OTP code has been sent to your phone number.";
    }

    @Override
    protected String getSessionExpiredError() {
        return SmsOtpConst.ERROR_SESSION_EXPIRED;
    }

    @Override
    protected String getOtpInvalidError() {
        return SmsOtpConst.ERROR_OTP_INVALID;
    }

    @Override
    protected String getMaxRetriesError() {
        return SmsOtpConst.ERROR_OTP_MAX_RETRIES;
    }
}
