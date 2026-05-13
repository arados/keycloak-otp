package hr.delmisoft.keycloak.otp.sms;

import org.keycloak.models.RealmModel;

public final class SmsOtpConst {

    private SmsOtpConst() {}

    /**
     * Resolves the user attribute that stores the phone number to send the OTP to.
     * Reads the realm-level {@code smsOtp.phoneAttribute} setting, falling back to
     * {@link #DEFAULT_PHONE_ATTRIBUTE}. Keeps "is the user eligible?" and "where do we
     * send?" consistent across the browser and grant flows.
     */
    public static String resolvePhoneAttribute(RealmModel realm) {
        String configured = realm.getAttribute(CONFIG_PHONE_ATTRIBUTE);
        if (configured == null || configured.isBlank()) {
            return DEFAULT_PHONE_ATTRIBUTE;
        }
        return configured;
    }

    // Provider IDs
    public static final String BROWSER_PROVIDER_ID = "sms-otp-form";

    // Config keys
    public static final String CONFIG_CODE_LENGTH = "smsOtp.codeLength";
    public static final String CONFIG_TTL = "smsOtp.ttl";
    public static final String CONFIG_MAX_RETRIES = "smsOtp.maxRetries";
    public static final String CONFIG_PHONE_ATTRIBUTE = "smsOtp.phoneAttribute";
    public static final String CONFIG_SEND_COOLDOWN = "smsOtp.sendCooldown";
    public static final String CONFIG_REQUIRE_VERIFIED_PHONE = "smsOtp.requireVerifiedPhone";
    public static final String CONFIG_VERIFIED_PHONE_ATTRIBUTE = "smsOtp.verifiedPhoneAttribute";

    // Defaults
    public static final int DEFAULT_CODE_LENGTH = 6;
    public static final int DEFAULT_TTL = 300;
    public static final int DEFAULT_MAX_RETRIES = 3;
    public static final int DEFAULT_SEND_COOLDOWN = 60;
    public static final String DEFAULT_PHONE_ATTRIBUTE = "phoneNumber";
    public static final boolean DEFAULT_REQUIRE_VERIFIED_PHONE = false;
    public static final String DEFAULT_VERIFIED_PHONE_ATTRIBUTE = "phoneNumberVerified";

    // Auth session note keys (browser flow)
    public static final String AUTH_NOTE_CODE_HASH = "smsOtpCodeHash";
    public static final String AUTH_NOTE_CODE_SALT = "smsOtpCodeSalt";
    public static final String AUTH_NOTE_EXPIRY = "smsOtpExpiry";
    public static final String AUTH_NOTE_ATTEMPTS = "smsOtpAttempts";
    public static final String AUTH_NOTE_LAST_SENT = "smsOtpLastSent";

    // SingleUseObject note keys (direct grant)
    public static final String NOTE_CODE_HASH = "codeHash";
    public static final String NOTE_CODE_SALT = "codeSalt";
    public static final String NOTE_USER_ID = "userId";
    public static final String NOTE_ATTEMPTS = "attempts";

    // Form / request param names
    public static final String PARAM_OTP = "otp";
    public static final String PARAM_OTP_SESSION_ID = "otp_session_id";
    public static final String PARAM_RESEND = "resend";

    // Error codes
    public static final String ERROR_SMS_OTP_REQUIRED = "sms_otp_required";
    public static final String ERROR_OTP_INVALID = "smsOtpInvalid";
    public static final String ERROR_OTP_EXPIRED = "smsOtpExpired";
    public static final String ERROR_OTP_MAX_RETRIES = "smsOtpMaxRetries";
    public static final String ERROR_SESSION_EXPIRED = "smsOtpSessionExpired";
    public static final String ERROR_OTP_SEND_THROTTLED = "otp_send_throttled";

    // SMS message key
    public static final String SMS_MESSAGE_KEY = "smsOtpMessage";

    // Login template
    public static final String LOGIN_TEMPLATE = "login-sms-otp.ftl";
}
