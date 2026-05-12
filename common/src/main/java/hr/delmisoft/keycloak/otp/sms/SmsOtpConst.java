package hr.delmisoft.keycloak.otp.sms;

public final class SmsOtpConst {

    private SmsOtpConst() {}

    // Provider IDs
    public static final String BROWSER_PROVIDER_ID = "sms-otp-form";

    // Config keys
    public static final String CONFIG_CODE_LENGTH = "smsOtp.codeLength";
    public static final String CONFIG_TTL = "smsOtp.ttl";
    public static final String CONFIG_MAX_RETRIES = "smsOtp.maxRetries";
    public static final String CONFIG_PHONE_ATTRIBUTE = "smsOtp.phoneAttribute";
    public static final String CONFIG_SEND_COOLDOWN = "smsOtp.sendCooldown";

    // Defaults
    public static final int DEFAULT_CODE_LENGTH = 6;
    public static final int DEFAULT_TTL = 300;
    public static final int DEFAULT_MAX_RETRIES = 3;
    public static final int DEFAULT_SEND_COOLDOWN = 60;
    public static final String DEFAULT_PHONE_ATTRIBUTE = "phoneNumber";

    // Auth session note keys (browser flow)
    public static final String AUTH_NOTE_CODE = "smsOtpCode";
    public static final String AUTH_NOTE_EXPIRY = "smsOtpExpiry";
    public static final String AUTH_NOTE_ATTEMPTS = "smsOtpAttempts";
    public static final String AUTH_NOTE_LAST_SENT = "smsOtpLastSent";

    // SingleUseObject note keys (direct grant)
    public static final String NOTE_CODE = "code";
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
