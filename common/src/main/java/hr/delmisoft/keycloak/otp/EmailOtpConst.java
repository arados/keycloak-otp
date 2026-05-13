package hr.delmisoft.keycloak.otp;

public final class EmailOtpConst {

    private EmailOtpConst() {}

    // Provider IDs
    public static final String BROWSER_PROVIDER_ID = "email-otp-form";
    public static final String THEME_RESOURCE_PROVIDER_ID = "email-otp-resources";

    // Config keys
    public static final String CONFIG_CODE_LENGTH = "emailOtp.codeLength";
    public static final String CONFIG_TTL = "emailOtp.ttl";
    public static final String CONFIG_MAX_RETRIES = "emailOtp.maxRetries";
    public static final String CONFIG_SEND_COOLDOWN = "emailOtp.sendCooldown";
    public static final String CONFIG_REQUIRE_VERIFIED_EMAIL = "emailOtp.requireVerifiedEmail";

    // Defaults
    public static final int DEFAULT_CODE_LENGTH = 6;
    public static final int DEFAULT_TTL = 300;
    public static final int DEFAULT_MAX_RETRIES = 3;
    public static final int DEFAULT_SEND_COOLDOWN = 60;
    public static final boolean DEFAULT_REQUIRE_VERIFIED_EMAIL = true;

    // Auth session note keys (browser flow)
    public static final String AUTH_NOTE_CODE_HASH = "emailOtpCodeHash";
    public static final String AUTH_NOTE_CODE_SALT = "emailOtpCodeSalt";
    public static final String AUTH_NOTE_EXPIRY = "emailOtpExpiry";
    public static final String AUTH_NOTE_ATTEMPTS = "emailOtpAttempts";
    public static final String AUTH_NOTE_LAST_SENT = "emailOtpLastSent";

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
    public static final String ERROR_EMAIL_OTP_REQUIRED = "email_otp_required";
    public static final String ERROR_OTP_INVALID = "emailOtpInvalid";
    public static final String ERROR_OTP_EXPIRED = "emailOtpExpired";
    public static final String ERROR_OTP_MAX_RETRIES = "emailOtpMaxRetries";
    public static final String ERROR_SESSION_EXPIRED = "emailOtpSessionExpired";
    public static final String ERROR_OTP_SEND_THROTTLED = "otp_send_throttled";

    // Email template
    public static final String EMAIL_TEMPLATE = "email-otp-code.ftl";
    public static final String EMAIL_SUBJECT_KEY = "emailOtpSubject";

    // Login template
    public static final String LOGIN_TEMPLATE = "login-email-otp.ftl";
}
