package hr.delmisoft.keycloak.otp;

public final class OtpChannelChoiceConst {

    private OtpChannelChoiceConst() {}

    public static final String PROVIDER_ID = "otp-channel-choice-form";

    // Config keys (shared for both channels)
    public static final String CONFIG_CODE_LENGTH = "otpChoice.codeLength";
    public static final String CONFIG_TTL = "otpChoice.ttl";
    public static final String CONFIG_MAX_RETRIES = "otpChoice.maxRetries";
    public static final String CONFIG_PHONE_ATTRIBUTE = "otpChoice.phoneAttribute";

    // Defaults
    public static final int DEFAULT_CODE_LENGTH = 6;
    public static final int DEFAULT_TTL = 300;
    public static final int DEFAULT_MAX_RETRIES = 3;
}
