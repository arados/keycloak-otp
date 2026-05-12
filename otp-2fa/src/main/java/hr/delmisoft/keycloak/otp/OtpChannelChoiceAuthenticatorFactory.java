package hr.delmisoft.keycloak.otp;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import hr.delmisoft.keycloak.otp.sms.SmsOtpConst;

public class OtpChannelChoiceAuthenticatorFactory implements AuthenticatorFactory {

    private static final OtpChannelChoiceAuthenticator INSTANCE = new OtpChannelChoiceAuthenticator();

    @Override
    public String getId() {
        return OtpChannelChoiceConst.PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "OTP Channel Choice (Email or SMS)";
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
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Presents a choice between Email and SMS OTP, then sends a one-time code via the chosen channel.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty codeLength = new ProviderConfigProperty();
        codeLength.setName(OtpChannelChoiceConst.CONFIG_CODE_LENGTH);
        codeLength.setLabel("Code Length");
        codeLength.setHelpText("Number of digits in the OTP code.");
        codeLength.setType(ProviderConfigProperty.STRING_TYPE);
        codeLength.setDefaultValue(String.valueOf(OtpChannelChoiceConst.DEFAULT_CODE_LENGTH));

        ProviderConfigProperty ttl = new ProviderConfigProperty();
        ttl.setName(OtpChannelChoiceConst.CONFIG_TTL);
        ttl.setLabel("Code TTL (seconds)");
        ttl.setHelpText("Time-to-live in seconds for the OTP code.");
        ttl.setType(ProviderConfigProperty.STRING_TYPE);
        ttl.setDefaultValue(String.valueOf(OtpChannelChoiceConst.DEFAULT_TTL));

        ProviderConfigProperty maxRetries = new ProviderConfigProperty();
        maxRetries.setName(OtpChannelChoiceConst.CONFIG_MAX_RETRIES);
        maxRetries.setLabel("Max Retries");
        maxRetries.setHelpText("Maximum number of failed attempts before the code is invalidated.");
        maxRetries.setType(ProviderConfigProperty.STRING_TYPE);
        maxRetries.setDefaultValue(String.valueOf(OtpChannelChoiceConst.DEFAULT_MAX_RETRIES));

        ProviderConfigProperty phoneAttr = new ProviderConfigProperty();
        phoneAttr.setName(OtpChannelChoiceConst.CONFIG_PHONE_ATTRIBUTE);
        phoneAttr.setLabel("Phone Number Attribute");
        phoneAttr.setHelpText("User attribute that stores the phone number.");
        phoneAttr.setType(ProviderConfigProperty.STRING_TYPE);
        phoneAttr.setDefaultValue(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE);

        ProviderConfigProperty sendCooldown = new ProviderConfigProperty();
        sendCooldown.setName(OtpChannelChoiceConst.CONFIG_SEND_COOLDOWN);
        sendCooldown.setLabel("Send Cooldown (seconds)");
        sendCooldown.setHelpText("Minimum interval between OTP sends per user, per channel. Resend is disabled until this elapses. Set to 0 to disable throttling. Should be < Code TTL.");
        sendCooldown.setType(ProviderConfigProperty.STRING_TYPE);
        sendCooldown.setDefaultValue(String.valueOf(OtpChannelChoiceConst.DEFAULT_SEND_COOLDOWN));

        return List.of(codeLength, ttl, maxRetries, phoneAttr, sendCooldown);
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return INSTANCE;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
