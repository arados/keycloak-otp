package hr.delmisoft.keycloak.otp.sms;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.provider.ProviderConfigProperty;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;

class SmsOtpAuthenticatorFactoryTest {

    private SmsOtpAuthenticatorFactory factory;

    @BeforeEach
    void setUp() {
        factory = new SmsOtpAuthenticatorFactory();
    }

    @Test
    void getId_returnsCorrectId() {
        assertThat(factory.getId(), equalTo(SmsOtpConst.BROWSER_PROVIDER_ID));
    }

    @Test
    void getDisplayType_returnsExpected() {
        assertThat(factory.getDisplayType(), equalTo("SMS OTP Form"));
    }

    @Test
    void isConfigurable_returnsTrue() {
        assertThat(factory.isConfigurable(), equalTo(true));
    }

    @Test
    void getRequirementChoices_containsThreeChoices() {
        AuthenticationExecutionModel.Requirement[] choices = factory.getRequirementChoices();
        assertThat(choices, notNullValue());
        assertThat(choices.length, equalTo(3));
    }

    @Test
    void getConfigProperties_returnsFourProperties() {
        // Phone attribute is intentionally absent — it is realm-scoped only. See CFG-001.
        List<ProviderConfigProperty> props = factory.getConfigProperties();
        assertThat(props, hasSize(4));
        assertThat(props.get(0).getName(), equalTo(SmsOtpConst.CONFIG_CODE_LENGTH));
        assertThat(props.get(1).getName(), equalTo(SmsOtpConst.CONFIG_TTL));
        assertThat(props.get(2).getName(), equalTo(SmsOtpConst.CONFIG_MAX_RETRIES));
        assertThat(props.get(3).getName(), equalTo(SmsOtpConst.CONFIG_SEND_COOLDOWN));
    }

    @Test
    void getConfigProperties_haveDefaults() {
        List<ProviderConfigProperty> props = factory.getConfigProperties();
        assertThat(props.get(0).getDefaultValue(), equalTo(String.valueOf(SmsOtpConst.DEFAULT_CODE_LENGTH)));
        assertThat(props.get(1).getDefaultValue(), equalTo(String.valueOf(SmsOtpConst.DEFAULT_TTL)));
        assertThat(props.get(2).getDefaultValue(), equalTo(String.valueOf(SmsOtpConst.DEFAULT_MAX_RETRIES)));
        assertThat(props.get(3).getDefaultValue(), equalTo(String.valueOf(SmsOtpConst.DEFAULT_SEND_COOLDOWN)));
    }

    @Test
    void create_returnsSingletonAuthenticator() {
        Authenticator a1 = factory.create(null);
        Authenticator a2 = factory.create(null);
        assertThat(a1, instanceOf(SmsOtpAuthenticator.class));
        assertThat(a1, equalTo(a2));
    }

    @Test
    void getReferenceCategory_returnsOtp() {
        assertThat(factory.getReferenceCategory(), equalTo("otp"));
    }

    @Test
    void isUserSetupAllowed_returnsFalse() {
        assertThat(factory.isUserSetupAllowed(), equalTo(false));
    }

    @Test
    void getHelpText_returnsNonNull() {
        assertThat(factory.getHelpText(), notNullValue());
    }
}
