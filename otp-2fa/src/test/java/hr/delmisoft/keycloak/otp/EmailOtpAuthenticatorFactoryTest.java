package hr.delmisoft.keycloak.otp;

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

class EmailOtpAuthenticatorFactoryTest {

    private EmailOtpAuthenticatorFactory factory;

    @BeforeEach
    void setUp() {
        factory = new EmailOtpAuthenticatorFactory();
    }

    @Test
    void getId_returnsCorrectId() {
        assertThat(factory.getId(), equalTo(EmailOtpConst.BROWSER_PROVIDER_ID));
    }

    @Test
    void getDisplayType_returnsNonNull() {
        assertThat(factory.getDisplayType(), equalTo("Email OTP Form"));
    }

    @Test
    void isConfigurable_returnsTrue() {
        assertThat(factory.isConfigurable(), equalTo(true));
    }

    @Test
    void getRequirementChoices_containsRequiredAlternativeDisabled() {
        AuthenticationExecutionModel.Requirement[] choices = factory.getRequirementChoices();
        assertThat(choices, notNullValue());
        assertThat(choices.length, equalTo(3));
    }

    @Test
    void getConfigProperties_returnsThreeProperties() {
        List<ProviderConfigProperty> props = factory.getConfigProperties();
        assertThat(props, hasSize(3));
        assertThat(props.get(0).getName(), equalTo(EmailOtpConst.CONFIG_CODE_LENGTH));
        assertThat(props.get(1).getName(), equalTo(EmailOtpConst.CONFIG_TTL));
        assertThat(props.get(2).getName(), equalTo(EmailOtpConst.CONFIG_MAX_RETRIES));
    }

    @Test
    void getConfigProperties_haveDefaults() {
        List<ProviderConfigProperty> props = factory.getConfigProperties();
        assertThat(props.get(0).getDefaultValue(), equalTo(String.valueOf(EmailOtpConst.DEFAULT_CODE_LENGTH)));
        assertThat(props.get(1).getDefaultValue(), equalTo(String.valueOf(EmailOtpConst.DEFAULT_TTL)));
        assertThat(props.get(2).getDefaultValue(), equalTo(String.valueOf(EmailOtpConst.DEFAULT_MAX_RETRIES)));
    }

    @Test
    void create_returnsSingletonAuthenticator() {
        Authenticator a1 = factory.create(null);
        Authenticator a2 = factory.create(null);
        assertThat(a1, instanceOf(EmailOtpAuthenticator.class));
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
