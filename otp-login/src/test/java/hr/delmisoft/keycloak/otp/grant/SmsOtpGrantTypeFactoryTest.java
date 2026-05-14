package hr.delmisoft.keycloak.otp.grant;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;

class SmsOtpGrantTypeFactoryTest {

    private final SmsOtpGrantTypeFactory factory = new SmsOtpGrantTypeFactory();

    @Test
    void getId_returnsUrnGrantType() {
        assertThat(factory.getId(), equalTo("urn:otp:sms"));
    }

    @Test
    void getShortcut_isStableForUrlSafeForm() {
        assertThat(factory.getShortcut(), equalTo("os"));
    }

    @Test
    void create_returnsSmsGrantInstance() {
        OAuth2GrantType grant = factory.create(null);
        assertThat(grant, notNullValue());
        assertThat(grant, instanceOf(SmsOtpGrantType.class));
    }
}
