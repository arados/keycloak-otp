package hr.delmisoft.keycloak.otp.grant;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;

class EmailOtpGrantTypeFactoryTest {

    private final EmailOtpGrantTypeFactory factory = new EmailOtpGrantTypeFactory();

    @Test
    void getId_returnsUrnGrantType() {
        assertThat(factory.getId(), equalTo("urn:otp:email"));
    }

    @Test
    void getShortcut_isStableForUrlSafeForm() {
        // The shortcut is what Keycloak exposes in the metadata listing of supported grants;
        // changing it is a breaking API change for clients that hard-code it.
        assertThat(factory.getShortcut(), equalTo("oe"));
    }

    @Test
    void create_returnsEmailGrantInstance() {
        OAuth2GrantType grant = factory.create(null);
        assertThat(grant, notNullValue());
        assertThat(grant, instanceOf(EmailOtpGrantType.class));
    }
}
