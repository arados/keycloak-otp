package hr.delmisoft.keycloak.otp.grant;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;

public class SmsOtpGrantTypeFactory implements OAuth2GrantTypeFactory {

    public static final String GRANT_TYPE = "urn:otp:sms";

    @Override
    public String getId() {
        return GRANT_TYPE;
    }

    @Override
    public String getShortcut() {
        return "os";
    }

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new SmsOtpGrantType();
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
