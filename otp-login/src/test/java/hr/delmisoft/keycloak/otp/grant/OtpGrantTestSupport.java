package hr.delmisoft.keycloak.otp.grant;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.services.cors.Cors;

/**
 * Shared scaffolding for grant-type unit tests.
 * <p>
 * The {@link OAuth2GrantTypeBase#setContext} machinery wants a populated
 * {@link OAuth2GrantType.Context} with package-private fields. Reflecting against that on every
 * test would be noisy, so the grant under test is given a no-op {@code setContext} override and
 * its protected fields are assigned directly via reflection. This keeps each test's setup focused
 * on the dependencies the assertions actually care about.
 */
final class OtpGrantTestSupport {

    private OtpGrantTestSupport() {}

    static void injectMocks(OAuth2GrantTypeBase grant,
                            KeycloakSession session,
                            RealmModel realm,
                            ClientModel client,
                            ClientConnection clientConnection,
                            MultivaluedMap<String, String> formParams,
                            EventBuilder event,
                            Cors cors,
                            HttpRequest request) {
        setField(grant, "session", session);
        setField(grant, "realm", realm);
        setField(grant, "client", client);
        setField(grant, "clientConnection", clientConnection);
        setField(grant, "formParams", formParams);
        setField(grant, "event", event);
        setField(grant, "cors", cors);
        setField(grant, "request", request);
        setField(grant, "clientAuthAttributes", new HashMap<String, String>());
    }

    /**
     * Build a minimal Context so {@link OAuth2GrantTypeBase#setContext} has something non-null
     * to swallow when {@code process()} is invoked. Test subclasses override {@code setContext}
     * to a no-op, so the context's contents do not actually flow into the grant; this method
     * just satisfies the method signature. Note: the Context constructor calls
     * {@code session.getContext()}, so a non-null session mock is required.
     */
    static OAuth2GrantType.Context dummyContext(KeycloakSession session) {
        return new OAuth2GrantType.Context(session, null,
                new HashMap<>(),
                new MultivaluedHashMap<>(),
                null, null, null);
    }

    private static void setField(Object target, String name, Object value) {
        Class<?> cls = target.getClass();
        while (cls != null) {
            try {
                Field f = cls.getDeclaredField(name);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException e) {
                cls = cls.getSuperclass();
            } catch (IllegalAccessException e) {
                throw new RuntimeException("Failed to set field " + name, e);
            }
        }
        throw new IllegalStateException("Field not found in class hierarchy: " + name);
    }

    static MultivaluedMap<String, String> formParams(Map<String, String> entries) {
        MultivaluedMap<String, String> map = new MultivaluedHashMap<>();
        for (Map.Entry<String, String> e : entries.entrySet()) {
            map.putSingle(e.getKey(), e.getValue());
        }
        return map;
    }
}
