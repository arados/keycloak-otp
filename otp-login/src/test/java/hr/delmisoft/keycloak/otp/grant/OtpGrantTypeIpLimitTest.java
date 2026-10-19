package hr.delmisoft.keycloak.otp.grant;

import java.util.Map;
import java.util.stream.Stream;

import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.ClientConnection;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.BruteForceProtector;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import hr.delmisoft.keycloak.otp.OtpSendThrottle;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Per-source-IP send limit on the OTP grant types' phase 1. The limit is checked before the
 * per-user cooldown so a blocked IP does not burn the victim's cooldown slot, and the IP slot
 * is released again when nothing was actually sent.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OtpGrantTypeIpLimitTest {

    private static final String IP = "203.0.113.7";
    private static final String IP_KEY_PREFIX = "otp-ip:realm-1:" + IP + ":";
    private static final String USER_KEY_PREFIX = "otp-throttle:";
    private static final String IDENTIFIER_KEY_PREFIX = "otp-throttle:id:";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock ClientModel client;
    @Mock UserModel user;
    @Mock UserProvider userProvider;
    @Mock SingleUseObjectProvider singleUseStore;
    @Mock EmailTemplateProvider emailProvider;
    @Mock BruteForceProtector bruteForceProtector;
    @Mock ClientConnection clientConnection;
    @Mock HttpRequest httpRequest;
    @Mock EventBuilder event;
    @Mock Cors cors;
    @Mock KeycloakContext keycloakContext;

    private AbstractOtpGrantTypeTest.TestableEmailOtpGrantType grant;

    @BeforeEach
    void setUp() {
        grant = new AbstractOtpGrantTypeTest.TestableEmailOtpGrantType();

        when(session.users()).thenReturn(userProvider);
        when(session.getContext()).thenReturn(keycloakContext);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUseStore);
        when(session.getProvider(EmailTemplateProvider.class)).thenReturn(emailProvider);
        when(session.getProvider(BruteForceProtector.class)).thenReturn(bruteForceProtector);
        when(emailProvider.setRealm(any())).thenReturn(emailProvider);
        when(emailProvider.setUser(any())).thenReturn(emailProvider);

        when(client.isDirectAccessGrantsEnabled()).thenReturn(true);
        when(client.isConsentRequired()).thenReturn(false);
        when(client.getClientId()).thenReturn("test-client");

        when(realm.getId()).thenReturn("realm-1");
        when(realm.isLoginWithEmailAllowed()).thenReturn(false);
        when(realm.isBruteForceProtected()).thenReturn(false);

        when(user.getId()).thenReturn("user-1");
        when(user.isEnabled()).thenReturn(true);
        when(user.getEmail()).thenReturn("test@example.com");
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getRequiredActionsStream()).thenReturn(Stream.empty());

        when(userProvider.getUserByUsername(any(), any())).thenReturn(user);
        when(clientConnection.getRemoteAddr()).thenReturn(IP);
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(true);

        when(event.detail(anyString(), anyString())).thenReturn(event);
        when(event.user(any(UserModel.class))).thenReturn(event);

        OtpGrantTestSupport.injectMocks(grant, session, realm, client, clientConnection,
                OtpGrantTestSupport.formParams(Map.of("username", "alice")), event, cors, httpRequest);
    }

    private void ipLimitReached() {
        when(singleUseStore.putIfAbsent(startsWith("otp-ip:"), anyLong())).thenReturn(false);
    }

    @Test
    void phase1_success_reservesIpSlotWithDefaultWindow() throws Exception {
        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(401));
        verify(singleUseStore).putIfAbsent(startsWith(IP_KEY_PREFIX),
                eq((long) OtpSendThrottle.DEFAULT_IP_SEND_WINDOW));
        verify(emailProvider).send(anyString(), anyString(), any());
    }

    @Test
    void phase1_ipLimitReached_returns429WithRetryAfter() throws Exception {
        ipLimitReached();

        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(429));
        Map<?, ?> body = (Map<?, ?>) response.getEntity();
        assertThat(body.get("error"), equalTo("otp_send_throttled"));
        assertThat((Integer) body.get("retry_after"), greaterThan(0));
        assertThat(response.getHeaderString("Retry-After"), notNullValue());
        assertThat(Integer.parseInt(response.getHeaderString("Retry-After")), greaterThan(0));
    }

    @Test
    void phase1_ipLimitReached_doesNotSendOrConsumeUserCooldown() throws Exception {
        ipLimitReached();

        grant.process(OtpGrantTestSupport.dummyContext(session));

        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(singleUseStore, never()).putIfAbsent(startsWith(USER_KEY_PREFIX), anyLong());
    }

    @Test
    void phase1_unknownUser_ipLimitReached_returns429() throws Exception {
        // Unknown usernames must hit the IP limit the same way real ones do, otherwise a
        // blocked IP could tell real accounts (429) from unknown ones (401).
        when(userProvider.getUserByUsername(any(), any())).thenReturn(null);
        ipLimitReached();

        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(429));
        Map<?, ?> body = (Map<?, ?>) response.getEntity();
        assertThat(body.get("error"), equalTo("otp_send_throttled"));
    }

    @Test
    void phase1_unknownUser_consumesIpSlot() throws Exception {
        when(userProvider.getUserByUsername(any(), any())).thenReturn(null);

        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(401));
        verify(singleUseStore).putIfAbsent(startsWith(IP_KEY_PREFIX), anyLong());
    }

    @Test
    void phase1_identifierThrottled_releasesIpSlot() throws Exception {
        // The identifier throttle answers 429 for real and unknown usernames alike and nothing
        // is sent, so the IP slot is given back.
        when(singleUseStore.putIfAbsent(startsWith(IDENTIFIER_KEY_PREFIX), anyLong())).thenReturn(false);

        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(429));
        verify(singleUseStore).remove(IP_KEY_PREFIX + "0");
    }

    @Test
    void phase1_onlyUserCooldownActive_keepsIpSlotLikeFakePath() throws Exception {
        // When only the per-user cooldown blocks, the grant answers with the fake phase-1 401.
        // An unknown username consumes an IP slot for that same response, so the real account
        // must keep its slot too or the remaining IP budget would reveal that it exists.
        when(singleUseStore.putIfAbsent(startsWith(USER_KEY_PREFIX + "realm-1:"), anyLong())).thenReturn(false);

        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(401));
        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(singleUseStore, never()).remove(IP_KEY_PREFIX + "0");
    }

    @Test
    void phase1_sendFailure_releasesIpSlot() throws Exception {
        doThrow(new RuntimeException("smtp down"))
                .when(emailProvider).send(anyString(), anyString(), any());

        assertThrows(CorsErrorResponseException.class,
                () -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        verify(singleUseStore).remove(IP_KEY_PREFIX + "0");
    }

    @Test
    void phase1_ipLimitDisabledViaRealmAttribute_doesNotTrackIp() throws Exception {
        when(realm.getAttribute(OtpSendThrottle.CONFIG_IP_SEND_LIMIT)).thenReturn("0");
        ipLimitReached();

        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(401));
        verify(singleUseStore, never()).putIfAbsent(startsWith("otp-ip:"), anyLong());
        verify(emailProvider).send(anyString(), anyString(), any());
    }
}
