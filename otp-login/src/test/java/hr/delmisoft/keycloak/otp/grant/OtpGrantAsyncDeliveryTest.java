package hr.delmisoft.keycloak.otp.grant;

import java.util.Map;
import java.util.stream.Stream;

import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.ClientConnection;
import org.keycloak.email.EmailException;
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
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.BruteForceProtector;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import hr.delmisoft.keycloak.otp.OtpSendThrottle;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Phase 1 of the OTP grant types must not deliver the OTP on the request thread: response time
 * would otherwise reveal whether a send happened (i.e. whether the account exists). Delivery runs
 * on Keycloak's executor, in a fresh session, only after the request transaction completed.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OtpGrantAsyncDeliveryTest {

    private static final String IP = "203.0.113.7";

    @Mock KeycloakSession session;
    @Mock KeycloakSession backgroundSession;
    @Mock RealmModel realm;
    @Mock ClientModel client;
    @Mock UserModel user;
    @Mock UserProvider userProvider;
    @Mock UserProvider backgroundUsers;
    @Mock EmailTemplateProvider requestEmailProvider;
    @Mock EmailTemplateProvider backgroundEmailProvider;
    @Mock BruteForceProtector bruteForceProtector;
    @Mock ClientConnection clientConnection;
    @Mock HttpRequest httpRequest;
    @Mock EventBuilder event;
    @Mock Cors cors;
    @Mock KeycloakContext keycloakContext;

    private OtpGrantTestSupport.ConcurrentInMemoryStore store;
    private OtpGrantTestSupport.AsyncDeliveryHarness async;

    @BeforeEach
    void setUp() {
        store = new OtpGrantTestSupport.ConcurrentInMemoryStore();

        when(session.users()).thenReturn(userProvider);
        when(session.getContext()).thenReturn(keycloakContext);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(session.getProvider(EmailTemplateProvider.class)).thenReturn(requestEmailProvider);
        when(session.getProvider(BruteForceProtector.class)).thenReturn(bruteForceProtector);
        when(requestEmailProvider.setRealm(any())).thenReturn(requestEmailProvider);
        when(requestEmailProvider.setUser(any())).thenReturn(requestEmailProvider);

        when(backgroundSession.users()).thenReturn(backgroundUsers);
        when(backgroundSession.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(backgroundSession.getProvider(EmailTemplateProvider.class)).thenReturn(backgroundEmailProvider);
        when(backgroundEmailProvider.setRealm(any())).thenReturn(backgroundEmailProvider);
        when(backgroundEmailProvider.setUser(any())).thenReturn(backgroundEmailProvider);
        when(backgroundUsers.getUserById(any(), eq("user-1"))).thenReturn(user);

        when(client.isDirectAccessGrantsEnabled()).thenReturn(true);
        when(client.isConsentRequired()).thenReturn(false);
        when(client.getClientId()).thenReturn("test-client");

        when(realm.getId()).thenReturn("realm-1");
        when(realm.isLoginWithEmailAllowed()).thenReturn(false);
        when(realm.isBruteForceProtected()).thenReturn(false);
        when(realm.getAttribute("otp.sendCooldown")).thenReturn("60");

        when(user.getId()).thenReturn("user-1");
        when(user.isEnabled()).thenReturn(true);
        when(user.getEmail()).thenReturn("alice@example.com");
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getRequiredActionsStream()).thenAnswer(inv -> Stream.empty());

        when(userProvider.getUserByUsername(any(), eq("alice"))).thenReturn(user);
        when(clientConnection.getRemoteAddr()).thenReturn(IP);

        when(event.detail(anyString(), anyString())).thenReturn(event);
        when(event.user(any(UserModel.class))).thenReturn(event);

        async = OtpGrantTestSupport.AsyncDeliveryHarness.install(session, backgroundSession, realm, "realm-1");
    }

    @Test
    void phase1_returnsBeforeDelivery_andSendsOnlyWhenTheScheduledJobRuns() throws Exception {
        Response response = phase1("alice");

        assertThat(response.getStatus(), equalTo(401));
        assertThat(((Map<?, ?>) response.getEntity()).get("otp_session_id"), notNullValue());
        // Nothing was sent while handling the request...
        verify(requestEmailProvider, never()).send(anyString(), anyString(), any());
        verify(backgroundEmailProvider, never()).send(anyString(), anyString(), any());
        // ...and nothing is even scheduled until the request transaction has completed, so the
        // OTP session entry is visible before the code can arrive.
        assertThat(async.executor.pending(), equalTo(0));

        async.commitRequest();
        verify(backgroundEmailProvider, never()).send(anyString(), anyString(), any());
        assertThat(async.executor.pending(), equalTo(1));

        async.runDeliveries();
        verify(backgroundEmailProvider, times(1)).send(anyString(), anyString(), any());
        verify(requestEmailProvider, never()).send(anyString(), anyString(), any());
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void deliveryJob_usesFreshSession_andReResolvesRealmAndUserById() throws Exception {
        Response response = phase1("alice");
        async.completeRequest();

        verify(async.factory).create();
        verify(async.backgroundRealms).getRealm("realm-1");
        verify(backgroundUsers).getUserById(realm, "user-1");
        verify(backgroundEmailProvider).setRealm(realm);
        ArgumentCaptor<Map> attrs = ArgumentCaptor.forClass(Map.class);
        verify(backgroundEmailProvider).send(eq("emailOtpSubject"), eq("email-otp-code.ftl"), attrs.capture());
        String code = (String) attrs.getValue().get("code");
        assertThat(code.matches("\\d{6}"), is(true));
        // The delivered code is the one the OTP session was created for.
        String sessionId = (String) ((Map<?, ?>) response.getEntity()).get("otp_session_id");
        Map<String, String> notes = store.get(sessionId);
        assertThat(hr.delmisoft.keycloak.otp.OtpHash.verify(code, notes.get("codeHash"), notes.get("codeSalt")), is(true));
    }

    @Test
    void asyncDeliveryFailure_isNotReportedToTheClient_andRollsBackSessionAndSlots() throws Exception {
        doThrow(new EmailException("smtp down"))
                .when(backgroundEmailProvider).send(anyString(), anyString(), any());

        Response response = phase1("alice");

        // No synchronous 500 "otp_send_failed" any more — that was an oracle as well.
        assertThat(response.getStatus(), equalTo(401));
        String sessionId = (String) ((Map<?, ?>) response.getEntity()).get("otp_session_id");
        assertThat(store.contains(sessionId), is(true));

        async.completeRequest();

        assertThat("OTP session removed", store.contains(sessionId), is(false));
        assertThat("per-user cooldown released",
                store.contains("otp-throttle:realm-1:user-1:email"), is(false));
        assertThat("per-user stash released",
                OtpSendThrottle.getRecentCode(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL), is((Object) null));
        assertThat("identifier slot released",
                OtpSendThrottle.remainingSecondsForIdentifier(session, realm, "alice", OtpSendThrottle.CHANNEL_EMAIL),
                equalTo(0));
        assertThat("IP slot released", store.contains("otp-ip:realm-1:" + IP + ":0"), is(false));

        // The user can immediately ask again and the retry is delivered.
        org.mockito.Mockito.reset(backgroundEmailProvider);
        when(backgroundEmailProvider.setRealm(any())).thenReturn(backgroundEmailProvider);
        when(backgroundEmailProvider.setUser(any())).thenReturn(backgroundEmailProvider);
        Response retry = phase1("alice");
        async.completeRequest();
        assertThat(retry.getStatus(), equalTo(401));
        verify(backgroundEmailProvider).send(anyString(), anyString(), any());
    }

    @Test
    void requestRollback_sendsNothing_andRollsBackSessionAndSlots() throws Exception {
        Response response = phase1("alice");
        String sessionId = (String) ((Map<?, ?>) response.getEntity()).get("otp_session_id");

        async.rollbackRequest();
        async.runDeliveries();

        verify(backgroundEmailProvider, never()).send(anyString(), anyString(), any());
        verify(requestEmailProvider, never()).send(anyString(), anyString(), any());
        assertThat(store.contains(sessionId), is(false));
        assertThat(store.contains("otp-throttle:realm-1:user-1:email"), is(false));
        assertThat(store.contains("otp-ip:realm-1:" + IP + ":0"), is(false));
    }

    @Test
    void unknownUser_schedulesNothing_butPerformsTheSameNumberOfStoreWrites() {
        // IP slots are scanned in order, so later requests from one IP cost an extra probe;
        // switch the IP limit off to compare just the account-dependent work.
        when(realm.getAttribute(OtpSendThrottle.CONFIG_IP_SEND_LIMIT)).thenReturn("0");
        int before = store.writes();
        phase1("alice");
        int realWrites = store.writes() - before;
        async.completeRequest();

        before = store.writes();
        phase1("ghost");
        int fakeWrites = store.writes() - before;

        assertThat(async.afterCompletion.size(), equalTo(0));
        async.completeRequest();
        assertThat(async.executor.pending(), equalTo(0));
        assertThat("store writes on the fake path match the real path", fakeWrites, equalTo(realWrites));
    }

    private Response phase1(String username) {
        AbstractOtpGrantTypeTest.TestableEmailOtpGrantType grant = new AbstractOtpGrantTypeTest.TestableEmailOtpGrantType();
        OtpGrantTestSupport.injectMocks(grant, session, realm, client, clientConnection,
                OtpGrantTestSupport.formParams(Map.of("username", username)), event, cors, httpRequest);
        return grant.process(OtpGrantTestSupport.dummyContext(session));
    }
}
