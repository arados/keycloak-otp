package hr.delmisoft.keycloak.otp.grant;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.BruteForceProtector;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import hr.delmisoft.keycloak.otp.OtpHash;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Exercises the protected/private flow logic in {@link AbstractOtpGrantType} via a concrete
 * subclass ({@link EmailOtpGrantType}). The token-issuance branch of phase 2 is intentionally
 * not covered here — it threads through {@code AuthenticationSessionManager} and the rest of
 * the Keycloak auth machinery, which the e2e suite covers end-to-end.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AbstractOtpGrantTypeTest {

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock ClientModel client;
    @Mock UserModel user;
    @Mock UserProvider userProvider;
    @Mock SingleUseObjectProvider singleUseStore;
    @Mock EmailTemplateProvider emailProvider;
    @Mock BruteForceProtector bruteForceProtector;
    @Mock SubjectCredentialManager credentialManager;
    @Mock ClientConnection clientConnection;
    @Mock HttpRequest httpRequest;
    @Mock EventBuilder event;
    @Mock Cors cors;
    @Mock KeycloakContext keycloakContext;

    private TestableEmailOtpGrantType grant;

    @BeforeEach
    void setUp() {
        grant = new TestableEmailOtpGrantType();

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
        when(user.credentialManager()).thenReturn(credentialManager);

        when(userProvider.getUserByUsername(any(), any())).thenReturn(user);
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(true);

        // EventBuilder chains. event.error(String) is void in 26.6.1 so it's not stubbed —
        // lenient strictness lets the void call pass through silently.
        when(event.detail(anyString(), anyString())).thenReturn(event);
        when(event.user(any(UserModel.class))).thenReturn(event);
    }

    private void inject(MultivaluedMap<String, String> formParams) {
        OtpGrantTestSupport.injectMocks(grant, session, realm, client, clientConnection,
                formParams, event, cors, httpRequest);
    }

    // ---------- Phase 1: client-level checks ----------

    @Test
    void phase1_clientWithoutDirectGrants_isRejected() throws Exception {
        when(client.isDirectAccessGrantsEnabled()).thenReturn(false);
        inject(OtpGrantTestSupport.formParams(Map.of("username", "alice")));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo(OAuthErrorException.UNAUTHORIZED_CLIENT));
        verify(event).error("not_allowed");
    }

    @Test
    void phase1_clientRequiringConsent_isRejected() throws Exception {
        when(client.isConsentRequired()).thenReturn(true);
        inject(OtpGrantTestSupport.formParams(Map.of("username", "alice")));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo(OAuthErrorException.INVALID_CLIENT));
    }

    @Test
    void phase1_missingUsername_isRejected() throws Exception {
        inject(OtpGrantTestSupport.formParams(Map.of()));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo(OAuthErrorException.INVALID_REQUEST));
        assertThat(ex.getErrorDescription(), containsString("username"));
    }

    // ---------- Phase 1: account-enumeration resistance ----------

    @Test
    void phase1_unknownUser_returnsIndistinguishableResponse() throws Exception {
        // No actual OTP delivery, no throttle reservation — but the response shape mirrors success.
        when(userProvider.getUserByUsername(any(), eq("ghost"))).thenReturn(null);
        inject(OtpGrantTestSupport.formParams(Map.of("username", "ghost")));

        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(401));
        Map<?, ?> body = (Map<?, ?>) response.getEntity();
        assertThat(body.get("otp_session_id"), notNullValue());
        verify(singleUseStore, never()).putIfAbsent(anyString(), anyLong());
        verify(emailProvider, never()).send(anyString(), anyString(), any());
    }

    @Test
    void phase1_disabledUser_returnsIndistinguishableResponse() throws Exception {
        when(user.isEnabled()).thenReturn(false);
        inject(OtpGrantTestSupport.formParams(Map.of("username", "alice")));

        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(401));
        Map<?, ?> body = (Map<?, ?>) response.getEntity();
        assertThat(body.get("otp_session_id"), notNullValue());
        verify(emailProvider, never()).send(anyString(), anyString(), any());
    }

    @Test
    void phase1_unverifiedEmail_returnsIndistinguishableResponse() throws Exception {
        // emailOtp.requireVerifiedEmail defaults to true; an unverified user must not be told
        // their account exists.
        when(user.isEmailVerified()).thenReturn(false);
        inject(OtpGrantTestSupport.formParams(Map.of("username", "alice")));

        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(401));
        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(singleUseStore, never()).putIfAbsent(anyString(), anyLong());
    }

    @Test
    void phase2_fakeOtpSessionId_returnsIndistinguishableExpiredResponse() throws Exception {
        // The fake session id from a phase-1 enumeration probe never resolves in phase 2;
        // the response must match the real "OTP session has expired" branch.
        when(user.isEnabled()).thenReturn(false);
        inject(OtpGrantTestSupport.formParams(Map.of(
                "username", "alice",
                "otp", "123456",
                "otp_session_id", "fake-id")));

        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(401));
        Map<?, ?> body = (Map<?, ?>) response.getEntity();
        assertThat((String) body.get("error_description"), containsString("expired"));
    }

    // ---------- Phase 1: brute-force interaction ----------

    @Test
    void phase1_bruteForceLockedUser_isRejectedWithGenericError() throws Exception {
        // A locked-out user must not learn whether their lockout is what blocked them —
        // the response is the same generic "Invalid user credentials" the wrong-OTP path returns.
        when(realm.isBruteForceProtected()).thenReturn(true);
        when(bruteForceProtector.isTemporarilyDisabled(session, realm, user)).thenReturn(true);
        inject(OtpGrantTestSupport.formParams(Map.of("username", "alice")));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo(OAuthErrorException.INVALID_GRANT));
        verify(emailProvider, never()).send(anyString(), anyString(), any());
    }

    // ---------- Phase 1: required actions ----------

    @Test
    void phase1_userWithRequiredActions_isRejected() throws Exception {
        when(user.getRequiredActionsStream()).thenReturn(Stream.of("UPDATE_PASSWORD"));
        inject(OtpGrantTestSupport.formParams(Map.of("username", "alice")));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo(OAuthErrorException.INVALID_GRANT));
        assertThat(ex.getErrorDescription(), containsString("not fully set up"));
        verify(emailProvider, never()).send(anyString(), anyString(), any());
    }

    // ---------- Phase 1: password validation when supplied ----------

    @Test
    void phase1_wrongPasswordWhenSupplied_isRejectedAndRecordsBruteForceFailure() throws Exception {
        when(realm.isBruteForceProtected()).thenReturn(true);
        when(credentialManager.isValid(any(UserCredentialModel.class))).thenReturn(false);
        inject(OtpGrantTestSupport.formParams(Map.of(
                "username", "alice",
                "password", "wrong")));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo(OAuthErrorException.INVALID_GRANT));
        verify(bruteForceProtector).failedLogin(eq(realm), eq(user), eq(clientConnection), any(), eq("test-client"));
        verify(emailProvider, never()).send(anyString(), anyString(), any());
    }

    // ---------- Phase 1: send success ----------

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void phase1_success_sendsOtpAndReturns401WithSessionId() throws Exception {
        ArgumentCaptor<Map> notesCaptor = ArgumentCaptor.forClass(Map.class);
        inject(OtpGrantTestSupport.formParams(Map.of("username", "alice")));

        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(401));
        Map<?, ?> body = (Map<?, ?>) response.getEntity();
        String sessionId = (String) body.get("otp_session_id");
        assertThat(sessionId, notNullValue());
        verify(emailProvider).send(anyString(), anyString(), any());
        verify(singleUseStore).put(eq(sessionId), anyLong(), notesCaptor.capture());

        Map<String, String> notes = (Map<String, String>) notesCaptor.getValue();
        assertThat(notes.get("userId"), equalTo("user-1"));
        assertThat(notes.get("clientId"), equalTo("test-client"));
        assertThat(notes.get("attempts"), equalTo("0"));
        assertThat(notes.get("codeHash"), notNullValue());
        assertThat(notes.get("codeSalt"), notNullValue());
    }

    // ---------- Phase 1: throttle ----------

    @Test
    void phase1_secondSendWithinCooldown_returns429() throws Exception {
        // First send reserves; the throttle is keyed by (realm, user, channel) so a second
        // phase-1 from the same client (or anyone) for the same user gets 429.
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(false);
        // remainingSeconds reads the throttle's meta map; populate it with a future expiresAt.
        Map<String, String> meta = new HashMap<>();
        meta.put("expiresAt", String.valueOf(Time.currentTime() + 30));
        when(singleUseStore.get(anyString())).thenReturn(meta);
        inject(OtpGrantTestSupport.formParams(Map.of("username", "alice")));

        Response response = grant.process(OtpGrantTestSupport.dummyContext(session));

        assertThat(response.getStatus(), equalTo(429));
        Map<?, ?> body = (Map<?, ?>) response.getEntity();
        assertThat(body.get("error"), equalTo("otp_send_throttled"));
        assertThat((Integer) body.get("retry_after"), greaterThan(0));
        assertThat(response.getHeaderString("Retry-After"), notNullValue());
    }

    // ---------- Phase 1: send failure rollback ----------

    @Test
    void phase1_sendFailure_rollsBackSessionAndThrottle() throws Exception {
        doThrow(new RuntimeException("smtp down"))
                .when(emailProvider).send(anyString(), anyString(), any());
        inject(OtpGrantTestSupport.formParams(Map.of("username", "alice")));

        assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        // Both the session id store entry AND the throttle reservation must be removed so a
        // transient delivery error doesn't lock the user out of retries. release() removes
        // two keys (the bare key + the ":meta" sibling), and the otp_session_id is also
        // removed — three total remove() calls.
        verify(singleUseStore, atLeast(2)).remove(anyString());
    }

    // ---------- Phase 2: session-id validation ----------

    @Test
    void phase2_missingOtpSessionId_returns401() throws Exception {
        inject(OtpGrantTestSupport.formParams(Map.of(
                "username", "alice",
                "otp", "123456")));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo(OAuthErrorException.INVALID_GRANT));
        assertThat(ex.getErrorDescription(), containsString("otp_session_id"));
    }

    @Test
    void phase2_expiredSession_returns401() throws Exception {
        when(singleUseStore.get("session-x")).thenReturn(null);
        inject(OtpGrantTestSupport.formParams(Map.of(
                "username", "alice",
                "otp", "123456",
                "otp_session_id", "session-x")));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo("emailOtpSessionExpired"));
    }

    // ---------- Phase 2: user binding ----------

    @Test
    void phase2_otpSessionBoundToDifferentUser_isRejected() throws Exception {
        Map<String, String> notes = stubStoredSession("other-user-id", "test-client", "0", "123456");
        when(singleUseStore.get("sess")).thenReturn(notes);

        inject(OtpGrantTestSupport.formParams(Map.of(
                "username", "alice",
                "otp", "123456",
                "otp_session_id", "sess")));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo(OAuthErrorException.INVALID_GRANT));
        verify(singleUseStore).remove("sess");
    }

    // ---------- Phase 2: client binding ----------

    @Test
    void phase2_otpSessionBoundToDifferentClient_isRejected() throws Exception {
        // SECURITY: prevents a malicious client from redeeming an OTP session that was
        // initiated against a different client.
        Map<String, String> notes = stubStoredSession("user-1", "other-client", "0", "123456");
        when(singleUseStore.get("sess")).thenReturn(notes);

        inject(OtpGrantTestSupport.formParams(Map.of(
                "username", "alice",
                "otp", "123456",
                "otp_session_id", "sess")));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo(OAuthErrorException.INVALID_GRANT));
        verify(singleUseStore).remove("sess");
    }

    // ---------- Phase 2: brute-force counter ----------

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void phase2_invalidOtp_incrementsAttemptsAndRecordsBruteForce() throws Exception {
        when(realm.isBruteForceProtected()).thenReturn(true);
        Map<String, String> notes = stubStoredSession("user-1", "test-client", "0", "123456");
        when(singleUseStore.get("sess")).thenReturn(notes);

        inject(OtpGrantTestSupport.formParams(Map.of(
                "username", "alice",
                "otp", "999999",
                "otp_session_id", "sess")));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo("emailOtpInvalid"));
        verify(bruteForceProtector).failedLogin(eq(realm), eq(user), any(), any(), eq("test-client"));
        // attempts counter bumped from 0 to 1
        ArgumentCaptor<Map> capt = ArgumentCaptor.forClass(Map.class);
        verify(singleUseStore).replace(eq("sess"), capt.capture());
        Map<String, String> updated = (Map<String, String>) capt.getValue();
        assertThat(updated.get("attempts"), equalTo("1"));
    }

    @Test
    void phase2_maxRetriesExceeded_isRejected() throws Exception {
        Map<String, String> notes = stubStoredSession("user-1", "test-client", "3", "123456");
        when(singleUseStore.get("sess")).thenReturn(notes);

        inject(OtpGrantTestSupport.formParams(Map.of(
                "username", "alice",
                "otp", "123456",
                "otp_session_id", "sess")));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo("emailOtpMaxRetries"));
        verify(singleUseStore).remove("sess");
    }

    @Test
    void phase2_malformedAttemptsCounter_failsClosed() throws Exception {
        // A corrupt counter must not let an attacker pass an unbounded-retries check by
        // tampering with the stored session.
        Map<String, String> notes = stubStoredSession("user-1", "test-client", "not-a-number", "123456");
        when(singleUseStore.get("sess")).thenReturn(notes);

        inject(OtpGrantTestSupport.formParams(Map.of(
                "username", "alice",
                "otp", "123456",
                "otp_session_id", "sess")));

        CorsErrorResponseException ex = assertThrowsCors(() -> grant.process(OtpGrantTestSupport.dummyContext(session)));

        assertThat(errorOf(ex), equalTo("emailOtpSessionExpired"));
        verify(singleUseStore).remove("sess");
    }

    // ---------- Helpers ----------

    private Map<String, String> stubStoredSession(String userId, String clientId, String attempts, String code) {
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash(code, salt);
        Map<String, String> notes = new HashMap<>();
        notes.put("userId", userId);
        notes.put("clientId", clientId);
        notes.put("attempts", attempts);
        notes.put("codeHash", hash);
        notes.put("codeSalt", salt);
        return notes;
    }

    @FunctionalInterface
    private interface ThrowingRun {
        void run();
    }

    private static CorsErrorResponseException assertThrowsCors(ThrowingRun r) {
        try {
            r.run();
        } catch (CorsErrorResponseException e) {
            return e;
        }
        throw new AssertionError("Expected CorsErrorResponseException");
    }

    /**
     * {@link CorsErrorResponseException} stashes the OAuth error code in a package-private
     * field with no accessor. Reflect once instead of repeating it in each test.
     */
    private static String errorOf(CorsErrorResponseException ex) {
        try {
            java.lang.reflect.Field f = CorsErrorResponseException.class.getDeclaredField("error");
            f.setAccessible(true);
            return (String) f.get(ex);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Test subclass with two adjustments:
     * <ul>
     *   <li>{@code setContext} is a no-op so injected mocks aren't overwritten.</li>
     *   <li>{@code getRequestedScopes} is short-circuited so we don't have to bootstrap
     *       Keycloak's static {@link org.keycloak.common.Profile} singleton in a unit test
     *       (the parent's implementation calls {@code Profile.isFeatureEnabled(...)} which
     *       NPEs when {@code Profile.getInstance()} is null).</li>
     * </ul>
     */
    static class TestableEmailOtpGrantType extends EmailOtpGrantType {
        @Override
        protected void setContext(OAuth2GrantType.Context context) {
            // no-op — fields are pre-injected via reflection
        }

        @Override
        protected String getRequestedScopes() {
            return "openid";
        }
    }
}
