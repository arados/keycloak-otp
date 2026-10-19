package hr.delmisoft.keycloak.otp.grant;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.ClientConnection;
import org.keycloak.credential.hash.PasswordHashProvider;
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
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.BruteForceProtector;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Account-enumeration parity tests for the OTP grant types.
 *
 * <p>Every test drives the same sequence of token-endpoint requests once for a real account
 * ({@code alice}) in some state and once for a username that does not exist ({@code ghost}),
 * and asserts the observable responses (status, OAuth error code, body keys, {@code Retry-After}
 * header) are identical. A real {@link SingleUseObjectProvider}-like in-memory store backs the
 * flow so throttle and session state behave as they would in Keycloak.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OtpGrantEnumerationParityTest {

    private static final String REAL = "alice";
    private static final String REAL_EMAIL = "alice@example.com";
    private static final String UNKNOWN = "ghost";
    private static final String UNKNOWN_EMAIL = "ghost@example.com";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock ClientModel client;
    @Mock UserModel user;
    @Mock UserModel otherUser;
    @Mock UserProvider userProvider;
    @Mock EmailTemplateProvider emailProvider;
    @Mock BruteForceProtector bruteForceProtector;
    @Mock SubjectCredentialManager credentialManager;
    @Mock PasswordHashProvider passwordHashProvider;
    @Mock ClientConnection clientConnection;
    @Mock HttpRequest httpRequest;
    @Mock EventBuilder event;
    @Mock Cors cors;
    @Mock KeycloakContext keycloakContext;

    private InMemorySingleUseStore store;
    private OtpGrantTestSupport.AsyncDeliveryHarness async;

    @BeforeEach
    void setUp() {
        store = new InMemorySingleUseStore();

        when(session.users()).thenReturn(userProvider);
        when(session.getContext()).thenReturn(keycloakContext);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(session.getProvider(EmailTemplateProvider.class)).thenReturn(emailProvider);
        when(session.getProvider(BruteForceProtector.class)).thenReturn(bruteForceProtector);
        when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
        when(emailProvider.setRealm(any())).thenReturn(emailProvider);
        when(emailProvider.setUser(any())).thenReturn(emailProvider);

        when(client.isDirectAccessGrantsEnabled()).thenReturn(true);
        when(client.isConsentRequired()).thenReturn(false);
        when(client.getClientId()).thenReturn("test-client");

        when(realm.getId()).thenReturn("realm-1");
        when(realm.isLoginWithEmailAllowed()).thenReturn(true);
        when(realm.isBruteForceProtected()).thenReturn(true);
        when(realm.getAttribute("otp.sendCooldown")).thenReturn("60");

        when(user.getId()).thenReturn("user-1");
        when(user.getUsername()).thenReturn(REAL);
        when(user.isEnabled()).thenReturn(true);
        when(user.getEmail()).thenReturn(REAL_EMAIL);
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getRequiredActionsStream()).thenAnswer(inv -> Stream.empty());
        when(user.credentialManager()).thenReturn(credentialManager);
        when(credentialManager.isValid(any(UserCredentialModel.class))).thenReturn(true);

        when(otherUser.getId()).thenReturn("user-2");
        when(userProvider.getUserById(eq(realm), eq("user-1"))).thenReturn(user);
        async = OtpGrantTestSupport.AsyncDeliveryHarness.install(session, session, realm, "realm-1");

        // Keycloak's username/email lookups are case-insensitive.
        when(userProvider.getUserByUsername(eq(realm), argThat(s -> REAL.equalsIgnoreCase(s)))).thenReturn(user);
        when(userProvider.getUserByEmail(eq(realm), argThat(s -> REAL_EMAIL.equalsIgnoreCase(s)))).thenReturn(user);

        when(event.detail(anyString(), anyString())).thenReturn(event);
        when(event.user(any(UserModel.class))).thenReturn(event);
    }

    // ---------- Throttle parity ----------

    @Test
    void secondPhase1Request_isThrottledForRealAndUnknownUsersAlike() throws Exception {
        Observed real1 = phase1(REAL, null);
        Observed real2 = phase1(REAL, null);
        Observed unknown1 = phase1(UNKNOWN, null);
        Observed unknown2 = phase1(UNKNOWN, null);

        assertThat(real1.status, equalTo(401));
        assertThat(real2.status, equalTo(429));
        assertThat(real2.error, equalTo("otp_send_throttled"));
        assertThat(real2.retryAfterHeader, equalTo(true));
        assertParity(real1, unknown1);
        assertParity(real2, unknown2);
        verify(emailProvider, times(1)).send(anyString(), anyString(), any());
    }

    @Test
    void throttleKey_isCaseInsensitive_forRealAndUnknownUsersAlike() throws Exception {
        Observed real1 = phase1("ALICE", null);
        Observed real2 = phase1("alice", null);
        Observed unknown1 = phase1("GHOST", null);
        Observed unknown2 = phase1("ghost", null);

        assertThat(real2.status, equalTo(429));
        assertParity(real1, unknown1);
        assertParity(real2, unknown2);
    }

    @Test
    void lookupByEmailAfterUsername_behavesLikeTwoUnrelatedUnknownIdentifiers() throws Exception {
        // Unknown identifiers never share a throttle slot, so a real user looked up via a
        // different identifier must not be throttled either — otherwise a 429 would reveal
        // that the email and username belong to the same account.
        Observed realByUsername = phase1(REAL, null);
        Observed realByEmail = phase1(REAL_EMAIL, null);
        Observed unknownByUsername = phase1(UNKNOWN, null);
        Observed unknownByEmail = phase1(UNKNOWN_EMAIL, null);

        assertParity(realByUsername, unknownByUsername);
        assertParity(realByEmail, unknownByEmail);
        assertThat(realByEmail.status, equalTo(401));
        // The per-user send cooldown still applies: only one OTP actually goes out.
        verify(emailProvider, times(1)).send(anyString(), anyString(), any());
    }

    @Test
    void disabledUser_isThrottledLikeUnknownUser() throws Exception {
        when(user.isEnabled()).thenReturn(false);

        assertParity(phase1(REAL, null), phase1(UNKNOWN, null));
        Observed real2 = phase1(REAL, null);
        assertThat(real2.status, equalTo(429));
        assertParity(real2, phase1(UNKNOWN, null));
    }

    @Test
    void unverifiedUser_isThrottledLikeUnknownUser() throws Exception {
        when(user.isEmailVerified()).thenReturn(false);

        assertParity(phase1(REAL, null), phase1(UNKNOWN, null));
        Observed real2 = phase1(REAL, null);
        assertThat(real2.status, equalTo(429));
        assertParity(real2, phase1(UNKNOWN, null));
    }

    // ---------- Wrong password parity ----------

    @Test
    void wrongPassword_phase1_isIndistinguishableFromUnknownUser() throws Exception {
        when(credentialManager.isValid(any(UserCredentialModel.class))).thenReturn(false);

        Observed real = phase1(REAL, "wrong");
        Observed unknown = phase1(UNKNOWN, "wrong");

        assertThat(real.status, equalTo(401));
        assertThat(real.error, equalTo("email_otp_required"));
        assertParity(real, unknown);
        // No OTP goes out, but the real account's brute-force counter is still bumped.
        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(bruteForceProtector).failedLogin(eq(realm), eq(user), eq(clientConnection), any(),
                eq(Set.of("test-client")));
    }

    @Test
    void wrongPassword_phase1_consumesThrottleSlotLikeUnknownUser() throws Exception {
        when(credentialManager.isValid(any(UserCredentialModel.class))).thenReturn(false);

        phase1(REAL, "wrong");
        phase1(UNKNOWN, "wrong");
        Observed real2 = phase1(REAL, "wrong");
        Observed unknown2 = phase1(UNKNOWN, "wrong");

        assertThat(real2.status, equalTo(429));
        assertParity(real2, unknown2);
    }

    @Test
    void wrongPassword_phase2_withPhase1SessionId_failsLikeUnknownUser() throws Exception {
        when(credentialManager.isValid(any(UserCredentialModel.class))).thenReturn(false);

        Observed real1 = phase1(REAL, "wrong");
        Observed unknown1 = phase1(UNKNOWN, "wrong");

        Observed real2 = phase2(REAL, "wrong", "123456", real1.otpSessionId);
        Observed unknown2 = phase2(UNKNOWN, "wrong", "123456", unknown1.otpSessionId);

        assertThat(real2.status, equalTo(401));
        assertThat(real2.error, equalTo("emailOtpSessionExpired"));
        assertParity(real2, unknown2);
    }

    @Test
    void wrongPassword_phase2_againstRealSession_failsLikeUnknownUser() throws Exception {
        // Phase 1 with the correct password creates a real session; phase 2 with a wrong
        // password must not answer with a distinct "invalid credentials" error.
        Observed real1 = phase1(REAL, "right");
        when(credentialManager.isValid(any(UserCredentialModel.class))).thenReturn(false);
        Observed unknown1 = phase1(UNKNOWN, "wrong");

        Observed real2 = phase2(REAL, "wrong", "123456", real1.otpSessionId);
        Observed unknown2 = phase2(UNKNOWN, "wrong", "123456", unknown1.otpSessionId);

        assertParity(real2, unknown2);
        verify(bruteForceProtector, atLeastOnce()).failedLogin(eq(realm), eq(user), any(), any(), any());
    }

    @Test
    void unknownUser_withPassword_stillPerformsPasswordHashWork() throws Exception {
        // Timing: a real user with a password costs a password-hash verification, so the
        // unknown-user path must do comparable work instead of returning immediately.
        phase1(UNKNOWN, "some-password");

        verify(passwordHashProvider).encodedCredential(eq("some-password"), anyInt());
    }

    // ---------- Brute-force lockout parity ----------

    @Test
    void bruteForceLockedUser_isIndistinguishableFromUnknownUser() throws Exception {
        when(bruteForceProtector.isTemporarilyDisabled(session, realm, user)).thenReturn(true);

        Observed real1 = phase1(REAL, null);
        Observed unknown1 = phase1(UNKNOWN, null);
        assertParity(real1, unknown1);

        Observed real2 = phase1(REAL, null);
        Observed unknown2 = phase1(UNKNOWN, null);
        assertThat(real2.status, equalTo(429));
        assertParity(real2, unknown2);

        assertParity(phase2(REAL, null, "123456", real1.otpSessionId),
                phase2(UNKNOWN, null, "123456", unknown1.otpSessionId));
        verify(emailProvider, never()).send(anyString(), anyString(), any());
    }

    @Test
    void bruteForceLockedUser_withPassword_isIndistinguishableFromUnknownUser() throws Exception {
        when(bruteForceProtector.isTemporarilyDisabled(session, realm, user)).thenReturn(true);

        assertParity(phase1(REAL, "pw"), phase1(UNKNOWN, "pw"));
    }

    // ---------- Required actions parity ----------

    @Test
    void userWithRequiredActions_isIndistinguishableFromUnknownUser() throws Exception {
        when(user.getRequiredActionsStream()).thenAnswer(inv -> Stream.of("UPDATE_PASSWORD"));

        Observed real1 = phase1(REAL, null);
        Observed unknown1 = phase1(UNKNOWN, null);
        assertParity(real1, unknown1);

        Observed real2 = phase1(REAL, null);
        Observed unknown2 = phase1(UNKNOWN, null);
        assertThat(real2.status, equalTo(429));
        assertParity(real2, unknown2);

        assertParity(phase2(REAL, null, "123456", real1.otpSessionId),
                phase2(UNKNOWN, null, "123456", unknown1.otpSessionId));
    }

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void userWithRequiredActions_isRefusedTokensAtPhase2WithGenericFailure() throws Exception {
        // A required action added after a real OTP was sent must still block token issuance,
        // but with the same generic response a fake/expired session gets.
        Observed real1 = phase1(REAL, null);
        ArgumentCaptor<Map> attrs = ArgumentCaptor.forClass(Map.class);
        verify(emailProvider).send(anyString(), anyString(), attrs.capture());
        String code = (String) attrs.getValue().get("code");

        when(user.getRequiredActionsStream()).thenAnswer(inv -> Stream.of("UPDATE_PASSWORD"));
        Observed unknown1 = phase1(UNKNOWN, null);

        Observed real2 = phase2(REAL, null, code, real1.otpSessionId);
        Observed unknown2 = phase2(UNKNOWN, null, code, unknown1.otpSessionId);

        assertThat(real2.status, equalTo(401));
        assertParity(real2, unknown2);
    }

    // ---------- Phase 2 parity ----------

    @Test
    void phase2_missingSessionId_isIndistinguishable() throws Exception {
        assertParity(phase2(REAL, null, "123456", null), phase2(UNKNOWN, null, "123456", null));
    }

    @Test
    void phase2_sessionBoundToAnotherUser_isIndistinguishableAndConsumesSessionAlike() throws Exception {
        // An attacker holding a session for their own account must not be able to probe other
        // usernames with it: the response AND the effect on the session must match.
        String sessA = seedSession("user-2");
        String sessB = seedSession("user-2");

        Observed real = phase2(REAL, null, "123456", sessA);
        Observed unknown = phase2(UNKNOWN, null, "123456", sessB);

        assertParity(real, unknown);
        assertThat(store.contains(sessA), equalTo(store.contains(sessB)));
    }

    // ---------- Helpers ----------

    private String seedSession(String userId) {
        String id = java.util.UUID.randomUUID().toString();
        Map<String, String> notes = new HashMap<>();
        notes.put("userId", userId);
        notes.put("clientId", "test-client");
        notes.put("codeExpiresAt", String.valueOf(org.keycloak.common.util.Time.currentTime() + 300));
        String salt = hr.delmisoft.keycloak.otp.OtpHash.newSalt();
        notes.put("codeSalt", salt);
        notes.put("codeHash", hr.delmisoft.keycloak.otp.OtpHash.hash("654321", salt));
        store.put(id, 300, notes);
        return id;
    }

    private Observed phase1(String username, String password) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("username", username);
        if (password != null) {
            params.put("password", password);
        }
        return run(params);
    }

    private Observed phase2(String username, String password, String otp, String otpSessionId) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("username", username);
        if (password != null) {
            params.put("password", password);
        }
        params.put("otp", otp);
        if (otpSessionId != null) {
            params.put("otp_session_id", otpSessionId);
        }
        return run(params);
    }

    private Observed run(Map<String, String> params) {
        AbstractOtpGrantTypeTest.TestableEmailOtpGrantType grant = new AbstractOtpGrantTypeTest.TestableEmailOtpGrantType();
        OtpGrantTestSupport.injectMocks(grant, session, realm, client, clientConnection,
                OtpGrantTestSupport.formParams(params), event, cors, httpRequest);
        try {
            Response response = grant.process(OtpGrantTestSupport.dummyContext(session));
            return Observed.of(response);
        } catch (CorsErrorResponseException e) {
            return Observed.of(e);
        } finally {
            // End of the HTTP request: after-completion hooks run and the asynchronous OTP
            // delivery (if any) is let through, so tests can inspect what was sent.
            async.completeRequest();
        }
    }

    private static void assertParity(Observed real, Observed unknown) {
        assertThat("status", real.status, equalTo(unknown.status));
        assertThat("error", real.error, equalTo(unknown.error));
        assertThat("body keys", real.bodyKeys, equalTo(unknown.bodyKeys));
        assertThat("Retry-After header", real.retryAfterHeader, equalTo(unknown.retryAfterHeader));
        if (real.status != 429) {
            // 429 descriptions embed the remaining seconds, which can tick between calls.
            assertThat("error_description", real.errorDescription, equalTo(unknown.errorDescription));
        }
    }

    /** What an external observer of the token endpoint can see. */
    private static final class Observed {
        int status;
        String error;
        String errorDescription;
        Set<String> bodyKeys;
        boolean retryAfterHeader;
        String otpSessionId;

        static Observed of(Response response) {
            Observed o = new Observed();
            o.status = response.getStatus();
            Map<?, ?> body = (Map<?, ?>) response.getEntity();
            o.bodyKeys = new TreeSet<>();
            body.keySet().forEach(k -> o.bodyKeys.add((String) k));
            o.error = (String) body.get("error");
            o.errorDescription = (String) body.get("error_description");
            o.otpSessionId = (String) body.get("otp_session_id");
            o.retryAfterHeader = response.getHeaderString("Retry-After") != null;
            return o;
        }

        static Observed of(CorsErrorResponseException e) {
            Observed o = new Observed();
            o.status = ((Response.Status) readField(e, "status")).getStatusCode();
            o.error = (String) readField(e, "error");
            o.errorDescription = e.getErrorDescription();
            o.bodyKeys = new TreeSet<>(Set.of("error", "error_description"));
            o.retryAfterHeader = false;
            return o;
        }

        private static Object readField(Object target, String name) {
            try {
                Field f = CorsErrorResponseException.class.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(target);
            } catch (ReflectiveOperationException ex) {
                throw new RuntimeException(ex);
            }
        }

        @Override
        public String toString() {
            return status + " " + error + " " + bodyKeys + " retryAfter=" + retryAfterHeader
                    + " desc=" + errorDescription;
        }
    }

    /** Minimal in-memory {@link SingleUseObjectProvider} (TTL is ignored — tests run instantly). */
    static final class InMemorySingleUseStore implements SingleUseObjectProvider {
        private final Map<String, Map<String, String>> data = new HashMap<>();

        @Override
        public void put(String key, long lifespanSeconds, Map<String, String> notes) {
            data.put(key, new HashMap<>(notes));
        }

        @Override
        public Map<String, String> get(String key) {
            Map<String, String> v = data.get(key);
            return v == null ? null : new HashMap<>(v);
        }

        @Override
        public Map<String, String> remove(String key) {
            return data.remove(key);
        }

        @Override
        public boolean replace(String key, Map<String, String> notes) {
            if (!data.containsKey(key)) {
                return false;
            }
            data.put(key, new HashMap<>(notes));
            return true;
        }

        @Override
        public boolean putIfAbsent(String key, long lifespanInSeconds) {
            if (data.containsKey(key)) {
                return false;
            }
            data.put(key, new HashMap<>());
            return true;
        }

        @Override
        public boolean contains(String key) {
            return data.containsKey(key);
        }

        @Override
        public void close() {
        }
    }
}
