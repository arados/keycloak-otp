package hr.delmisoft.keycloak.otp.grant;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
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
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import hr.delmisoft.keycloak.otp.OtpSendThrottle;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.oneOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The grant types' per-code attempt limit must hold under concurrency and must be shared with
 * the browser flow.
 *
 * <p>Concurrency is reproduced deterministically with {@link OtpGrantTestSupport.ConcurrentInMemoryStore}:
 * either {@code freeze}-ing the OTP session entry (every later reader sees the snapshot taken
 * before any concurrent write — the worst-case interleaving of a get/compare/replace counter) or
 * gating real threads so that all of them have read the entry before any of them proceeds.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OtpGrantAttemptRaceTest {

    private static final int MAX_RETRIES = AbstractOtpGrantType.DEFAULT_MAX_RETRIES;
    private static final String INVALID = "emailOtpInvalid";
    private static final String MAX = "emailOtpMaxRetries";
    private static final String EXPIRED = "emailOtpSessionExpired";

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock ClientModel client;
    @Mock UserModel user;
    @Mock UserProvider userProvider;
    @Mock EmailTemplateProvider emailProvider;
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
        when(session.getProvider(EmailTemplateProvider.class)).thenReturn(emailProvider);
        when(session.getProvider(BruteForceProtector.class)).thenReturn(bruteForceProtector);
        when(emailProvider.setRealm(any())).thenReturn(emailProvider);
        when(emailProvider.setUser(any())).thenReturn(emailProvider);

        when(client.isDirectAccessGrantsEnabled()).thenReturn(true);
        when(client.isConsentRequired()).thenReturn(false);
        when(client.getClientId()).thenReturn("test-client");

        when(realm.getId()).thenReturn("realm-1");
        when(realm.isLoginWithEmailAllowed()).thenReturn(false);
        when(realm.isBruteForceProtected()).thenReturn(true);
        when(realm.getAttribute("otp.sendCooldown")).thenReturn("60");

        when(user.getId()).thenReturn("user-1");
        when(user.isEnabled()).thenReturn(true);
        when(user.getEmail()).thenReturn("alice@example.com");
        when(user.isEmailVerified()).thenReturn(true);
        when(user.getRequiredActionsStream()).thenAnswer(inv -> Stream.empty());

        when(userProvider.getUserByUsername(any(), eq("alice"))).thenReturn(user);
        when(userProvider.getUserById(any(), eq("user-1"))).thenReturn(user);

        when(event.detail(anyString(), anyString())).thenReturn(event);
        when(event.user(any(UserModel.class))).thenReturn(event);

        async = OtpGrantTestSupport.AsyncDeliveryHarness.install(session, session, realm, "realm-1");
    }

    // ---------- Concurrent guesses against one otp_session_id ----------

    @Test
    void staleConcurrentReads_cannotEvaluateMoreThanMaxRetriesWrongGuesses() {
        Phase1 p1 = phase1();
        String wrong = wrongCodeFor(p1.code);

        // Worst-case interleaving: all requests read the session before any of them writes.
        store.freeze(p1.sessionId);
        List<String> errors = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            errors.add(phase2(wrong, p1.sessionId));
        }
        store.unfreeze(p1.sessionId);

        assertThat("wrong guesses actually evaluated", count(errors, INVALID), equalTo(MAX_RETRIES));
        assertThat(errors.subList(MAX_RETRIES, errors.size()), everyItem(is(MAX)));
        // Only evaluated guesses count towards brute-force detection.
        verify(bruteForceProtector, org.mockito.Mockito.times(MAX_RETRIES))
                .failedLogin(eq(realm), eq(user), any(), any(), any());
    }

    @Test
    void staleConcurrentReads_exhaustedCode_isBurnedEverywhere() {
        Phase1 p1 = phase1();
        String wrong = wrongCodeFor(p1.code);

        store.freeze(p1.sessionId);
        for (int i = 0; i < MAX_RETRIES + 1; i++) {
            phase2(wrong, p1.sessionId);
        }
        store.unfreeze(p1.sessionId);

        // The OTP session is gone, and the code cannot be recovered into a browser session.
        assertThat(store.contains(p1.sessionId), is(false));
        assertThat(OtpSendThrottle.getRecentCode(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL), nullValue());
        // Even the correct code is now refused.
        assertThat(phase2(p1.code, p1.sessionId), oneOf(EXPIRED, MAX));
    }

    @Test
    void realThreads_allReadingBeforeAnyWrite_evaluateExactlyMaxRetriesWrongGuesses() throws Exception {
        Phase1 p1 = phase1();
        String wrong = wrongCodeFor(p1.code);
        int threads = 20;
        store.gateReads(p1.sessionId, threads);

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<String>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> phase2(wrong, p1.sessionId)));
            }
            List<String> errors = new ArrayList<>();
            for (Future<String> f : futures) {
                errors.add(f.get(20, TimeUnit.SECONDS));
            }

            assertThat("wrong guesses actually evaluated", count(errors, INVALID), equalTo(MAX_RETRIES));
            assertThat(errors, everyItem(oneOf(INVALID, MAX, EXPIRED)));
        } finally {
            pool.shutdownNow();
        }
        assertThat(store.contains(p1.sessionId), is(false));
    }

    @Test
    void concurrentRedemptionOfCorrectCode_secondRequestDoesNotGetTokens() {
        // Two requests with the correct code read the session concurrently; the first one
        // consumes it. The second must not issue tokens off its stale read.
        Phase1 p1 = phase1();
        store.freeze(p1.sessionId);
        store.remove(p1.sessionId); // the concurrent winner already redeemed it

        String error = phase2(p1.code, p1.sessionId);

        assertThat(error, equalTo(EXPIRED));
    }

    // ---------- One budget per delivered code, shared with the browser flow ----------

    @Test
    void browserFlowGuesses_countAgainstTheGrantBudget() {
        Phase1 p1 = phase1();
        String wrong = wrongCodeFor(p1.code);

        // The browser flow recovers the grant-sent code from the per-user stash (cooldown still
        // running) and spends two attempts on it — exactly what the authenticators do.
        OtpSendThrottle.RecentCode recent =
                OtpSendThrottle.getRecentCode(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL);
        assertThat(recent, notNullValue());
        for (int i = 0; i < 2; i++) {
            assertThat(OtpSendThrottle.tryConsumeAttempt(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL,
                    recent.codeHash, MAX_RETRIES, recent.expiresAt), equalTo(i + 1));
        }

        assertThat(phase2(wrong, p1.sessionId), equalTo(INVALID));
        assertThat(phase2(wrong, p1.sessionId), equalTo(MAX));
    }

    @Test
    void grantGuesses_exhaustTheBrowserFlowBudget() {
        Phase1 p1 = phase1();
        String wrong = wrongCodeFor(p1.code);
        OtpSendThrottle.RecentCode recent =
                OtpSendThrottle.getRecentCode(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL);
        assertThat(recent, notNullValue());

        for (int i = 0; i < MAX_RETRIES; i++) {
            assertThat(phase2(wrong, p1.sessionId), equalTo(INVALID));
        }

        assertThat(OtpSendThrottle.tryConsumeAttempt(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL,
                recent.codeHash, MAX_RETRIES, recent.expiresAt), equalTo(0));
        assertThat(OtpSendThrottle.getRecentCode(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL), nullValue());
    }

    // ---------- Helpers ----------

    private record Phase1(String sessionId, String code) {}

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Phase1 phase1() {
        Response response = newGrant(Map.of("username", "alice"))
                .process(OtpGrantTestSupport.dummyContext(session));
        async.completeRequest();
        assertThat(response.getStatus(), equalTo(401));
        String sessionId = (String) ((Map<?, ?>) response.getEntity()).get("otp_session_id");
        ArgumentCaptor<Map> attrs = ArgumentCaptor.forClass(Map.class);
        try {
            verify(emailProvider).send(anyString(), anyString(), attrs.capture());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return new Phase1(sessionId, (String) attrs.getValue().get("code"));
    }

    /** Returns the OAuth {@code error} of the phase-2 response (or {@code "TOKENS"} on success). */
    private String phase2(String otp, String sessionId) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("username", "alice");
        params.put("otp", otp);
        params.put("otp_session_id", sessionId);
        try {
            Response response = newGrant(params).process(OtpGrantTestSupport.dummyContext(session));
            Object entity = response.getEntity();
            if (entity instanceof Map<?, ?> body && body.get("error") != null) {
                return (String) body.get("error");
            }
            return "TOKENS";
        } catch (CorsErrorResponseException e) {
            return errorOf(e);
        }
    }

    private AbstractOtpGrantTypeTest.TestableEmailOtpGrantType newGrant(Map<String, String> params) {
        AbstractOtpGrantTypeTest.TestableEmailOtpGrantType grant = new AbstractOtpGrantTypeTest.TestableEmailOtpGrantType();
        OtpGrantTestSupport.injectMocks(grant, session, realm, client, clientConnection,
                OtpGrantTestSupport.formParams(params), event, cors, httpRequest);
        return grant;
    }

    private static int count(List<String> errors, String error) {
        return (int) errors.stream().filter(error::equals).count();
    }

    private static String wrongCodeFor(String code) {
        char last = code.charAt(code.length() - 1);
        char flipped = last == '9' ? '0' : (char) (last + 1);
        return code.substring(0, code.length() - 1) + flipped;
    }

    private static String errorOf(CorsErrorResponseException ex) {
        try {
            Field f = CorsErrorResponseException.class.getDeclaredField("error");
            f.setAccessible(true);
            return (String) f.get(ex);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }
}
