package hr.delmisoft.keycloak.otp;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Per-code attempt accounting in {@link OtpSendThrottle}: failures are counted against the
 * delivered code (shared across auth sessions), and a code that has used up its attempts is
 * burned so it can never be recovered into another session.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OtpSendThrottleAttemptsTest {

    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;
    @Mock private UserModel user;

    private InMemoryStore store;
    private int codeExpiresAt;

    @BeforeEach
    void setUp() {
        store = new InMemoryStore();
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(realm.getId()).thenReturn("realm-1");
        when(user.getId()).thenReturn("user-1");
        codeExpiresAt = Time.currentTime() + 300;
    }

    @AfterEach
    void resetTime() {
        Time.setOffset(0);
    }

    @Test
    void tryConsumeAttempt_returnsSequentialAttemptNumbersThenZero() {
        assertThat(consume("hash-a", 3), equalTo(1));
        assertThat(consume("hash-a", 3), equalTo(2));
        assertThat(consume("hash-a", 3), equalTo(3));
        assertThat(consume("hash-a", 3), equalTo(0));
        assertThat(consume("hash-a", 3), equalTo(0));
    }

    @Test
    void tryConsumeAttempt_isScopedPerCode() {
        for (int i = 0; i < 3; i++) {
            consume("hash-a", 3);
        }
        assertThat(consume("hash-a", 3), equalTo(0));
        assertThat(consume("hash-b", 3), equalTo(1));
    }

    @Test
    void tryConsumeAttempt_isScopedPerUserAndChannel() {
        for (int i = 0; i < 3; i++) {
            consume("hash-a", 3);
        }
        assertThat(OtpSendThrottle.tryConsumeAttempt(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL,
                "hash-a", 3, codeExpiresAt), equalTo(1));

        UserModel other = mock(UserModel.class);
        when(other.getId()).thenReturn("user-2");
        assertThat(OtpSendThrottle.tryConsumeAttempt(session, realm, other, OtpSendThrottle.CHANNEL_SMS,
                "hash-a", 3, codeExpiresAt), equalTo(1));
    }

    @Test
    void tryConsumeAttempt_slotsLiveUntilCodeExpiry() {
        for (int i = 0; i < 3; i++) {
            consume("hash-a", 3);
        }
        // Well past any cooldown but before the code expires: still exhausted.
        Time.setOffset(200);
        assertThat(consume("hash-a", 3), equalTo(0));
    }

    @Test
    void tryConsumeAttempt_nonPositiveMaxAttempts_isTreatedAsExhausted() {
        assertThat(consume("hash-a", 0), equalTo(0));
    }

    @Test
    void burnCode_matchingStash_getRecentCodeReturnsNullButCooldownIsKept() {
        OtpSendThrottle.tryReserveWithCodeHash(session, realm, user, OtpSendThrottle.CHANNEL_SMS, 60,
                "hash-a", "salt-a", codeExpiresAt);
        assertThat(OtpSendThrottle.getRecentCode(session, realm, user, OtpSendThrottle.CHANNEL_SMS), notNullValue());

        OtpSendThrottle.burnCode(session, realm, user, OtpSendThrottle.CHANNEL_SMS, "hash-a");

        assertThat(OtpSendThrottle.getRecentCode(session, realm, user, OtpSendThrottle.CHANNEL_SMS), nullValue());
        // Burning must not reset the send cooldown — otherwise a burned code would let the
        // caller immediately trigger a new send.
        assertThat(OtpSendThrottle.remainingSeconds(session, realm, user, OtpSendThrottle.CHANNEL_SMS),
                greaterThan(0));
        assertThat(OtpSendThrottle.tryReserve(session, realm, user, OtpSendThrottle.CHANNEL_SMS, 60),
                equalTo(false));
    }

    @Test
    void burnCode_differentCode_leavesNewerStashIntact() {
        OtpSendThrottle.tryReserveWithCodeHash(session, realm, user, OtpSendThrottle.CHANNEL_SMS, 60,
                "hash-new", "salt-new", codeExpiresAt);

        OtpSendThrottle.burnCode(session, realm, user, OtpSendThrottle.CHANNEL_SMS, "hash-old");

        OtpSendThrottle.RecentCode recent = OtpSendThrottle.getRecentCode(session, realm, user,
                OtpSendThrottle.CHANNEL_SMS);
        assertThat(recent, notNullValue());
        assertThat(recent.codeHash, equalTo("hash-new"));
    }

    @Test
    void burnCode_withoutStash_isNoOp() {
        OtpSendThrottle.burnCode(session, realm, user, OtpSendThrottle.CHANNEL_SMS, "hash-a");

        assertThat(OtpSendThrottle.getRecentCode(session, realm, user, OtpSendThrottle.CHANNEL_SMS), nullValue());
    }

    private int consume(String hash, int max) {
        return OtpSendThrottle.tryConsumeAttempt(session, realm, user, OtpSendThrottle.CHANNEL_SMS,
                hash, max, codeExpiresAt);
    }

    /** Minimal in-memory {@link SingleUseObjectProvider} honoring lifespans via {@link Time}. */
    private static final class InMemoryStore implements SingleUseObjectProvider {
        private final Map<String, Map<String, String>> values = new HashMap<>();
        private final Map<String, Long> expiries = new HashMap<>();

        private boolean live(String key) {
            Long exp = expiries.get(key);
            if (exp != null && Time.currentTime() >= exp) {
                values.remove(key);
                expiries.remove(key);
                return false;
            }
            return values.containsKey(key);
        }

        @Override
        public void put(String key, long lifespanSeconds, Map<String, String> notes) {
            values.put(key, new HashMap<>(notes));
            expiries.put(key, Time.currentTime() + lifespanSeconds);
        }

        @Override
        public Map<String, String> get(String key) {
            return live(key) ? new HashMap<>(values.get(key)) : null;
        }

        @Override
        public Map<String, String> remove(String key) {
            Map<String, String> v = live(key) ? values.get(key) : null;
            values.remove(key);
            expiries.remove(key);
            return v;
        }

        @Override
        public boolean replace(String key, Map<String, String> notes) {
            if (!live(key)) {
                return false;
            }
            values.put(key, new HashMap<>(notes));
            return true;
        }

        @Override
        public boolean putIfAbsent(String key, long lifespanInSeconds) {
            if (live(key)) {
                return false;
            }
            put(key, lifespanInSeconds, new HashMap<>());
            return true;
        }

        @Override
        public boolean contains(String key) {
            return live(key);
        }

        @Override
        public void close() {
            // no-op
        }
    }
}
