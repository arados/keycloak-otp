package hr.delmisoft.keycloak.otp;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Per-(realm, client IP) send limit: at most N sends per window across all users and
 * channels. Backed by an in-memory fake of {@link SingleUseObjectProvider} so the slot
 * reservation logic is exercised end-to-end.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OtpSendThrottleIpLimitTest {

    private static final String IP = "203.0.113.7";

    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;
    @Mock private SingleUseObjectProvider store;
    @Mock private ClientConnection connection;

    /** Fake store contents: key -> notes (empty map for putIfAbsent markers). */
    private final Map<String, Map<String, String>> entries = new HashMap<>();

    @BeforeEach
    void setUp() {
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(realm.getId()).thenReturn("realm-1");
        when(connection.getRemoteAddr()).thenReturn(IP);

        when(store.putIfAbsent(anyString(), anyLong())).thenAnswer(inv -> {
            String key = inv.getArgument(0);
            if (entries.containsKey(key)) {
                return false;
            }
            entries.put(key, new HashMap<>());
            return true;
        });
        Mockito.doAnswer(inv -> {
            entries.put(inv.getArgument(0), new HashMap<>(inv.<Map<String, String>>getArgument(2)));
            return null;
        }).when(store).put(anyString(), anyLong(), any());
        when(store.get(anyString())).thenAnswer(inv -> entries.get(inv.<String>getArgument(0)));
        when(store.remove(anyString())).thenAnswer(inv -> entries.remove(inv.<String>getArgument(0)));
    }

    @Test
    void allowsUpToLimitThenBlocks() {
        for (int i = 0; i < 3; i++) {
            OtpSendThrottle.IpSlot slot = OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 3, 3600);
            assertThat("send " + (i + 1) + " should be allowed", slot.isAllowed(), equalTo(true));
        }

        OtpSendThrottle.IpSlot blocked = OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 3, 3600);

        assertThat(blocked.isAllowed(), equalTo(false));
        assertThat(blocked.retryAfterSeconds(), greaterThan(0));
        assertThat(blocked.retryAfterSeconds(), lessThanOrEqualTo(3600));
    }

    @Test
    void slotKeysAreScopedToRealmAndIpWithWindowAsTtl() {
        OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 3, 900);

        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        verify(store).putIfAbsent(keyCaptor.capture(), eq(900L));
        assertThat(keyCaptor.getValue(), startsWith("otp-ip:realm-1:" + IP + ":"));
    }

    @Test
    void separateIpsAreIndependent() {
        for (int i = 0; i < 2; i++) {
            OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 2, 3600);
        }
        assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 2, 3600).isAllowed(), equalTo(false));

        OtpSendThrottle.IpSlot other = OtpSendThrottle.tryReserveIpSlot(session, realm, "198.51.100.9", 2, 3600);

        assertThat(other.isAllowed(), equalTo(true));
    }

    @Test
    void separateRealmsAreIndependent() {
        OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 1, 3600);
        assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 1, 3600).isAllowed(), equalTo(false));

        RealmModel otherRealm = Mockito.mock(RealmModel.class);
        when(otherRealm.getId()).thenReturn("realm-2");

        assertThat(OtpSendThrottle.tryReserveIpSlot(session, otherRealm, IP, 1, 3600).isAllowed(), equalTo(true));
    }

    @Test
    void zeroLimitDisablesWithoutTouchingStore() {
        for (int i = 0; i < 50; i++) {
            assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 0, 3600).isAllowed(), equalTo(true));
        }
        verify(store, never()).putIfAbsent(anyString(), anyLong());
    }

    @Test
    void missingClientIpIsNotTracked() {
        assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, (String) null, 1, 3600).isAllowed(), equalTo(true));
        assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, "  ", 1, 3600).isAllowed(), equalTo(true));
        verify(store, never()).putIfAbsent(anyString(), anyLong());
    }

    @Test
    void releaseFreesTheReservedSlot() {
        OtpSendThrottle.IpSlot first = OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 2, 3600);
        OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 2, 3600);
        assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 2, 3600).isAllowed(), equalTo(false));

        OtpSendThrottle.releaseIpSlot(session, first);

        assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 2, 3600).isAllowed(), equalTo(true));
        assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 2, 3600).isAllowed(), equalTo(false));
    }

    @Test
    void releaseOfBlockedOrUntrackedSlotIsNoOp() {
        OtpSendThrottle.IpSlot untracked = OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 0, 3600);
        OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 1, 3600);
        OtpSendThrottle.IpSlot blocked = OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 1, 3600);

        OtpSendThrottle.releaseIpSlot(session, untracked);
        OtpSendThrottle.releaseIpSlot(session, blocked);
        OtpSendThrottle.releaseIpSlot(session, null);

        verify(store, never()).remove(anyString());
    }

    @Test
    void retryAfterReflectsEarliestExpiringSlot() {
        OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 2, 3600);
        OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 2, 3600);
        // Simulate the first slot having been reserved long ago: only 42s of its window remain.
        entries.entrySet().stream()
                .filter(e -> e.getKey().endsWith(":0:meta"))
                .forEach(e -> e.getValue().put("expiresAt", String.valueOf(Time.currentTime() + 42)));

        OtpSendThrottle.IpSlot blocked = OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 2, 3600);

        assertThat(blocked.isAllowed(), equalTo(false));
        assertThat(blocked.retryAfterSeconds(), lessThanOrEqualTo(42));
        assertThat(blocked.retryAfterSeconds(), greaterThan(40));
    }

    @Test
    void ipv6AddressesInSameSlash64ShareABucket() {
        OtpSendThrottle.tryReserveIpSlot(session, realm, "2001:db8:1:2::1", 1, 3600);

        OtpSendThrottle.IpSlot sameNet = OtpSendThrottle.tryReserveIpSlot(session, realm,
                "2001:db8:1:2:ffff:eeee:dddd:cccc", 1, 3600);
        OtpSendThrottle.IpSlot otherNet = OtpSendThrottle.tryReserveIpSlot(session, realm,
                "2001:db8:1:3::1", 1, 3600);

        assertThat(sameNet.isAllowed(), equalTo(false));
        assertThat(otherNet.isAllowed(), equalTo(true));
    }

    @Test
    void ipv4MappedIpv6SharesBucketWithIpv4() {
        OtpSendThrottle.tryReserveIpSlot(session, realm, IP, 1, 3600);

        OtpSendThrottle.IpSlot mapped = OtpSendThrottle.tryReserveIpSlot(session, realm, "::ffff:" + IP, 1, 3600);

        assertThat(mapped.isAllowed(), equalTo(false));
    }

    // ---------- realm-attribute resolution ----------

    @Test
    void realmDefaults_allowTenPerHour() {
        when(realm.getAttribute(OtpSendThrottle.CONFIG_IP_SEND_LIMIT)).thenReturn(null);
        when(realm.getAttribute(OtpSendThrottle.CONFIG_IP_SEND_WINDOW)).thenReturn(null);

        for (int i = 0; i < OtpSendThrottle.DEFAULT_IP_SEND_LIMIT; i++) {
            assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, connection).isAllowed(), equalTo(true));
        }
        assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, connection).isAllowed(), equalTo(false));
        verify(store, Mockito.atLeastOnce())
                .putIfAbsent(anyString(), eq((long) OtpSendThrottle.DEFAULT_IP_SEND_WINDOW));
        assertThat(OtpSendThrottle.DEFAULT_IP_SEND_LIMIT, equalTo(10));
        assertThat(OtpSendThrottle.DEFAULT_IP_SEND_WINDOW, equalTo(3600));
    }

    @Test
    void realmAttributesOverrideLimitAndWindow() {
        when(realm.getAttribute(OtpSendThrottle.CONFIG_IP_SEND_LIMIT)).thenReturn("2");
        when(realm.getAttribute(OtpSendThrottle.CONFIG_IP_SEND_WINDOW)).thenReturn("120");

        assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, connection).isAllowed(), equalTo(true));
        assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, connection).isAllowed(), equalTo(true));
        assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, connection).isAllowed(), equalTo(false));
        verify(store, Mockito.atLeastOnce()).putIfAbsent(anyString(), eq(120L));
    }

    @Test
    void realmAttributeZeroDisables() {
        when(realm.getAttribute(OtpSendThrottle.CONFIG_IP_SEND_LIMIT)).thenReturn("0");

        for (int i = 0; i < 50; i++) {
            assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, connection).isAllowed(), equalTo(true));
        }
        verify(store, never()).putIfAbsent(anyString(), anyLong());
    }

    @Test
    void invalidRealmAttributesFallBackToDefaults() {
        when(realm.getAttribute(OtpSendThrottle.CONFIG_IP_SEND_LIMIT)).thenReturn("-5");
        when(realm.getAttribute(OtpSendThrottle.CONFIG_IP_SEND_WINDOW)).thenReturn("not-a-number");

        assertThat(OtpSendThrottle.resolveIpSendLimit(realm), equalTo(OtpSendThrottle.DEFAULT_IP_SEND_LIMIT));
        assertThat(OtpSendThrottle.resolveIpSendWindow(realm), equalTo(OtpSendThrottle.DEFAULT_IP_SEND_WINDOW));

        when(realm.getAttribute(OtpSendThrottle.CONFIG_IP_SEND_WINDOW)).thenReturn("0");
        assertThat(OtpSendThrottle.resolveIpSendWindow(realm), equalTo(OtpSendThrottle.DEFAULT_IP_SEND_WINDOW));
    }

    @Test
    void nullConnectionIsNotTracked() {
        assertThat(OtpSendThrottle.tryReserveIpSlot(session, realm, (ClientConnection) null).isAllowed(),
                equalTo(true));
        verify(store, never()).putIfAbsent(anyString(), anyLong());
    }
}
