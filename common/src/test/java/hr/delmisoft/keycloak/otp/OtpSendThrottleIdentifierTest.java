package hr.delmisoft.keycloak.otp;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for the per-(realm, submitted identifier, channel) throttle used by the OTP grant
 * types, which applies to every phase-1 request regardless of whether the identifier resolves
 * to an account.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OtpSendThrottleIdentifierTest {

    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;
    @Mock private SingleUseObjectProvider store;

    @BeforeEach
    void setUp() {
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(realm.getId()).thenReturn("realm-1");
    }

    @Test
    void tryReserveForIdentifier_firstCall_returnsTrueAndStoresMeta() {
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(true);

        boolean reserved = OtpSendThrottle.tryReserveForIdentifier(session, realm, "alice",
                OtpSendThrottle.CHANNEL_EMAIL, 60);

        assertThat(reserved, equalTo(true));
        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(store).putIfAbsent(key.capture(), eq(60L));
        verify(store).put(eq(key.getValue() + ":meta"), eq(60L), any());
    }

    @Test
    void tryReserveForIdentifier_keyDoesNotContainRawIdentifier() {
        // The submitted identifier may be an email address — don't leave it in cache keys.
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(true);

        OtpSendThrottle.tryReserveForIdentifier(session, realm, "alice@example.com",
                OtpSendThrottle.CHANNEL_EMAIL, 60);

        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(store).putIfAbsent(key.capture(), anyLong());
        assertThat(key.getValue(), not(containsString("alice")));
        assertThat(key.getValue(), startsWith("otp-throttle:"));
    }

    @Test
    void tryReserveForIdentifier_keyIsDistinctFromPerUserKey() {
        // A username equal to some user's id must not collide with the per-user throttle.
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(true);
        org.keycloak.models.UserModel user = org.mockito.Mockito.mock(org.keycloak.models.UserModel.class);
        when(user.getId()).thenReturn("alice");

        OtpSendThrottle.tryReserveForIdentifier(session, realm, "alice", OtpSendThrottle.CHANNEL_EMAIL, 60);
        OtpSendThrottle.tryReserve(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL, 60);

        ArgumentCaptor<String> keys = ArgumentCaptor.forClass(String.class);
        verify(store, times(2)).putIfAbsent(keys.capture(), anyLong());
        assertThat(keys.getAllValues().get(0), not(equalTo(keys.getAllValues().get(1))));
    }

    @Test
    void tryReserveForIdentifier_normalizesCaseAndWhitespace() {
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(true);

        OtpSendThrottle.tryReserveForIdentifier(session, realm, "Alice", OtpSendThrottle.CHANNEL_EMAIL, 60);
        OtpSendThrottle.tryReserveForIdentifier(session, realm, " alice ", OtpSendThrottle.CHANNEL_EMAIL, 60);

        ArgumentCaptor<String> keys = ArgumentCaptor.forClass(String.class);
        verify(store, times(2)).putIfAbsent(keys.capture(), anyLong());
        assertThat(keys.getAllValues().get(0), equalTo(keys.getAllValues().get(1)));
    }

    @Test
    void tryReserveForIdentifier_keyIsScopedToRealmIdentifierAndChannel() {
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(true);
        RealmModel otherRealm = org.mockito.Mockito.mock(RealmModel.class);
        when(otherRealm.getId()).thenReturn("realm-2");

        OtpSendThrottle.tryReserveForIdentifier(session, realm, "alice", OtpSendThrottle.CHANNEL_EMAIL, 60);
        OtpSendThrottle.tryReserveForIdentifier(session, realm, "alice", OtpSendThrottle.CHANNEL_SMS, 60);
        OtpSendThrottle.tryReserveForIdentifier(session, otherRealm, "alice", OtpSendThrottle.CHANNEL_EMAIL, 60);
        OtpSendThrottle.tryReserveForIdentifier(session, realm, "bob", OtpSendThrottle.CHANNEL_EMAIL, 60);

        ArgumentCaptor<String> keys = ArgumentCaptor.forClass(String.class);
        verify(store, times(4)).putIfAbsent(keys.capture(), anyLong());
        assertThat(new java.util.HashSet<>(keys.getAllValues()).size(), equalTo(4));
    }

    @Test
    void tryReserveForIdentifier_secondCallWithinCooldown_returnsFalseWithoutOverwritingMeta() {
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(false);

        boolean reserved = OtpSendThrottle.tryReserveForIdentifier(session, realm, "alice",
                OtpSendThrottle.CHANNEL_SMS, 60);

        assertThat(reserved, equalTo(false));
        verify(store, never()).put(anyString(), anyLong(), any());
    }

    @Test
    void tryReserveForIdentifier_zeroCooldown_alwaysTrueWithoutHittingStore() {
        boolean reserved = OtpSendThrottle.tryReserveForIdentifier(session, realm, "alice",
                OtpSendThrottle.CHANNEL_EMAIL, 0);

        assertThat(reserved, equalTo(true));
        verify(store, never()).putIfAbsent(anyString(), anyLong());
    }

    @Test
    void remainingSecondsForIdentifier_activeReservation_returnsRemaining() {
        Map<String, String> meta = new HashMap<>();
        meta.put("expiresAt", String.valueOf(Time.currentTime() + 45));
        when(store.get(anyString())).thenReturn(meta);

        int remaining = OtpSendThrottle.remainingSecondsForIdentifier(session, realm, "alice",
                OtpSendThrottle.CHANNEL_EMAIL);

        assertThat(remaining, greaterThanOrEqualTo(44));
        assertThat(remaining, lessThanOrEqualTo(45));
    }

    @Test
    void remainingSecondsForIdentifier_readsTheSameKeyThatWasReserved() {
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(true);
        OtpSendThrottle.tryReserveForIdentifier(session, realm, "Alice", OtpSendThrottle.CHANNEL_EMAIL, 60);
        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(store).putIfAbsent(key.capture(), anyLong());

        OtpSendThrottle.remainingSecondsForIdentifier(session, realm, "alice", OtpSendThrottle.CHANNEL_EMAIL);

        verify(store).get(key.getValue() + ":meta");
    }

    @Test
    void remainingSecondsForIdentifier_noReservationOrCorruptMeta_returnsZero() {
        when(store.get(anyString())).thenReturn(null);
        assertThat(OtpSendThrottle.remainingSecondsForIdentifier(session, realm, "alice",
                OtpSendThrottle.CHANNEL_EMAIL), equalTo(0));

        Map<String, String> meta = new HashMap<>();
        meta.put("expiresAt", "garbage");
        when(store.get(anyString())).thenReturn(meta);
        assertThat(OtpSendThrottle.remainingSecondsForIdentifier(session, realm, "alice",
                OtpSendThrottle.CHANNEL_EMAIL), equalTo(0));
    }

    @Test
    void releaseIdentifier_removesKeyAndMeta() {
        OtpSendThrottle.releaseIdentifier(session, realm, "alice", OtpSendThrottle.CHANNEL_EMAIL);

        ArgumentCaptor<String> keys = ArgumentCaptor.forClass(String.class);
        verify(store, times(2)).remove(keys.capture());
        assertThat(keys.getAllValues().get(1), equalTo(keys.getAllValues().get(0) + ":meta"));
    }
}
