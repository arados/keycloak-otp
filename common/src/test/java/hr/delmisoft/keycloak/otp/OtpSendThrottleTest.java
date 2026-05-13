package hr.delmisoft.keycloak.otp;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OtpSendThrottleTest {

    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;
    @Mock private UserModel user;
    @Mock private SingleUseObjectProvider store;

    @BeforeEach
    void setUp() {
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(realm.getId()).thenReturn("realm-1");
        when(user.getId()).thenReturn("user-1");
    }

    @Test
    void tryReserve_firstCall_returnsTrueAndStoresExpiry() {
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(true);

        boolean result = OtpSendThrottle.tryReserve(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL, 60);

        assertThat(result, equalTo(true));
        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        verify(store).putIfAbsent(keyCaptor.capture(), eq(60L));
        assertThat(keyCaptor.getValue(), containsString("realm-1"));
        assertThat(keyCaptor.getValue(), containsString("user-1"));
        assertThat(keyCaptor.getValue(), containsString("email"));

        // Sibling :meta is written for remainingSeconds()
        verify(store).put(eq(keyCaptor.getValue() + ":meta"), eq(60L), any());
    }

    @Test
    void tryReserve_secondCallWithinCooldown_returnsFalse() {
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(false);

        boolean result = OtpSendThrottle.tryReserve(session, realm, user, OtpSendThrottle.CHANNEL_SMS, 60);

        assertThat(result, equalTo(false));
        // Meta must NOT be overwritten when reservation fails
        verify(store, never()).put(anyString(), anyLong(), any());
    }

    @Test
    void tryReserve_zeroCooldown_alwaysReturnsTrueWithoutHittingStore() {
        boolean result = OtpSendThrottle.tryReserve(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL, 0);

        assertThat(result, equalTo(true));
        verify(store, never()).putIfAbsent(anyString(), anyLong());
    }

    @Test
    void tryReserve_keyIsScopedToRealmUserAndChannel() {
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(true);

        OtpSendThrottle.tryReserve(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL, 60);
        OtpSendThrottle.tryReserve(session, realm, user, OtpSendThrottle.CHANNEL_SMS, 60);

        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        verify(store, org.mockito.Mockito.times(2)).putIfAbsent(keyCaptor.capture(), anyLong());
        // Email and SMS get distinct keys (so user can be in email cooldown while triggering SMS)
        assertThat(keyCaptor.getAllValues().get(0), equalTo(keyCaptor.getAllValues().get(1).replace(":sms", ":email")));
    }

    @Test
    void remainingSeconds_noReservation_returnsZero() {
        when(store.get(anyString())).thenReturn(null);

        int remaining = OtpSendThrottle.remainingSeconds(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL);

        assertThat(remaining, equalTo(0));
    }

    @Test
    void remainingSeconds_activeReservation_returnsPositiveValue() {
        Map<String, String> meta = new HashMap<>();
        meta.put("expiresAt", String.valueOf(org.keycloak.common.util.Time.currentTime() + 45));
        when(store.get(anyString())).thenReturn(meta);

        int remaining = OtpSendThrottle.remainingSeconds(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL);

        assertThat(remaining, greaterThanOrEqualTo(44));
        assertThat(remaining, lessThanOrEqualTo(45));
    }

    @Test
    void remainingSeconds_expiredReservation_returnsZero() {
        Map<String, String> meta = new HashMap<>();
        meta.put("expiresAt", String.valueOf(org.keycloak.common.util.Time.currentTime() - 10));
        when(store.get(anyString())).thenReturn(meta);

        int remaining = OtpSendThrottle.remainingSeconds(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL);

        assertThat(remaining, equalTo(0));
    }

    @Test
    void remainingSeconds_corruptMeta_returnsZero() {
        Map<String, String> meta = new HashMap<>();
        meta.put("expiresAt", "not-a-number");
        when(store.get(anyString())).thenReturn(meta);

        int remaining = OtpSendThrottle.remainingSeconds(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL);

        assertThat(remaining, equalTo(0));
    }

    @Test
    void tryReserveWithCodeHash_onSuccess_stashesHashAndSaltInMeta() {
        when(store.putIfAbsent(anyString(), anyLong())).thenReturn(true);
        int codeExpiresAt = org.keycloak.common.util.Time.currentTime() + 300;

        boolean reserved = OtpSendThrottle.tryReserveWithCodeHash(session, realm, user,
                OtpSendThrottle.CHANNEL_EMAIL, 60, "hash-value", "salt-value", codeExpiresAt);

        assertThat(reserved, equalTo(true));
        ArgumentCaptor<Map> notesCaptor = ArgumentCaptor.forClass(Map.class);
        verify(store).put(anyString(), anyLong(), notesCaptor.capture());
        Map<String, String> notes = notesCaptor.getValue();
        assertThat(notes.get("codeHash"), equalTo("hash-value"));
        assertThat(notes.get("codeSalt"), equalTo("salt-value"));
        assertThat(notes.get("codeExpiresAt"), equalTo(String.valueOf(codeExpiresAt)));
    }

    @Test
    void release_removesBothKeyAndMeta() {
        OtpSendThrottle.release(session, realm, user, OtpSendThrottle.CHANNEL_EMAIL);

        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        verify(store, org.mockito.Mockito.times(2)).remove(keyCaptor.capture());
        assertThat(keyCaptor.getAllValues().get(1), equalTo(keyCaptor.getAllValues().get(0) + ":meta"));
    }

    @Test
    void getRecentCode_noMeta_returnsNull() {
        when(store.get(anyString())).thenReturn(null);

        OtpSendThrottle.RecentCode recent = OtpSendThrottle.getRecentCode(session, realm, user,
                OtpSendThrottle.CHANNEL_EMAIL);

        assertThat(recent, equalTo(null));
    }

    @Test
    void getRecentCode_withActiveStash_returnsHashSaltAndExpiry() {
        int codeExpiresAt = org.keycloak.common.util.Time.currentTime() + 120;
        Map<String, String> meta = new HashMap<>();
        meta.put("expiresAt", String.valueOf(org.keycloak.common.util.Time.currentTime() + 60));
        meta.put("codeHash", "stored-hash");
        meta.put("codeSalt", "stored-salt");
        meta.put("codeExpiresAt", String.valueOf(codeExpiresAt));
        when(store.get(anyString())).thenReturn(meta);

        OtpSendThrottle.RecentCode recent = OtpSendThrottle.getRecentCode(session, realm, user,
                OtpSendThrottle.CHANNEL_EMAIL);

        assertThat(recent, org.hamcrest.Matchers.notNullValue());
        assertThat(recent.codeHash, equalTo("stored-hash"));
        assertThat(recent.codeSalt, equalTo("stored-salt"));
        assertThat(recent.expiresAt, equalTo(codeExpiresAt));
    }

    @Test
    void getRecentCode_expiredCode_returnsNull() {
        Map<String, String> meta = new HashMap<>();
        meta.put("codeHash", "h");
        meta.put("codeSalt", "s");
        meta.put("codeExpiresAt", String.valueOf(org.keycloak.common.util.Time.currentTime() - 10));
        when(store.get(anyString())).thenReturn(meta);

        OtpSendThrottle.RecentCode recent = OtpSendThrottle.getRecentCode(session, realm, user,
                OtpSendThrottle.CHANNEL_EMAIL);

        assertThat(recent, equalTo(null));
    }

    @Test
    void getRecentCode_metaWithoutHash_returnsNull() {
        Map<String, String> meta = new HashMap<>();
        meta.put("expiresAt", String.valueOf(org.keycloak.common.util.Time.currentTime() + 30));
        when(store.get(anyString())).thenReturn(meta);

        OtpSendThrottle.RecentCode recent = OtpSendThrottle.getRecentCode(session, realm, user,
                OtpSendThrottle.CHANNEL_EMAIL);

        assertThat(recent, equalTo(null));
    }
}
