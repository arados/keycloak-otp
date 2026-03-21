package hr.delmisoft.keycloak.otp.sms;

import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmsOtpDirectGrantAuthenticatorTest {

    private SmsOtpDirectGrantAuthenticator authenticator;

    @Mock private AuthenticationFlowContext context;
    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;
    @Mock private UserModel user;
    @Mock private HttpRequest httpRequest;
    @Mock private EventBuilder eventBuilder;
    @Mock private SmsProvider smsProvider;
    @Mock private SingleUseObjectProvider store;

    @BeforeEach
    void setUp() {
        authenticator = new SmsOtpDirectGrantAuthenticator();
    }

    private void setupCommonMocks() {
        when(context.getSession()).thenReturn(session);
        when(context.getUser()).thenReturn(user);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        when(user.getId()).thenReturn("user-123");
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn("+1234567890");
    }

    @Test
    void authenticate_noOtpParam_sendsSmsAndReturns401() throws Exception {
        setupCommonMocks();
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(session.getProvider(SmsProvider.class)).thenReturn(smsProvider);

        authenticator.authenticate(context);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> notesCaptor = ArgumentCaptor.forClass(Map.class);
        verify(store).put(anyString(), anyLong(), notesCaptor.capture());
        Map<String, String> notes = notesCaptor.getValue();
        assertThat(notes, hasEntry(equalTo(SmsOtpConst.NOTE_CODE), notNullValue()));
        assertThat(notes, hasEntry(SmsOtpConst.NOTE_USER_ID, "user-123"));
        assertThat(notes, hasEntry(SmsOtpConst.NOTE_ATTEMPTS, "0"));

        verify(smsProvider).send(eq("+1234567890"), anyString());

        ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
        verify(context).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS), responseCaptor.capture());
        assertThat(responseCaptor.getValue().getStatus(), equalTo(401));
    }

    @Test
    void authenticate_noUser_fails() {
        when(context.getUser()).thenReturn(null);
        when(context.getEvent()).thenReturn(eventBuilder);
        when(context.getAuthenticatorConfig()).thenReturn(null);

        authenticator.authenticate(context);

        verify(context).failure(eq(AuthenticationFlowError.INVALID_USER), any());
    }

    @Test
    void authenticate_noPhoneNumber_fails() {
        when(context.getUser()).thenReturn(user);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn(null);
        when(context.getEvent()).thenReturn(eventBuilder);

        authenticator.authenticate(context);

        verify(context).failure(eq(AuthenticationFlowError.INVALID_USER), any());
    }

    @Test
    void authenticate_smsFailure_cleansUpAndFails() throws Exception {
        setupCommonMocks();
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(session.getProvider(SmsProvider.class)).thenReturn(smsProvider);
        when(context.getEvent()).thenReturn(eventBuilder);
        doThrow(new SmsException("fail")).when(smsProvider).send(anyString(), anyString());

        authenticator.authenticate(context);

        verify(store).remove(anyString());
        verify(context).failure(eq(AuthenticationFlowError.INTERNAL_ERROR), any());
    }

    @Test
    void authenticate_phase2_validOtp_succeeds() {
        setupCommonMocks();
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle(SmsOtpConst.PARAM_OTP, "123456");
        params.putSingle(SmsOtpConst.PARAM_OTP_SESSION_ID, "session-abc");
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);

        Map<String, String> storedNotes = new HashMap<>();
        storedNotes.put(SmsOtpConst.NOTE_CODE, "123456");
        storedNotes.put(SmsOtpConst.NOTE_USER_ID, "user-123");
        storedNotes.put(SmsOtpConst.NOTE_ATTEMPTS, "0");
        when(store.get("session-abc")).thenReturn(storedNotes);

        authenticator.authenticate(context);

        verify(store).remove("session-abc");
        verify(context).success();
    }

    @Test
    void authenticate_phase2_invalidOtp_incrementsAttempts() {
        setupCommonMocks();
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle(SmsOtpConst.PARAM_OTP, "999999");
        params.putSingle(SmsOtpConst.PARAM_OTP_SESSION_ID, "session-abc");
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(context.getEvent()).thenReturn(eventBuilder);

        Map<String, String> storedNotes = new HashMap<>();
        storedNotes.put(SmsOtpConst.NOTE_CODE, "123456");
        storedNotes.put(SmsOtpConst.NOTE_USER_ID, "user-123");
        storedNotes.put(SmsOtpConst.NOTE_ATTEMPTS, "0");
        when(store.get("session-abc")).thenReturn(storedNotes);

        authenticator.authenticate(context);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> notesCaptor = ArgumentCaptor.forClass(Map.class);
        verify(store).replace(eq("session-abc"), notesCaptor.capture());
        assertThat(notesCaptor.getValue().get(SmsOtpConst.NOTE_ATTEMPTS), equalTo("1"));
        verify(context).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
        verify(context, never()).success();
    }

    @Test
    void authenticate_phase2_expiredSession_fails() {
        setupCommonMocks();
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle(SmsOtpConst.PARAM_OTP, "123456");
        params.putSingle(SmsOtpConst.PARAM_OTP_SESSION_ID, "session-abc");
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(store.get("session-abc")).thenReturn(null);
        when(context.getEvent()).thenReturn(eventBuilder);

        authenticator.authenticate(context);

        verify(context).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
        verify(context, never()).success();
    }

    @Test
    void authenticate_phase2_wrongUser_fails() {
        setupCommonMocks();
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle(SmsOtpConst.PARAM_OTP, "123456");
        params.putSingle(SmsOtpConst.PARAM_OTP_SESSION_ID, "session-abc");
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(context.getEvent()).thenReturn(eventBuilder);

        Map<String, String> storedNotes = new HashMap<>();
        storedNotes.put(SmsOtpConst.NOTE_CODE, "123456");
        storedNotes.put(SmsOtpConst.NOTE_USER_ID, "different-user");
        storedNotes.put(SmsOtpConst.NOTE_ATTEMPTS, "0");
        when(store.get("session-abc")).thenReturn(storedNotes);

        authenticator.authenticate(context);

        verify(store).remove("session-abc");
        verify(context).failure(eq(AuthenticationFlowError.INVALID_USER), any());
        verify(context, never()).success();
    }

    @Test
    void authenticate_phase2_maxRetriesExceeded_fails() {
        setupCommonMocks();
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle(SmsOtpConst.PARAM_OTP, "999999");
        params.putSingle(SmsOtpConst.PARAM_OTP_SESSION_ID, "session-abc");
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(store);
        when(context.getEvent()).thenReturn(eventBuilder);

        Map<String, String> storedNotes = new HashMap<>();
        storedNotes.put(SmsOtpConst.NOTE_CODE, "123456");
        storedNotes.put(SmsOtpConst.NOTE_USER_ID, "user-123");
        storedNotes.put(SmsOtpConst.NOTE_ATTEMPTS, "3");
        when(store.get("session-abc")).thenReturn(storedNotes);

        authenticator.authenticate(context);

        verify(store).remove("session-abc");
        verify(context).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
    }

    @Test
    void authenticate_phase2_missingSessionId_fails() {
        setupCommonMocks();
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle(SmsOtpConst.PARAM_OTP, "123456");
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);
        when(context.getEvent()).thenReturn(eventBuilder);

        authenticator.authenticate(context);

        verify(context).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
    }

    @Test
    void requiresUser_returnsTrue() {
        assertThat(authenticator.requiresUser(), equalTo(true));
    }

    @Test
    void configuredFor_userWithPhone_returnsTrue() {
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn("+1234567890");
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(true));
    }

    @Test
    void configuredFor_userWithoutPhone_returnsFalse() {
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn(null);
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(false));
    }

    @Test
    void getId_returnsCorrectId() {
        assertThat(authenticator.getId(), equalTo(SmsOtpConst.DIRECT_GRANT_PROVIDER_ID));
    }

    @Test
    void isConfigurable_returnsTrue() {
        assertThat(authenticator.isConfigurable(), equalTo(true));
    }

    @Test
    void getConfigProperties_hasFourEntries() {
        assertThat(authenticator.getConfigProperties().size(), equalTo(4));
    }
}
