package hr.delmisoft.keycloak.otp.sms;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import hr.delmisoft.keycloak.otp.OtpSendThrottle;

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
 * Per-source-IP send limit on the SMS OTP browser authenticator.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmsOtpAuthenticatorIpLimitTest {

    private static final String IP = "203.0.113.7";
    private static final String IP_KEY_PREFIX = "otp-ip:realm-1:" + IP + ":";

    private SmsOtpAuthenticator authenticator;

    @Mock private AuthenticationFlowContext context;
    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;
    @Mock private UserModel user;
    @Mock private AuthenticationSessionModel authSession;
    @Mock private SmsProvider smsProvider;
    @Mock private LoginFormsProvider form;
    @Mock private HttpRequest httpRequest;
    @Mock private Response formResponse;
    @Mock private SingleUseObjectProvider singleUseStore;
    @Mock private ClientConnection connection;

    @BeforeEach
    void setUp() {
        authenticator = new SmsOtpAuthenticator();
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        when(context.getConnection()).thenReturn(connection);
        when(connection.getRemoteAddr()).thenReturn(IP);
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn("+1234567890");
        when(session.getProvider(SmsProvider.class)).thenReturn(smsProvider);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUseStore);
        when(realm.getId()).thenReturn("realm-1");
        when(user.getId()).thenReturn("user-1");
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(true);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(SmsOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);
        when(form.createErrorPage(any())).thenReturn(formResponse);
    }

    private void ipLimitReached() {
        when(singleUseStore.putIfAbsent(startsWith("otp-ip:"), anyLong())).thenReturn(false);
    }

    private void formParam(String name, String value) {
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.putSingle(name, value);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(params);
    }

    private void verifyIpLimitedChallengeWithoutSend() throws Exception {
        verify(smsProvider, never()).send(anyString(), anyString());
        verify(singleUseStore, never()).putIfAbsent(startsWith("otp-throttle:"), anyLong());
        verify(authSession, never()).setAuthNote(eq(SmsOtpConst.AUTH_NOTE_CODE_HASH), anyString());
        verify(form).setError(OtpSendThrottle.ERROR_IP_SEND_LIMITED);
        verify(context).challenge(formResponse);
    }

    @Test
    void authenticate_reservesIpSlotOnSend() throws Exception {
        authenticator.authenticate(context);

        verify(singleUseStore).putIfAbsent(startsWith(IP_KEY_PREFIX), anyLong());
        verify(smsProvider).send(eq("+1234567890"), anyString());
    }

    @Test
    void authenticate_ipLimitReached_showsFormWithErrorAndDoesNotSend() throws Exception {
        ipLimitReached();

        authenticator.authenticate(context);

        verifyIpLimitedChallengeWithoutSend();
    }

    @Test
    void action_resend_ipLimitReached_showsFormWithErrorAndDoesNotSend() throws Exception {
        ipLimitReached();
        formParam(SmsOtpConst.PARAM_RESEND, "true");

        authenticator.action(context);

        verifyIpLimitedChallengeWithoutSend();
    }

    @Test
    void action_expiredCode_ipLimitReached_showsFormWithErrorAndDoesNotSend() throws Exception {
        ipLimitReached();
        formParam(SmsOtpConst.PARAM_OTP, "123456");
        when(authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_CODE_HASH)).thenReturn("hash");
        when(authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_CODE_SALT)).thenReturn("salt");
        when(authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY)).thenReturn(String.valueOf(Time.currentTime() - 10));
        when(authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS)).thenReturn("0");

        authenticator.action(context);

        verify(smsProvider, never()).send(anyString(), anyString());
        verify(singleUseStore, never()).putIfAbsent(startsWith("otp-throttle:"), anyLong());
        verify(form).setError(OtpSendThrottle.ERROR_IP_SEND_LIMITED);
    }

    @Test
    void authenticate_userCooldownActive_releasesIpSlot() throws Exception {
        when(singleUseStore.putIfAbsent(startsWith("otp-throttle:"), anyLong())).thenReturn(false);

        authenticator.authenticate(context);

        verify(smsProvider, never()).send(anyString(), anyString());
        verify(singleUseStore).remove(startsWith(IP_KEY_PREFIX));
    }

    @Test
    void authenticate_sendFailure_releasesIpSlot() throws Exception {
        doThrow(new SmsException("fail")).when(smsProvider).send(anyString(), anyString());

        authenticator.authenticate(context);

        verify(singleUseStore).remove(startsWith(IP_KEY_PREFIX));
    }
}
