package hr.delmisoft.keycloak.otp;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
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

import hr.delmisoft.keycloak.otp.sms.SmsOtpConst;
import hr.delmisoft.keycloak.otp.sms.SmsProvider;

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
 * Per-source-IP send limit on the combined channel-choice authenticator.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OtpChannelChoiceAuthenticatorIpLimitTest {

    private static final String IP = "203.0.113.7";
    private static final String IP_KEY_PREFIX = "otp-ip:realm-1:" + IP + ":";

    private OtpChannelChoiceAuthenticator authenticator;

    @Mock private AuthenticationFlowContext context;
    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;
    @Mock private UserModel user;
    @Mock private AuthenticationSessionModel authSession;
    @Mock private EmailTemplateProvider emailProvider;
    @Mock private SmsProvider smsProvider;
    @Mock private LoginFormsProvider form;
    @Mock private HttpRequest httpRequest;
    @Mock private Response formResponse;
    @Mock private SingleUseObjectProvider singleUseStore;
    @Mock private ClientConnection connection;

    @BeforeEach
    void setUp() {
        authenticator = new OtpChannelChoiceAuthenticator();
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        when(context.getConnection()).thenReturn(connection);
        when(connection.getRemoteAddr()).thenReturn(IP);
        when(session.getProvider(EmailTemplateProvider.class)).thenReturn(emailProvider);
        when(emailProvider.setRealm(any())).thenReturn(emailProvider);
        when(emailProvider.setUser(any())).thenReturn(emailProvider);
        when(session.getProvider(SmsProvider.class)).thenReturn(smsProvider);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUseStore);
        when(realm.getId()).thenReturn("realm-1");
        when(user.getId()).thenReturn("user-1");
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn("+1234567890");
        when(user.getEmail()).thenReturn("test@example.com");
        when(user.isEmailVerified()).thenReturn(true);
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(true);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(anyString())).thenReturn(formResponse);
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

    private void verifyNothingSent() throws Exception {
        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(smsProvider, never()).send(anyString(), anyString());
        verify(singleUseStore, never()).putIfAbsent(startsWith("otp-throttle:"), anyLong());
        verify(authSession, never()).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_HASH), anyString());
    }

    @Test
    void selectEmail_reservesIpSlotOnSend() throws Exception {
        formParam(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "email");

        authenticator.action(context);

        verify(singleUseStore).putIfAbsent(startsWith(IP_KEY_PREFIX), anyLong());
        verify(emailProvider).send(anyString(), anyString(), any());
    }

    @Test
    void selectEmail_ipLimitReached_showsOtpFormWithErrorAndDoesNotSend() throws Exception {
        ipLimitReached();
        formParam(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "email");

        authenticator.action(context);

        verifyNothingSent();
        verify(form).setError(OtpSendThrottle.ERROR_IP_SEND_LIMITED);
        verify(form).createForm(EmailOtpConst.LOGIN_TEMPLATE);
        verify(context).challenge(formResponse);
    }

    @Test
    void selectSms_ipLimitReached_showsOtpFormWithErrorAndDoesNotSend() throws Exception {
        ipLimitReached();
        formParam(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "sms");

        authenticator.action(context);

        verifyNothingSent();
        verify(form).setError(OtpSendThrottle.ERROR_IP_SEND_LIMITED);
        verify(form).createForm(SmsOtpConst.LOGIN_TEMPLATE);
        verify(context).challenge(formResponse);
    }

    @Test
    void resend_ipLimitReached_showsOtpFormWithErrorAndDoesNotSend() throws Exception {
        ipLimitReached();
        formParam(OtpChannelChoiceAuthenticator.PARAM_RESEND, "true");
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL)).thenReturn("sms");

        authenticator.action(context);

        verifyNothingSent();
        verify(form).setError(OtpSendThrottle.ERROR_IP_SEND_LIMITED);
        verify(context).challenge(formResponse);
    }

    @Test
    void expiredCode_ipLimitReached_showsErrorAndDoesNotSend() throws Exception {
        ipLimitReached();
        formParam(OtpChannelChoiceAuthenticator.PARAM_OTP, "123456");
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL)).thenReturn("email");
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_HASH)).thenReturn("hash");
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_SALT)).thenReturn("salt");
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_EXPIRY))
                .thenReturn(String.valueOf(Time.currentTime() - 10));
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_ATTEMPTS)).thenReturn("0");

        authenticator.action(context);

        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(singleUseStore, never()).putIfAbsent(startsWith("otp-throttle:"), anyLong());
        verify(form).setError(OtpSendThrottle.ERROR_IP_SEND_LIMITED);
    }

    @Test
    void selectEmail_userCooldownActive_releasesIpSlot() throws Exception {
        when(singleUseStore.putIfAbsent(startsWith("otp-throttle:"), anyLong())).thenReturn(false);
        formParam(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "email");

        authenticator.action(context);

        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(singleUseStore).remove(startsWith(IP_KEY_PREFIX));
    }

    @Test
    void selectEmail_sendFailure_releasesIpSlot() throws Exception {
        doThrow(new EmailException("fail")).when(emailProvider).send(anyString(), anyString(), any());
        formParam(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "email");

        authenticator.action(context);

        verify(singleUseStore).remove(startsWith(IP_KEY_PREFIX));
    }
}
