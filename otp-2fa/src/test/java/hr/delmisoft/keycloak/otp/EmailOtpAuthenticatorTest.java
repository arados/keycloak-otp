package hr.delmisoft.keycloak.otp;

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
import org.keycloak.common.util.Time;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class EmailOtpAuthenticatorTest {

    private EmailOtpAuthenticator authenticator;

    @Mock private AuthenticationFlowContext context;
    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;
    @Mock private UserModel user;
    @Mock private AuthenticationSessionModel authSession;
    @Mock private EmailTemplateProvider emailProvider;
    @Mock private LoginFormsProvider form;
    @Mock private HttpRequest httpRequest;
    @Mock private AuthenticatorConfigModel authenticatorConfig;
    @Mock private Response formResponse;

    @BeforeEach
    void setUp() {
        authenticator = new EmailOtpAuthenticator();
    }

    private void setupCommonMocks() {
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        when(session.getProvider(EmailTemplateProvider.class)).thenReturn(emailProvider);
        when(emailProvider.setRealm(any())).thenReturn(emailProvider);
        when(emailProvider.setUser(any())).thenReturn(emailProvider);
    }

    @Test
    void authenticate_sendsEmailAndChallenge() throws Exception {
        setupCommonMocks();
        when(context.form()).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.authenticate(context);

        // Verify code was stored in auth session
        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_CODE), anyString());
        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_EXPIRY), anyString());
        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_ATTEMPTS), eq("0"));

        // Verify email was sent
        verify(emailProvider).send(eq(EmailOtpConst.EMAIL_SUBJECT_KEY), eq(EmailOtpConst.EMAIL_TEMPLATE), any());

        // Verify challenge was issued
        verify(context).challenge(formResponse);
    }

    @Test
    void authenticate_emailFailure_returnsError() throws Exception {
        setupCommonMocks();
        when(context.form()).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createErrorPage(any())).thenReturn(formResponse);
        doThrow(new EmailException("fail")).when(emailProvider).send(anyString(), anyString(), any());

        authenticator.authenticate(context);

        verify(context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), any());
        verify(context, never()).challenge(any());
    }

    @Test
    void action_validCode_succeeds() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(EmailOtpConst.PARAM_OTP, "123456");

        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE)).thenReturn("123456");
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY)).thenReturn(String.valueOf(Time.currentTime() + 300));
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS)).thenReturn("0");

        authenticator.action(context);

        verify(context).success();
    }

    @Test
    void action_invalidCode_incrementsAttemptsAndFails() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(EmailOtpConst.PARAM_OTP, "999999");

        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE)).thenReturn("123456");
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY)).thenReturn(String.valueOf(Time.currentTime() + 300));
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS)).thenReturn("0");
        when(context.form()).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(anyString())).thenReturn(formResponse);

        authenticator.action(context);

        verify(authSession).setAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS, "1");
        verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
        verify(context, never()).success();
    }

    @Test
    void action_emptyOtp_fails() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(EmailOtpConst.PARAM_OTP, "");

        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(anyString())).thenReturn(formResponse);

        authenticator.action(context);

        verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
        verify(context, never()).success();
    }

    @Test
    void action_expiredCode_resendsAndFails() throws Exception {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(EmailOtpConst.PARAM_OTP, "123456");

        setupCommonMocks();
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE)).thenReturn("123456");
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY)).thenReturn(String.valueOf(Time.currentTime() - 10));
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS)).thenReturn("0");
        when(context.form()).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(anyString())).thenReturn(formResponse);

        authenticator.action(context);

        // Verify new code was generated and email resent
        ArgumentCaptor<String> codeCaptor = ArgumentCaptor.forClass(String.class);
        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_CODE), codeCaptor.capture());
        assertThat(codeCaptor.getValue(), notNullValue());
        verify(emailProvider).send(eq(EmailOtpConst.EMAIL_SUBJECT_KEY), eq(EmailOtpConst.EMAIL_TEMPLATE), any());
        verify(context).failureChallenge(eq(AuthenticationFlowError.EXPIRED_CODE), any());
    }

    @Test
    void action_maxRetriesExceeded_fails() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(EmailOtpConst.PARAM_OTP, "999999");

        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE)).thenReturn("123456");
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY)).thenReturn(String.valueOf(Time.currentTime() + 300));
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS)).thenReturn("3");
        when(context.form()).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(anyString())).thenReturn(formResponse);

        authenticator.action(context);

        verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
        verify(form).setError(EmailOtpConst.ERROR_OTP_MAX_RETRIES);
    }

    @Test
    void authenticate_withCustomConfig() throws Exception {
        setupCommonMocks();
        Map<String, String> config = new HashMap<>();
        config.put(EmailOtpConst.CONFIG_CODE_LENGTH, "8");
        config.put(EmailOtpConst.CONFIG_TTL, "600");
        when(authenticatorConfig.getConfig()).thenReturn(config);
        when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
        when(context.form()).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.authenticate(context);

        ArgumentCaptor<String> codeCaptor = ArgumentCaptor.forClass(String.class);
        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_CODE), codeCaptor.capture());
        assertThat(codeCaptor.getValue().length(), equalTo(8));
    }

    @Test
    void requiresUser_returnsTrue() {
        assertThat(authenticator.requiresUser(), equalTo(true));
    }

    @Test
    void configuredFor_userWithEmail_returnsTrue() {
        when(user.getEmail()).thenReturn("test@example.com");
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(true));
    }

    @Test
    void configuredFor_userWithoutEmail_returnsFalse() {
        when(user.getEmail()).thenReturn(null);
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(false));
    }
}
