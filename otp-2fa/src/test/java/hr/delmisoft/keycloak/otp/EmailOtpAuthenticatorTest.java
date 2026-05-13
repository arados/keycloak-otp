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
import org.keycloak.models.SingleUseObjectProvider;
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
import static org.mockito.ArgumentMatchers.anyLong;
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
    @Mock private SingleUseObjectProvider singleUseStore;

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
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUseStore);
        when(realm.getId()).thenReturn("realm-1");
        when(user.getId()).thenReturn("user-1");
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(true);
        when(emailProvider.setRealm(any())).thenReturn(emailProvider);
        when(emailProvider.setUser(any())).thenReturn(emailProvider);
    }

    private void stubStoredCode(String plainCode, int secondsUntilExpiry, String attempts) {
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash(plainCode, salt);
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE_HASH)).thenReturn(hash);
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE_SALT)).thenReturn(salt);
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY))
                .thenReturn(String.valueOf(Time.currentTime() + secondsUntilExpiry));
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS)).thenReturn(attempts);
    }

    @Test
    void authenticate_sendsEmailAndChallenge() throws Exception {
        setupCommonMocks();
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.authenticate(context);

        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_CODE_HASH), anyString());
        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_CODE_SALT), anyString());
        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_EXPIRY), anyString());
        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_ATTEMPTS), eq("0"));

        verify(emailProvider).send(eq(EmailOtpConst.EMAIL_SUBJECT_KEY), eq(EmailOtpConst.EMAIL_TEMPLATE), any());

        verify(context).challenge(formResponse);
    }

    @Test
    void authenticate_emailFailure_rollsBackThrottleAndClearsSession() throws Exception {
        setupCommonMocks();
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createErrorPage(any())).thenReturn(formResponse);
        doThrow(new EmailException("fail")).when(emailProvider).send(anyString(), anyString(), any());

        authenticator.authenticate(context);

        verify(context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), any());
        verify(context, never()).challenge(any());
        // REL-001: throttle rolled back (release removes both key and key:meta entries) so the
        // user is not locked out by a cooldown protecting an OTP they never received; auth
        // notes cleared so we don't later "recover" an undelivered code into a fresh session.
        verify(singleUseStore, org.mockito.Mockito.times(2)).remove(anyString());
        verify(authSession).removeAuthNote(EmailOtpConst.AUTH_NOTE_CODE_HASH);
        verify(authSession).removeAuthNote(EmailOtpConst.AUTH_NOTE_CODE_SALT);
    }

    @Test
    void action_validCode_succeeds() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(EmailOtpConst.PARAM_OTP, "123456");

        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        stubStoredCode("123456", 300, "0");

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
        stubStoredCode("123456", 300, "0");
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
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
        when(form.setAttribute(anyString(), any())).thenReturn(form);
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
        stubStoredCode("123456", -10, "0");
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(anyString())).thenReturn(formResponse);

        authenticator.action(context);

        ArgumentCaptor<String> hashCaptor = ArgumentCaptor.forClass(String.class);
        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_CODE_HASH), hashCaptor.capture());
        assertThat(hashCaptor.getValue(), notNullValue());
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
        stubStoredCode("123456", 300, "3");
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
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
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.authenticate(context);

        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_CODE_HASH), anyString());
        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_CODE_SALT), anyString());
        verify(emailProvider).send(anyString(), anyString(), any());
    }

    @Test
    void authenticate_refreshWithExistingValidCode_doesNotResend() throws Exception {
        setupCommonMocks();
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE_HASH)).thenReturn("any-hash");
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_CODE_SALT)).thenReturn("any-salt");
        when(authSession.getAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY))
                .thenReturn(String.valueOf(Time.currentTime() + 200));

        authenticator.authenticate(context);

        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(singleUseStore, never()).putIfAbsent(anyString(), anyLong());
        verify(context).challenge(formResponse);
    }

    @Test
    void authenticate_freshSessionHonorsActiveThrottle() throws Exception {
        // Initial send for a brand-new auth session is also throttled — defends against
        // OTP spam via rapid session restarts. With no stashed code available, the form is
        // still rendered so the corrupt-state path can later recover.
        setupCommonMocks();
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(false);
        when(singleUseStore.get(anyString())).thenReturn(null);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.authenticate(context);

        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(authSession, never()).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_CODE_HASH), anyString());
        verify(context).challenge(formResponse);
    }

    @Test
    void authenticate_freshSessionWithStashedCode_recoversCodeIntoSession() throws Exception {
        // When the cooldown is active AND a recently-sent code's hash/salt is stashed in the
        // throttle store, a fresh auth session must recover that state so the user who
        // legitimately restarted their login can still complete it with the code they
        // already received.
        setupCommonMocks();
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(false);
        int stashedExpiry = Time.currentTime() + 200;
        Map<String, String> stashedMeta = new HashMap<>();
        stashedMeta.put("expiresAt", String.valueOf(Time.currentTime() + 30));
        stashedMeta.put("codeHash", "stashed-hash");
        stashedMeta.put("codeSalt", "stashed-salt");
        stashedMeta.put("codeExpiresAt", String.valueOf(stashedExpiry));
        when(singleUseStore.get(anyString())).thenReturn(stashedMeta);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.authenticate(context);

        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(authSession).setAuthNote(EmailOtpConst.AUTH_NOTE_CODE_HASH, "stashed-hash");
        verify(authSession).setAuthNote(EmailOtpConst.AUTH_NOTE_CODE_SALT, "stashed-salt");
        verify(authSession).setAuthNote(EmailOtpConst.AUTH_NOTE_EXPIRY, String.valueOf(stashedExpiry));
        verify(authSession).setAuthNote(EmailOtpConst.AUTH_NOTE_ATTEMPTS, "0");
        verify(context).challenge(formResponse);
    }

    @Test
    void action_resendParamWhenAllowed_generatesAndSendsNewCode() throws Exception {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(EmailOtpConst.PARAM_RESEND, "true");

        setupCommonMocks();
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.action(context);

        verify(authSession).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_CODE_HASH), anyString());
        verify(emailProvider).send(eq(EmailOtpConst.EMAIL_SUBJECT_KEY), eq(EmailOtpConst.EMAIL_TEMPLATE), any());
        verify(context).challenge(formResponse);
    }

    @Test
    void action_resendParamWhenThrottled_doesNotSend() throws Exception {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(EmailOtpConst.PARAM_RESEND, "true");

        setupCommonMocks();
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(false);
        when(singleUseStore.get(anyString())).thenReturn(null);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.action(context);

        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(authSession, never()).setAuthNote(eq(EmailOtpConst.AUTH_NOTE_CODE_HASH), anyString());
        verify(context).challenge(formResponse);
    }

    @Test
    void requiresUser_returnsTrue() {
        assertThat(authenticator.requiresUser(), equalTo(true));
    }

    @Test
    void configuredFor_userWithVerifiedEmail_returnsTrue() {
        when(user.getEmail()).thenReturn("test@example.com");
        when(user.isEmailVerified()).thenReturn(true);
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(true));
    }

    @Test
    void configuredFor_userWithUnverifiedEmail_returnsFalseByDefault() {
        // SEC-003: unverified email is rejected unless emailOtp.requireVerifiedEmail=false
        when(user.getEmail()).thenReturn("test@example.com");
        when(user.isEmailVerified()).thenReturn(false);
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(false));
    }

    @Test
    void configuredFor_unverifiedEmailAllowedWhenRequireVerifiedFalse() {
        when(realm.getAttribute(EmailOtpConst.CONFIG_REQUIRE_VERIFIED_EMAIL)).thenReturn("false");
        when(user.getEmail()).thenReturn("test@example.com");
        when(user.isEmailVerified()).thenReturn(false);
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(true));
    }

    @Test
    void configuredFor_userWithoutEmail_returnsFalse() {
        when(user.getEmail()).thenReturn(null);
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(false));
    }
}
