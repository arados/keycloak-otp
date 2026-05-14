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
import org.keycloak.common.util.Time;
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

import hr.delmisoft.keycloak.otp.OtpHash;

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
class SmsOtpAuthenticatorTest {

    private SmsOtpAuthenticator authenticator;

    @Mock private AuthenticationFlowContext context;
    @Mock private KeycloakSession session;
    @Mock private RealmModel realm;
    @Mock private UserModel user;
    @Mock private AuthenticationSessionModel authSession;
    @Mock private SmsProvider smsProvider;
    @Mock private LoginFormsProvider form;
    @Mock private HttpRequest httpRequest;
    @Mock private AuthenticatorConfigModel authenticatorConfig;
    @Mock private Response formResponse;
    @Mock private SingleUseObjectProvider singleUseStore;

    @BeforeEach
    void setUp() {
        authenticator = new SmsOtpAuthenticator();
    }

    private void setupCommonMocks() {
        when(context.getSession()).thenReturn(session);
        when(context.getRealm()).thenReturn(realm);
        when(context.getUser()).thenReturn(user);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn("+1234567890");
        when(session.getProvider(SmsProvider.class)).thenReturn(smsProvider);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUseStore);
        when(realm.getId()).thenReturn("realm-1");
        when(user.getId()).thenReturn("user-1");
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(true);
    }

    private void stubStoredCode(String plainCode, int secondsUntilExpiry, String attempts) {
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash(plainCode, salt);
        when(authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_CODE_HASH)).thenReturn(hash);
        when(authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_CODE_SALT)).thenReturn(salt);
        when(authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY))
                .thenReturn(String.valueOf(Time.currentTime() + secondsUntilExpiry));
        when(authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS)).thenReturn(attempts);
    }

    @Test
    void authenticate_sendsSmsAndChallenge() throws Exception {
        setupCommonMocks();
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(SmsOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.authenticate(context);

        verify(authSession).setAuthNote(eq(SmsOtpConst.AUTH_NOTE_CODE_HASH), anyString());
        verify(authSession).setAuthNote(eq(SmsOtpConst.AUTH_NOTE_CODE_SALT), anyString());
        verify(authSession).setAuthNote(eq(SmsOtpConst.AUTH_NOTE_EXPIRY), anyString());
        verify(authSession).setAuthNote(eq(SmsOtpConst.AUTH_NOTE_ATTEMPTS), eq("0"));
        verify(smsProvider).send(eq("+1234567890"), anyString());
        verify(context).challenge(formResponse);
    }

    @Test
    void authenticate_smsFailure_returnsError() throws Exception {
        setupCommonMocks();
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createErrorPage(any())).thenReturn(formResponse);
        doThrow(new SmsException("fail")).when(smsProvider).send(anyString(), anyString());

        authenticator.authenticate(context);

        verify(context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), any());
        verify(context, never()).challenge(any());
        // REL-001: throttle rolled back (release removes both key and key:meta entries) so the
        // user is not locked out by a cooldown protecting an undelivered code; auth notes also cleared.
        verify(singleUseStore, org.mockito.Mockito.times(2)).remove(anyString());
        verify(authSession).removeAuthNote(SmsOtpConst.AUTH_NOTE_CODE_HASH);
    }

    @Test
    void authenticate_noPhoneNumber_fails() {
        setupCommonMocks();
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn(null);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createErrorPage(any())).thenReturn(formResponse);

        authenticator.authenticate(context);

        verify(context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), any());
    }

    @Test
    void action_validCode_succeeds() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(SmsOtpConst.PARAM_OTP, "123456");

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
        formParams.putSingle(SmsOtpConst.PARAM_OTP, "999999");

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

        verify(authSession).setAuthNote(SmsOtpConst.AUTH_NOTE_ATTEMPTS, "1");
        verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
        verify(context, never()).success();
    }

    @Test
    void action_emptyOtp_fails() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(SmsOtpConst.PARAM_OTP, "");

        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(anyString())).thenReturn(formResponse);

        authenticator.action(context);

        verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
    }

    @Test
    void action_expiredCode_resendsAndFails() throws Exception {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(SmsOtpConst.PARAM_OTP, "123456");

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
        verify(authSession).setAuthNote(eq(SmsOtpConst.AUTH_NOTE_CODE_HASH), hashCaptor.capture());
        assertThat(hashCaptor.getValue(), notNullValue());
        verify(smsProvider).send(eq("+1234567890"), anyString());
        verify(context).failureChallenge(eq(AuthenticationFlowError.EXPIRED_CODE), any());
    }

    @Test
    void action_maxRetriesExceeded_fails() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(SmsOtpConst.PARAM_OTP, "999999");

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
        verify(form).setError(SmsOtpConst.ERROR_OTP_MAX_RETRIES);
    }

    @Test
    void authenticate_withCustomConfig() throws Exception {
        setupCommonMocks();
        Map<String, String> config = new HashMap<>();
        config.put(SmsOtpConst.CONFIG_CODE_LENGTH, "8");
        config.put(SmsOtpConst.CONFIG_TTL, "600");
        when(authenticatorConfig.getConfig()).thenReturn(config);
        when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(SmsOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.authenticate(context);

        // Custom code-length config is honored — verify a hash was written (the underlying
        // plaintext is unobservable now, but the length config feeds into hash generation).
        verify(authSession).setAuthNote(eq(SmsOtpConst.AUTH_NOTE_CODE_HASH), anyString());
        verify(authSession).setAuthNote(eq(SmsOtpConst.AUTH_NOTE_CODE_SALT), anyString());
        verify(smsProvider).send(eq("+1234567890"), anyString());
    }

    @Test
    void authenticate_honorsRealmLevelPhoneAttribute() throws Exception {
        // CFG-001: phone attribute is now resolved exclusively from the realm-level
        // `smsOtp.phoneAttribute`, ensuring eligibility (configuredFor) and delivery
        // read the same user attribute.
        setupCommonMocks();
        when(realm.getAttribute(SmsOtpConst.CONFIG_PHONE_ATTRIBUTE)).thenReturn("mobile");
        when(user.getFirstAttribute("mobile")).thenReturn("+9876543210");
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(SmsOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.authenticate(context);

        verify(smsProvider).send(eq("+9876543210"), anyString());
    }

    @Test
    void authenticate_refreshWithExistingValidCode_doesNotResend() throws Exception {
        setupCommonMocks();
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(SmsOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);
        when(authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_CODE_HASH)).thenReturn("any-hash");
        when(authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_CODE_SALT)).thenReturn("any-salt");
        when(authSession.getAuthNote(SmsOtpConst.AUTH_NOTE_EXPIRY))
                .thenReturn(String.valueOf(Time.currentTime() + 200));

        authenticator.authenticate(context);

        verify(smsProvider, never()).send(anyString(), anyString());
        verify(singleUseStore, never()).putIfAbsent(anyString(), anyLong());
        verify(context).challenge(formResponse);
    }

    @Test
    void authenticate_freshSessionHonorsActiveThrottle() throws Exception {
        // Initial send for a brand-new auth session is also throttled to prevent OTP spam.
        // No stash present (store.get returns null) so the session stays empty.
        setupCommonMocks();
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(false);
        when(singleUseStore.get(anyString())).thenReturn(null);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(SmsOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.authenticate(context);

        verify(smsProvider, never()).send(anyString(), anyString());
        verify(authSession, never()).setAuthNote(eq(SmsOtpConst.AUTH_NOTE_CODE_HASH), anyString());
        verify(context).challenge(formResponse);
    }

    @Test
    void action_resendParamWhenAllowed_generatesAndSendsNewCode() throws Exception {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(SmsOtpConst.PARAM_RESEND, "true");

        setupCommonMocks();
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(SmsOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.action(context);

        verify(authSession).setAuthNote(eq(SmsOtpConst.AUTH_NOTE_CODE_HASH), anyString());
        verify(smsProvider).send(eq("+1234567890"), anyString());
        verify(context).challenge(formResponse);
    }

    @Test
    void action_resendParamWhenThrottled_doesNotSend() throws Exception {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(SmsOtpConst.PARAM_RESEND, "true");

        setupCommonMocks();
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(false);
        when(singleUseStore.get(anyString())).thenReturn(null);
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(SmsOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.action(context);

        verify(smsProvider, never()).send(anyString(), anyString());
        verify(authSession, never()).setAuthNote(eq(SmsOtpConst.AUTH_NOTE_CODE_HASH), anyString());
        verify(context).challenge(formResponse);
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
    void configuredFor_requireVerifiedPhone_rejectsUnverified() {
        when(realm.getAttribute(SmsOtpConst.CONFIG_REQUIRE_VERIFIED_PHONE)).thenReturn("true");
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn("+1234567890");
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_VERIFIED_PHONE_ATTRIBUTE)).thenReturn(null);
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(false));
    }

    @Test
    void configuredFor_requireVerifiedPhone_acceptsVerified() {
        when(realm.getAttribute(SmsOtpConst.CONFIG_REQUIRE_VERIFIED_PHONE)).thenReturn("true");
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn("+1234567890");
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_VERIFIED_PHONE_ATTRIBUTE)).thenReturn("true");
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(true));
    }
}
