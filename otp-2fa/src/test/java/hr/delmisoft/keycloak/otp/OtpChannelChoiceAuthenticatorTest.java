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

import hr.delmisoft.keycloak.otp.sms.SmsException;
import hr.delmisoft.keycloak.otp.sms.SmsOtpConst;
import hr.delmisoft.keycloak.otp.sms.SmsProvider;
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
class OtpChannelChoiceAuthenticatorTest {

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
    @Mock private AuthenticatorConfigModel authenticatorConfig;
    @Mock private Response formResponse;
    @Mock private SingleUseObjectProvider singleUseStore;

    @BeforeEach
    void setUp() {
        authenticator = new OtpChannelChoiceAuthenticator();
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
        when(session.getProvider(SmsProvider.class)).thenReturn(smsProvider);
        when(session.getProvider(SingleUseObjectProvider.class)).thenReturn(singleUseStore);
        when(realm.getId()).thenReturn("realm-1");
        when(user.getId()).thenReturn("user-1");
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(true);
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn("+1234567890");
        // Both channels are usable by default — individual tests can opt out by overriding
        // these stubs (e.g. to verify SEC-001 enforcement when a channel is unverified).
        when(user.getEmail()).thenReturn("test@example.com");
        when(user.isEmailVerified()).thenReturn(true);
    }

    private void stubStoredCode(String channel, String plainCode, int secondsUntilExpiry, String attempts) {
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash(plainCode, salt);
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL)).thenReturn(channel);
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_HASH)).thenReturn(hash);
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_SALT)).thenReturn(salt);
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_EXPIRY))
                .thenReturn(String.valueOf(Time.currentTime() + secondsUntilExpiry));
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_ATTEMPTS)).thenReturn(attempts);
    }

    // --- authenticate() ---

    @Test
    void authenticate_showsChannelSelectionForm() {
        setupCommonMocks();
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(OtpChannelChoiceAuthenticator.TEMPLATE_CHANNEL_SELECT)).thenReturn(formResponse);

        authenticator.authenticate(context);

        // Both channels usable by default — both `emailAllowed` and `smsAllowed` propagate
        // to the template so the FTL renders the corresponding buttons.
        verify(form).setAttribute("emailAllowed", true);
        verify(form).setAttribute("smsAllowed", true);
        verify(context).challenge(formResponse);
    }

    @Test
    void authenticate_unverifiedEmail_hidesEmailButton() {
        // SEC-001: with `emailOtp.requireVerifiedEmail` defaulted to true, a user whose
        // email is unverified must not see the Email channel button on the selection screen.
        setupCommonMocks();
        when(user.isEmailVerified()).thenReturn(false);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(OtpChannelChoiceAuthenticator.TEMPLATE_CHANNEL_SELECT)).thenReturn(formResponse);

        authenticator.authenticate(context);

        verify(form).setAttribute("emailAllowed", false);
        verify(form).setAttribute("smsAllowed", true);
    }

    @Test
    void action_selectUnverifiedEmail_rejectsAndDoesNotSend() throws Exception {
        // SEC-001: even if the client crafts a POST with channel=email, the server must
        // re-check the per-channel verification policy before sending. Mirrors what the
        // template-level filter already does for honest clients.
        setupCommonMocks();
        when(user.isEmailVerified()).thenReturn(false);
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "email");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(OtpChannelChoiceAuthenticator.TEMPLATE_CHANNEL_SELECT)).thenReturn(formResponse);

        authenticator.action(context);

        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(authSession, never()).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL), anyString());
        verify(form).setError("otpChannelInvalid");
        verify(context).challenge(formResponse);
    }

    // --- Channel selection (phase 1) ---

    @Test
    void action_selectEmail_sendsEmailAndShowsOtpForm() throws Exception {
        setupCommonMocks();
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "email");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.action(context);

        verify(authSession).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL), eq("email"));
        verify(authSession).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_HASH), anyString());
        verify(authSession).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_EXPIRY), anyString());
        verify(authSession).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_ATTEMPTS), eq("0"));
        verify(emailProvider).send(eq(EmailOtpConst.EMAIL_SUBJECT_KEY), eq(EmailOtpConst.EMAIL_TEMPLATE), any());
        verify(context).challenge(formResponse);
    }

    @Test
    void action_selectSms_sendsSmsAndShowsOtpForm() throws Exception {
        setupCommonMocks();
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "sms");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(SmsOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.action(context);

        verify(authSession).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL), eq("sms"));
        verify(smsProvider).send(eq("+1234567890"), anyString());
        verify(context).challenge(formResponse);
    }

    @Test
    void action_invalidChannel_showsSelectionWithError() {
        setupCommonMocks();
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "invalid");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(OtpChannelChoiceAuthenticator.TEMPLATE_CHANNEL_SELECT)).thenReturn(formResponse);

        authenticator.action(context);

        verify(form).setError("otpChannelInvalid");
        verify(context).challenge(formResponse);
    }

    @Test
    void action_emailSendFailure_returnsError() throws Exception {
        setupCommonMocks();
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "email");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createErrorPage(any())).thenReturn(formResponse);
        doThrow(new EmailException("fail")).when(emailProvider).send(anyString(), anyString(), any());

        authenticator.action(context);

        verify(context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), any());
    }

    @Test
    void action_smsSendFailure_returnsError() throws Exception {
        setupCommonMocks();
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "sms");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createErrorPage(any())).thenReturn(formResponse);
        doThrow(new SmsException("fail")).when(smsProvider).send(anyString(), anyString());

        authenticator.action(context);

        verify(context).failureChallenge(eq(AuthenticationFlowError.INTERNAL_ERROR), any());
    }

    @Test
    void action_smsNoPhoneNumber_rejectsChannelSelection() throws Exception {
        // SEC-001: a hostile client could POST channel=sms even though the FTL hid the
        // SMS button (because the user has no phone attribute). The server must reject
        // *before* attempting to send, not fall through to a delivery-time INTERNAL_ERROR.
        setupCommonMocks();
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn(null);
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "sms");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(OtpChannelChoiceAuthenticator.TEMPLATE_CHANNEL_SELECT)).thenReturn(formResponse);

        authenticator.action(context);

        verify(smsProvider, never()).send(anyString(), anyString());
        verify(authSession, never()).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL), anyString());
        verify(form).setError("otpChannelInvalid");
        verify(context).challenge(formResponse);
    }

    // --- OTP verification (phase 2) ---

    @Test
    void action_validEmailOtp_succeeds() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_OTP, "123456");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        stubStoredCode("email", "123456", 300, "0");

        authenticator.action(context);

        verify(context).success();
    }

    @Test
    void action_validSmsOtp_succeeds() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_OTP, "654321");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        stubStoredCode("sms", "654321", 300, "0");

        authenticator.action(context);

        verify(context).success();
    }

    @Test
    void action_invalidOtp_incrementsAttemptsAndFails() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_OTP, "999999");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        stubStoredCode("email", "123456", 300, "0");
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(anyString())).thenReturn(formResponse);

        authenticator.action(context);

        verify(authSession).setAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_ATTEMPTS, "1");
        verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
        verify(context, never()).success();
    }

    @Test
    void action_emptyOtp_fails() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_OTP, "");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL)).thenReturn("email");
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(anyString())).thenReturn(formResponse);

        authenticator.action(context);

        verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
        verify(context, never()).success();
    }

    @Test
    void action_expiredOtp_resendsCodeViaEmail() throws Exception {
        setupCommonMocks();
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_OTP, "123456");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        stubStoredCode("email", "123456", -10, "0");
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(anyString())).thenReturn(formResponse);

        authenticator.action(context);

        verify(emailProvider).send(eq(EmailOtpConst.EMAIL_SUBJECT_KEY), eq(EmailOtpConst.EMAIL_TEMPLATE), any());
        verify(context).failureChallenge(eq(AuthenticationFlowError.EXPIRED_CODE), any());
    }

    @Test
    void action_expiredOtp_resendsCodeViaSms() throws Exception {
        setupCommonMocks();
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_OTP, "123456");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        stubStoredCode("sms", "123456", -10, "0");
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(anyString())).thenReturn(formResponse);

        authenticator.action(context);

        verify(smsProvider).send(eq("+1234567890"), anyString());
        verify(context).failureChallenge(eq(AuthenticationFlowError.EXPIRED_CODE), any());
    }

    @Test
    void action_maxRetriesExceeded_fails() {
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_OTP, "999999");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getAuthenticatorConfig()).thenReturn(null);
        stubStoredCode("sms", "123456", 300, "3");
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.setError(anyString())).thenReturn(form);
        when(form.createForm(anyString())).thenReturn(formResponse);

        authenticator.action(context);

        verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any());
        verify(form).setError(SmsOtpConst.ERROR_OTP_MAX_RETRIES);
    }

    @Test
    void action_missingSessionState_restartsChannelSelection() {
        setupCommonMocks();
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_OTP, "123456");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL)).thenReturn("email");
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_HASH)).thenReturn(null);
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_SALT)).thenReturn(null);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(OtpChannelChoiceAuthenticator.TEMPLATE_CHANNEL_SELECT)).thenReturn(formResponse);

        authenticator.action(context);

        verify(authSession).removeAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL);
        verify(context).challenge(formResponse);
    }

    // --- Browser back button scenarios ---

    @Test
    void action_browserBack_reselectDifferentChannel_sendsNewOtp() throws Exception {
        // User selected email, got OTP form, pressed back, now selects SMS
        setupCommonMocks();
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "sms");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(SmsOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);
        // Existing channel note from previous selection
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL)).thenReturn("email");

        authenticator.action(context);

        // Old state should be cleared
        verify(authSession).removeAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_HASH);
        verify(authSession).removeAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_SALT);
        verify(authSession).removeAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_EXPIRY);
        verify(authSession).removeAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_ATTEMPTS);
        // New channel should be set
        verify(authSession).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL), eq("sms"));
        verify(authSession).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_HASH), anyString());
        // SMS should be sent (not email)
        verify(smsProvider).send(eq("+1234567890"), anyString());
        verify(context).challenge(formResponse);
    }

    @Test
    void action_browserBack_reselectSameChannel_sendsNewOtp() throws Exception {
        // User selected email, got OTP form, pressed back, selects email again
        setupCommonMocks();
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "email");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);
        // Existing channel note from previous selection
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL)).thenReturn("email");

        authenticator.action(context);

        // Old state should be cleared and new code generated
        verify(authSession).removeAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_HASH);
        verify(authSession).removeAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_SALT);
        verify(authSession).removeAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_EXPIRY);
        verify(authSession).removeAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_ATTEMPTS);
        verify(authSession).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL), eq("email"));
        verify(emailProvider).send(eq(EmailOtpConst.EMAIL_SUBJECT_KEY), eq(EmailOtpConst.EMAIL_TEMPLATE), any());
        verify(context).challenge(formResponse);
    }

    // --- No channel param and no session state ---

    @Test
    void action_noChannelParamNoSessionState_restartsSelection() {
        setupCommonMocks();
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL)).thenReturn(null);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(OtpChannelChoiceAuthenticator.TEMPLATE_CHANNEL_SELECT)).thenReturn(formResponse);

        authenticator.action(context);

        verify(context).challenge(formResponse);
    }

    // --- Custom config ---

    // --- Throttle / resend ---

    @Test
    void action_selectEmailHonorsActiveThrottle() throws Exception {
        // Initial channel selection is also throttled — defends against OTP spam via
        // repeated channel-select restarts. Form is still rendered so the user can
        // enter the previously sent code.
        setupCommonMocks();
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(false);
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "email");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.action(context);

        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(authSession, never()).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_HASH), anyString());
        verify(context).challenge(formResponse);
    }

    @Test
    void action_resendParamWhenAllowed_resendsViaSelectedChannel() throws Exception {
        setupCommonMocks();
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_RESEND, "true");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL))
                .thenReturn(OtpChannelChoiceAuthenticator.CHANNEL_SMS);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(SmsOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.action(context);

        verify(smsProvider).send(eq("+1234567890"), anyString());
        verify(authSession).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_HASH), anyString());
        verify(context).challenge(formResponse);
    }

    @Test
    void action_resendParamWhenThrottled_doesNotSend() throws Exception {
        setupCommonMocks();
        when(singleUseStore.putIfAbsent(anyString(), anyLong())).thenReturn(false);
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_RESEND, "true");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(authSession.getAuthNote(OtpChannelChoiceAuthenticator.AUTH_NOTE_CHANNEL))
                .thenReturn(OtpChannelChoiceAuthenticator.CHANNEL_EMAIL);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.action(context);

        verify(emailProvider, never()).send(anyString(), anyString(), any());
        verify(context).challenge(formResponse);
    }

    @Test
    void action_selectEmailWithCustomConfig_honorsLengthAndTtl() throws Exception {
        // With hashed storage we can't observe the underlying code length directly. The TTL
        // however is reflected in AUTH_NOTE_EXPIRY = now + 600.
        setupCommonMocks();
        Map<String, String> config = new HashMap<>();
        config.put(OtpChannelChoiceConst.CONFIG_CODE_LENGTH, "8");
        config.put(OtpChannelChoiceConst.CONFIG_TTL, "600");
        when(authenticatorConfig.getConfig()).thenReturn(config);
        when(context.getAuthenticatorConfig()).thenReturn(authenticatorConfig);
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<>();
        formParams.putSingle(OtpChannelChoiceAuthenticator.PARAM_CHANNEL, "email");
        when(context.getHttpRequest()).thenReturn(httpRequest);
        when(httpRequest.getDecodedFormParameters()).thenReturn(formParams);
        when(context.form()).thenReturn(form);
        when(form.setAttribute(anyString(), any())).thenReturn(form);
        when(form.createForm(EmailOtpConst.LOGIN_TEMPLATE)).thenReturn(formResponse);

        authenticator.action(context);

        verify(authSession).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_HASH), anyString());
        verify(authSession).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_CODE_SALT), anyString());
        ArgumentCaptor<String> expiryCaptor = ArgumentCaptor.forClass(String.class);
        verify(authSession).setAuthNote(eq(OtpChannelChoiceAuthenticator.AUTH_NOTE_EXPIRY), expiryCaptor.capture());
        int expiry = Integer.parseInt(expiryCaptor.getValue());
        int now = Time.currentTime();
        assertThat(expiry >= now + 595 && expiry <= now + 605, equalTo(true));
    }

    // --- configuredFor / requiresUser ---

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
    void configuredFor_userWithPhone_returnsTrue() {
        // SMS is usable when phone attribute is present; verified-phone gate is off by default.
        when(user.getEmail()).thenReturn(null);
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn("+1234567890");
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(true));
    }

    @Test
    void configuredFor_userWithNeither_returnsFalse() {
        when(user.getEmail()).thenReturn(null);
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn(null);
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(false));
    }

    @Test
    void configuredFor_userWithUnverifiedEmailAndNoPhone_returnsFalse() {
        // SEC-003: unverified email is rejected by default, and no phone means SMS path is out too.
        when(user.getEmail()).thenReturn("test@example.com");
        when(user.isEmailVerified()).thenReturn(false);
        when(user.getFirstAttribute(SmsOtpConst.DEFAULT_PHONE_ATTRIBUTE)).thenReturn(null);
        assertThat(authenticator.configuredFor(session, realm, user), equalTo(false));
    }
}
