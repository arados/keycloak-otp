package hr.delmisoft.keycloak.otp.grant;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import jakarta.ws.rs.core.MultivaluedHashMap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import hr.delmisoft.keycloak.otp.sms.SmsException;
import hr.delmisoft.keycloak.otp.sms.SmsProvider;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Channel-specific tests for {@link SmsOtpGrantType}: phone-number resolution, SMS dispatch,
 * and the SMS-specific verification predicate. Flow-control behavior is covered in
 * {@link AbstractOtpGrantTypeTest}.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmsOtpGrantTypeTest {

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock UserModel user;
    @Mock SmsProvider smsProvider;
    @Mock EventBuilder event;

    private SmsOtpGrantType grant;

    @BeforeEach
    void setUp() {
        grant = new SmsOtpGrantType();
        OtpGrantTestSupport.injectMocks(grant, session, realm, null, null,
                new MultivaluedHashMap<>(), event, null, null);
        when(session.getProvider(SmsProvider.class)).thenReturn(smsProvider);
    }

    @Test
    void isChannelVerified_noPhoneAttribute_returnsFalse() throws Exception {
        when(realm.getAttribute("smsOtp.phoneAttribute")).thenReturn(null); // default `phoneNumber`
        when(user.getFirstAttribute("phoneNumber")).thenReturn(null);

        assertThat(invokeIsChannelVerified(grant, user), equalTo(false));
    }

    @Test
    void isChannelVerified_hasPhoneAndPolicyDefaultsOff_returnsTrue() throws Exception {
        // smsOtp.requireVerifiedPhone defaults to false (no Keycloak-native phone verification),
        // so having any phone attribute value is sufficient unless the realm opts in.
        when(realm.getAttribute("smsOtp.phoneAttribute")).thenReturn(null);
        when(user.getFirstAttribute("phoneNumber")).thenReturn("+1234567890");
        when(realm.getAttribute("smsOtp.requireVerifiedPhone")).thenReturn(null);

        assertThat(invokeIsChannelVerified(grant, user), equalTo(true));
    }

    @Test
    void isChannelVerified_requireVerifiedPhoneEnabledButFlagAttributeMissing_returnsFalse() throws Exception {
        when(realm.getAttribute("smsOtp.phoneAttribute")).thenReturn(null);
        when(user.getFirstAttribute("phoneNumber")).thenReturn("+1234567890");
        when(realm.getAttribute("smsOtp.requireVerifiedPhone")).thenReturn("true");
        when(realm.getAttribute("smsOtp.verifiedPhoneAttribute")).thenReturn(null);
        when(user.getFirstAttribute("phoneNumberVerified")).thenReturn(null);

        assertThat(invokeIsChannelVerified(grant, user), equalTo(false));
    }

    @Test
    void isChannelVerified_requireVerifiedPhoneEnabledAndFlagTrue_returnsTrue() throws Exception {
        when(realm.getAttribute("smsOtp.phoneAttribute")).thenReturn(null);
        when(user.getFirstAttribute("phoneNumber")).thenReturn("+1234567890");
        when(realm.getAttribute("smsOtp.requireVerifiedPhone")).thenReturn("true");
        when(realm.getAttribute("smsOtp.verifiedPhoneAttribute")).thenReturn(null);
        when(user.getFirstAttribute("phoneNumberVerified")).thenReturn("true");

        assertThat(invokeIsChannelVerified(grant, user), equalTo(true));
    }

    @Test
    void isChannelVerified_customVerifiedAttributeName_isHonored() throws Exception {
        when(realm.getAttribute("smsOtp.phoneAttribute")).thenReturn(null);
        when(user.getFirstAttribute("phoneNumber")).thenReturn("+1234567890");
        when(realm.getAttribute("smsOtp.requireVerifiedPhone")).thenReturn("true");
        when(realm.getAttribute("smsOtp.verifiedPhoneAttribute")).thenReturn("mobile_verified");
        when(user.getFirstAttribute("mobile_verified")).thenReturn("true");

        assertThat(invokeIsChannelVerified(grant, user), equalTo(true));
    }

    @Test
    void sendOtp_sendsCodeToConfiguredPhoneNumber() throws Exception {
        when(realm.getAttribute("smsOtp.phoneAttribute")).thenReturn(null);
        when(user.getFirstAttribute("phoneNumber")).thenReturn("+1234567890");

        Method sendOtp = AbstractOtpGrantType.class.getDeclaredMethod("sendOtp", UserModel.class, String.class);
        sendOtp.setAccessible(true);
        sendOtp.invoke(grant, user, "123456");

        verify(smsProvider).send("+1234567890", "Your verification code is: 123456");
    }

    @Test
    void sendOtp_noPhoneNumber_throws() throws Exception {
        when(realm.getAttribute("smsOtp.phoneAttribute")).thenReturn(null);
        when(user.getFirstAttribute("phoneNumber")).thenReturn(null);

        Method sendOtp = AbstractOtpGrantType.class.getDeclaredMethod("sendOtp", UserModel.class, String.class);
        sendOtp.setAccessible(true);

        InvocationTargetException ex = org.junit.jupiter.api.Assertions.assertThrows(
                InvocationTargetException.class, () -> sendOtp.invoke(grant, user, "123456"));
        assertThat(ex.getCause().getMessage(), containsString("no phone number"));
    }

    @Test
    void sendOtp_smsProviderThrows_propagatesException() throws Exception {
        when(realm.getAttribute("smsOtp.phoneAttribute")).thenReturn(null);
        when(user.getFirstAttribute("phoneNumber")).thenReturn("+1234567890");
        doThrow(new SmsException("twilio is down")).when(smsProvider).send(anyString(), anyString());

        Method sendOtp = AbstractOtpGrantType.class.getDeclaredMethod("sendOtp", UserModel.class, String.class);
        sendOtp.setAccessible(true);

        InvocationTargetException ex = org.junit.jupiter.api.Assertions.assertThrows(
                InvocationTargetException.class, () -> sendOtp.invoke(grant, user, "123456"));
        assertThat(ex.getCause(), org.hamcrest.Matchers.instanceOf(SmsException.class));
    }

    @Test
    void getOtpRequiredError_returnsSmsOtpRequired() throws Exception {
        Method m = AbstractOtpGrantType.class.getDeclaredMethod("getOtpRequiredError");
        m.setAccessible(true);
        assertThat((String) m.invoke(grant), equalTo("sms_otp_required"));
    }

    @Test
    void getChannel_returnsSmsThrottleChannel() throws Exception {
        Method m = AbstractOtpGrantType.class.getDeclaredMethod("getChannel");
        m.setAccessible(true);
        assertThat((String) m.invoke(grant), equalTo("sms"));
    }

    private static boolean invokeIsChannelVerified(AbstractOtpGrantType grant, UserModel user) throws Exception {
        Method m = AbstractOtpGrantType.class.getDeclaredMethod("isChannelVerified", UserModel.class);
        m.setAccessible(true);
        return (boolean) m.invoke(grant, user);
    }
}
