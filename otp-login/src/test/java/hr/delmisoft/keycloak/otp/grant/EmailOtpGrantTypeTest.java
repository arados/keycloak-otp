package hr.delmisoft.keycloak.otp.grant;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.core.MultivaluedHashMap;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Channel-specific tests for {@link EmailOtpGrantType}: the verification predicate, the email
 * delivery shape, and the protocol-error strings. Flow-control behavior is covered in
 * {@link AbstractOtpGrantTypeTest}.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class EmailOtpGrantTypeTest {

    @Mock KeycloakSession session;
    @Mock RealmModel realm;
    @Mock UserModel user;
    @Mock EmailTemplateProvider emailProvider;
    @Mock EventBuilder event;

    private EmailOtpGrantType grant;

    @BeforeEach
    void setUp() {
        grant = new EmailOtpGrantType();
        // Phase-2 path reads the protected `realm` field directly via the channel-verification
        // helper, so wire that field for the predicate tests.
        OtpGrantTestSupport.injectMocks(grant, session, realm, null, null,
                new MultivaluedHashMap<>(), event, null, null);
        when(session.getProvider(EmailTemplateProvider.class)).thenReturn(emailProvider);
        when(emailProvider.setRealm(any())).thenReturn(emailProvider);
        when(emailProvider.setUser(any())).thenReturn(emailProvider);
    }

    @Test
    void isChannelVerified_nullEmail_returnsFalse() throws Exception {
        when(user.getEmail()).thenReturn(null);

        assertThat(invokeIsChannelVerified(grant, user), equalTo(false));
    }

    @Test
    void isChannelVerified_verifiedEmailWithDefaultPolicy_returnsTrue() throws Exception {
        when(user.getEmail()).thenReturn("alice@example.com");
        when(user.isEmailVerified()).thenReturn(true);
        when(realm.getAttribute("emailOtp.requireVerifiedEmail")).thenReturn(null); // default-on

        assertThat(invokeIsChannelVerified(grant, user), equalTo(true));
    }

    @Test
    void isChannelVerified_unverifiedEmailWithDefaultPolicy_returnsFalse() throws Exception {
        // emailOtp.requireVerifiedEmail defaults to true, so unverified must be rejected
        // even when the realm has no explicit attribute set.
        when(user.getEmail()).thenReturn("alice@example.com");
        when(user.isEmailVerified()).thenReturn(false);
        when(realm.getAttribute("emailOtp.requireVerifiedEmail")).thenReturn(null);

        assertThat(invokeIsChannelVerified(grant, user), equalTo(false));
    }

    @Test
    void isChannelVerified_unverifiedEmailWithPolicyOptedOut_returnsTrue() throws Exception {
        // Operator can disable the verification requirement; the predicate must honor that.
        when(user.getEmail()).thenReturn("alice@example.com");
        when(user.isEmailVerified()).thenReturn(false);
        when(realm.getAttribute("emailOtp.requireVerifiedEmail")).thenReturn("false");

        assertThat(invokeIsChannelVerified(grant, user), equalTo(true));
    }

    @Test
    void sendOtp_invokesEmailTemplateProviderWithCode() throws Exception {
        Method sendOtp = AbstractOtpGrantType.class.getDeclaredMethod("sendOtp", UserModel.class, String.class);
        sendOtp.setAccessible(true);
        sendOtp.invoke(grant, user, "987654");

        // The map passed to send() must carry the raw code under the "code" key so the
        // template can render it; if this assertion ever changes, the email template
        // (themes/email/.../otp-code.ftl) must change in lockstep.
        Map<String, Object> expected = new HashMap<>();
        expected.put("code", "987654");
        verify(emailProvider).setRealm(realm);
        verify(emailProvider).setUser(user);
        verify(emailProvider).send(eq("emailOtpSubject"), eq("email-otp-code.ftl"), eq(expected));
    }

    @Test
    void getOtpRequiredError_returnsEmailOtpRequired() throws Exception {
        assertThat(invokeProtectedString(grant, "getOtpRequiredError"), equalTo("email_otp_required"));
    }

    @Test
    void getChannel_returnsEmailThrottleChannel() throws Exception {
        assertThat(invokeProtectedString(grant, "getChannel"), equalTo("email"));
    }

    private static boolean invokeIsChannelVerified(AbstractOtpGrantType grant, UserModel user) throws Exception {
        Method m = AbstractOtpGrantType.class.getDeclaredMethod("isChannelVerified", UserModel.class);
        m.setAccessible(true);
        return (boolean) m.invoke(grant, user);
    }

    private static String invokeProtectedString(AbstractOtpGrantType grant, String name) throws Exception {
        Method m = AbstractOtpGrantType.class.getDeclaredMethod(name);
        m.setAccessible(true);
        return (String) m.invoke(grant);
    }
}
