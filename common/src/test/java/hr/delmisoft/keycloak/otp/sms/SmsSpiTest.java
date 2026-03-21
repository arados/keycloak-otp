package hr.delmisoft.keycloak.otp.sms;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

class SmsSpiTest {

    private final SmsSpi spi = new SmsSpi();

    @Test
    void getName_returnsSms() {
        assertThat(spi.getName(), equalTo("sms"));
    }

    @Test
    void isInternal_returnsFalse() {
        assertThat(spi.isInternal(), equalTo(false));
    }

    @Test
    void getProviderClass_returnsSmsProvider() {
        assertThat(spi.getProviderClass(), equalTo(SmsProvider.class));
    }

    @Test
    void getProviderFactoryClass_returnsSmsProviderFactory() {
        assertThat(spi.getProviderFactoryClass(), equalTo(SmsProviderFactory.class));
    }
}
