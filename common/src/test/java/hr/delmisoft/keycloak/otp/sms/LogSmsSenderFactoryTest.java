package hr.delmisoft.keycloak.otp.sms;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

class LogSmsSenderFactoryTest {

    private LogSmsSenderFactory factory;

    @BeforeEach
    void setUp() {
        factory = new LogSmsSenderFactory();
    }

    @Test
    void getId_returnsLog() {
        assertThat(factory.getId(), equalTo("log"));
    }

    @Test
    void create_returnsNonNull() {
        SmsProvider provider = factory.create(null);
        assertThat(provider, notNullValue());
    }

    @Test
    void send_doesNotThrow() throws Exception {
        SmsProvider provider = factory.create(null);
        provider.send("+1234567890", "Test message");
    }
}
