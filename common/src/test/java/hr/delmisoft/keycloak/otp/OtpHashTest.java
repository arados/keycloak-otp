package hr.delmisoft.keycloak.otp;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;

class OtpHashTest {

    @Test
    void newSalt_returnsDistinctValues() {
        String a = OtpHash.newSalt();
        String b = OtpHash.newSalt();
        assertThat(a, notNullValue());
        assertThat(b, notNullValue());
        assertThat(a, not(equalTo(b)));
    }

    @Test
    void hash_isDeterministicForSameInputs() {
        String salt = OtpHash.newSalt();
        assertThat(OtpHash.hash("123456", salt), equalTo(OtpHash.hash("123456", salt)));
    }

    @Test
    void hash_differsForDifferentSalts() {
        String hash1 = OtpHash.hash("123456", OtpHash.newSalt());
        String hash2 = OtpHash.hash("123456", OtpHash.newSalt());
        assertThat(hash1, not(equalTo(hash2)));
    }

    @Test
    void verify_correctCodeReturnsTrue() {
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash("123456", salt);
        assertThat(OtpHash.verify("123456", hash, salt), equalTo(true));
    }

    @Test
    void verify_wrongCodeReturnsFalse() {
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash("123456", salt);
        assertThat(OtpHash.verify("999999", hash, salt), equalTo(false));
    }

    @Test
    void verify_wrongSaltReturnsFalse() {
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash("123456", salt);
        assertThat(OtpHash.verify("123456", hash, OtpHash.newSalt()), equalTo(false));
    }

    @Test
    void verify_nullInputsReturnFalse() {
        String salt = OtpHash.newSalt();
        String hash = OtpHash.hash("123456", salt);
        assertThat(OtpHash.verify(null, hash, salt), equalTo(false));
        assertThat(OtpHash.verify("123456", null, salt), equalTo(false));
        assertThat(OtpHash.verify("123456", hash, null), equalTo(false));
    }
}
