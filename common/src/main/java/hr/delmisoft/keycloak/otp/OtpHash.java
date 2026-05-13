package hr.delmisoft.keycloak.otp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Salted SHA-256 hashing for OTP codes.
 *
 * <p>Used so that the server-side state (auth-session notes, {@code SingleUseObjectProvider}
 * records, and the {@link OtpSendThrottle} stash) never holds the OTP in plaintext. The hash
 * alone is not a cryptographic secret — a 6-digit OTP can be brute-forced offline in
 * microseconds — but storing the hash plus a per-entry random salt prevents casual exposure
 * via debug logs, support dumps, or cache inspection, which is the realistic threat for
 * short-lived OTPs.
 */
public final class OtpHash {

    private static final SecureRandom SALT_RANDOM = new SecureRandom();
    private static final int SALT_BYTES = 16;

    private OtpHash() {}

    /** Generates a fresh base64-encoded salt suitable for one OTP hash. */
    public static String newSalt() {
        byte[] bytes = new byte[SALT_BYTES];
        SALT_RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    /** Returns the base64-encoded SHA-256 digest of {@code salt || code}. */
    public static String hash(String code, String salt) {
        if (code == null || salt == null) {
            throw new IllegalArgumentException("code and salt must be non-null");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(Base64.getDecoder().decode(salt));
            byte[] digest = md.digest(code.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory in every JRE.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /**
     * Constant-time comparison of {@code submittedCode} hashed with {@code salt}
     * against {@code storedHash}. Returns {@code false} if any input is null.
     */
    public static boolean verify(String submittedCode, String storedHash, String salt) {
        if (submittedCode == null || storedHash == null || salt == null) {
            return false;
        }
        String computed;
        try {
            computed = hash(submittedCode, salt);
        } catch (IllegalArgumentException e) {
            return false;
        }
        return MessageDigest.isEqual(computed.getBytes(StandardCharsets.UTF_8),
                storedHash.getBytes(StandardCharsets.UTF_8));
    }
}
