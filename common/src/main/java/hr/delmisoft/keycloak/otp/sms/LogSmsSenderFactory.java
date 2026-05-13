package hr.delmisoft.keycloak.otp.sms;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Development-only SMS provider that logs a redacted notice instead of sending an SMS.
 *
 * <p>This is the default SPI implementation so the plugin works out of the box without a
 * real gateway. The OTP code is <strong>not</strong> written to the log — only the channel,
 * a partially masked destination number, and the OTP length, so this provider can ship as
 * the default without leaking live codes if it accidentally runs in production. For local
 * development, set {@code -Dkeycloak.otp.logSms.unsafe=true} (or env
 * {@code KEYCLOAK_OTP_LOG_SMS_UNSAFE=true}) to log the full message; the provider prints a
 * startup warning when that escape hatch is enabled.
 *
 * <p>Production deployments must replace this with a real SMS provider (see README).
 */
public class LogSmsSenderFactory implements SmsProviderFactory {

    private static final Logger LOG = Logger.getLogger(LogSmsSenderFactory.class);

    static final String UNSAFE_LOGGING_PROPERTY = "keycloak.otp.logSms.unsafe";
    static final String UNSAFE_LOGGING_ENV = "KEYCLOAK_OTP_LOG_SMS_UNSAFE";

    private volatile boolean unsafeLogging;

    @Override
    public SmsProvider create(KeycloakSession session) {
        return new LogSmsSender(unsafeLogging);
    }

    @Override
    public void init(Config.Scope config) {
        this.unsafeLogging = resolveUnsafeFlag();
        if (unsafeLogging) {
            LOG.warn("LogSmsSenderFactory is configured to log raw OTP codes (unsafe mode). " +
                    "This must only be used for local development. Disable by unsetting " +
                    UNSAFE_LOGGING_PROPERTY + " / " + UNSAFE_LOGGING_ENV + ".");
        } else {
            LOG.info("LogSmsSenderFactory is the default development SMS provider. It does NOT " +
                    "deliver SMS messages and redacts OTP values in the log. Configure a real " +
                    "SMS provider before deploying to production.");
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "log";
    }

    private static boolean resolveUnsafeFlag() {
        String prop = System.getProperty(UNSAFE_LOGGING_PROPERTY);
        if (prop != null) {
            return Boolean.parseBoolean(prop);
        }
        String env = System.getenv(UNSAFE_LOGGING_ENV);
        return env != null && Boolean.parseBoolean(env);
    }

    static String maskPhone(String phoneNumber) {
        if (phoneNumber == null) {
            return "<null>";
        }
        int len = phoneNumber.length();
        if (len <= 4) {
            return "***";
        }
        return phoneNumber.substring(0, 2) + "***" + phoneNumber.substring(len - 2);
    }

    private static class LogSmsSender implements SmsProvider {

        private final boolean unsafeLogging;

        LogSmsSender(boolean unsafeLogging) {
            this.unsafeLogging = unsafeLogging;
        }

        @Override
        public void send(String phoneNumber, String message) throws SmsException {
            if (unsafeLogging) {
                LOG.infof("[DEV-ONLY] SMS to %s: %s", phoneNumber, message);
            } else {
                int messageLength = message == null ? 0 : message.length();
                LOG.infof("[DEV-ONLY] SMS dispatch suppressed (log provider); destination=%s, payload=%d chars (redacted)",
                        maskPhone(phoneNumber), messageLength);
            }
        }

        @Override
        public void close() {
        }
    }
}
