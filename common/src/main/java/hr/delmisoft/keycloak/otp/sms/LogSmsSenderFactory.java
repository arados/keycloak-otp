package hr.delmisoft.keycloak.otp.sms;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class LogSmsSenderFactory implements SmsProviderFactory {

    private static final Logger LOG = Logger.getLogger(LogSmsSenderFactory.class);

    @Override
    public SmsProvider create(KeycloakSession session) {
        return new LogSmsSender();
    }

    @Override
    public void init(Config.Scope config) {
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

    private static class LogSmsSender implements SmsProvider {

        @Override
        public void send(String phoneNumber, String message) throws SmsException {
            LOG.infof("SMS to %s: %s", phoneNumber, message);
        }

        @Override
        public void close() {
        }
    }
}
