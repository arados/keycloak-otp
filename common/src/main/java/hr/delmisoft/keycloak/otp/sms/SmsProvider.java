package hr.delmisoft.keycloak.otp.sms;

import org.keycloak.provider.Provider;

public interface SmsProvider extends Provider {

    void send(String phoneNumber, String message) throws SmsException;
}
