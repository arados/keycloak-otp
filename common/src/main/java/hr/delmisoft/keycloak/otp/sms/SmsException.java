package hr.delmisoft.keycloak.otp.sms;

public class SmsException extends Exception {

    public SmsException(String message) {
        super(message);
    }

    public SmsException(String message, Throwable cause) {
        super(message, cause);
    }
}
