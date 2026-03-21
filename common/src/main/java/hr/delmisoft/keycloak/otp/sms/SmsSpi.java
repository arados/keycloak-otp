package hr.delmisoft.keycloak.otp.sms;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public class SmsSpi implements Spi {

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return "sms";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return SmsProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return SmsProviderFactory.class;
    }
}
