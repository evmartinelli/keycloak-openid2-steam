package arestless.keycloak.broker.provider;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

public class SteamIdentityProviderFactory extends AbstractIdentityProviderFactory<SteamIdentityProvider> implements SocialIdentityProviderFactory<SteamIdentityProvider> {

    @Override
    public String getName() {
        return "Steam";
    }

    @Override
    public SteamIdentityProvider create(KeycloakSession keycloakSession, IdentityProviderModel identityProviderModel) {
        return new SteamIdentityProvider(keycloakSession, new SteamIdentityProviderConfig(identityProviderModel));
    }


    @Override
    public SteamIdentityProviderConfig createConfig() {
        return new SteamIdentityProviderConfig();
    }

    @Override
    public String getId() {
        return "steam";
    }
}
