package arestless.keycloak.broker.provider;

import org.keycloak.models.IdentityProviderModel;

public class SteamIdentityProviderConfig extends IdentityProviderModel {

    private static final String STEAM_API_KEY = System.getenv("STEAM_API_KEY");

    public SteamIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public SteamIdentityProviderConfig() {
    }

    public String getSteamApiKey() {
        return STEAM_API_KEY;
    }
}