package arestless.keycloak.broker.provider;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.*;
import java.io.IOException;
import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SteamIdentityProvider extends AbstractIdentityProvider<SteamIdentityProviderConfig> implements SocialIdentityProvider<SteamIdentityProviderConfig> {

    public SteamIdentityProvider(KeycloakSession session, SteamIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Response retrieveToken(KeycloakSession keycloakSession, FederatedIdentityModel federatedIdentityModel) {
        return null;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new Endpoint(callback, realm, event, session);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        URI uri = UriBuilder.fromUri("https://steamcommunity.com/openid/login")
                .scheme("https")
                .queryParam("openid.ns", "http://specs.openid.net/auth/2.0")
                .queryParam("openid.assoc_handle", request.getState().getEncoded())
                .queryParam("openid.mode", "checkid_setup")
                .queryParam("openid.return_to", request.getRedirectUri() + "?state=" + request.getState().getEncoded())
                .queryParam("openid.realm", request.getRedirectUri())
                .queryParam("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
                .queryParam("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")
                .build();

        return Response.seeOther(uri).build();
    }

    public Response keycloakInitiatedBrowserLogout(KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        return null;
    }

    protected class Endpoint {
        protected AuthenticationCallback callback;
        protected RealmModel realm;
        protected EventBuilder event;
        protected KeycloakSession session;

        @Context
        protected ClientConnection clientConnection;

        @Context
        protected HttpHeaders headers;

        public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event, KeycloakSession session) {
            this.callback = callback;
            this.realm = realm;
            this.event = event;
            this.session = session;
        }

        @GET
        public Response authResponse(@QueryParam("state") String state,
                                     @QueryParam("openid.assoc_handle") String handle,
                                     @QueryParam("openid.signed") String signed,
                                     @QueryParam("openid.sig") String sig,
                                     @QueryParam("openid.mode") String mode,
                                     @QueryParam("openid.op_endpoint") String endpoint,
                                     @QueryParam("openid.claimed_id") String claimedId,
                                     @QueryParam("openid.identity") String identity,
                                     @QueryParam("openid.return_to") String returnTo,
                                     @QueryParam("openid.response_nonce") String responseNonce,
                                     @QueryParam("openid.invalidate_handle") String invalidateHandle) {
            String namespace = "http://specs.openid.net/auth/2.0";
                                
            AuthenticationSessionModel authSession = callback.getAndVerifyAuthenticationSession(state);
            session.getContext().setAuthenticationSession(authSession);

            SimpleHttp request = SimpleHttp.doPost("https://steamcommunity.com/openid/login", session)
                    .header("Accept-language", "en")
                    .header("Content-type", "application/x-www-form-urlencoded")
                    .param("openid.assoc_handle", handle)
                    .param("openid.signed", signed)
                    .param("openid.sig", sig)
                    .param("openid.ns", namespace)
                    .param("openid.op_endpoint", endpoint)
                    .param("openid.claimed_id", claimedId)
                    .param("openid.identity", identity)
                    .param("openid.return_to", returnTo)
                    .param("openid.response_nonce", responseNonce)
                    .param("openid.invalidate_handle", invalidateHandle)
                    .param("openid.mode", "check_authentication");

            try {
                String response = request.asString();
                if (!Pattern.compile(".*is_valid\\s*:\\s*true.*", Pattern.DOTALL).matcher(response).matches()) {
                    return callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }
            } catch (IOException e) {
                e.printStackTrace();
                return callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }

            Pattern p = Pattern.compile("https?://steamcommunity.com/openid/id/([0-9]{17,25})");
            Matcher matcher = p.matcher(identity);
            String steamId;
            if (matcher.matches()) {
                steamId = matcher.group(1);
            } else {
                return callback.error(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }

            BrokeredIdentityContext federatedIdentity = new BrokeredIdentityContext(claimedId);
            federatedIdentity.setIdp(SteamIdentityProvider.this);
            federatedIdentity.setIdpConfig(getConfig());
            federatedIdentity.setBrokerUserId(steamId);
            federatedIdentity.setUsername(steamId);
            federatedIdentity.setAuthenticationSession(authSession);
            federatedIdentity.setUserAttribute("steamId", steamId);

            try {
                JsonNode node = SimpleHttp.doGet("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/", session)
                        .param("key", getConfig().getSteamApiKey())
                        .param("steamids", steamId)
                        .asJson();

                federatedIdentity.setUsername(node.get("response").get("players").get(0).get("personaname").asText());
            } catch (IOException e) {
                e.printStackTrace();
            }


            return callback.authenticated(federatedIdentity);
        }
    }
}
