# keycloak-openid2-steam UPDATE to KeyCloak 22

A minimal Keycloak IdentityProvider implementation of OpenID2 for Steam. This implementation may
also serve as a basis for a full-fledged OpenID2 implementation for Keycloak and as example for
IdentityProvider implementations in general.

## Build

```
mvn package
```

## .env

```
creata .env to keep your steamkey secured
```


This will create `keycloak-openid2-steam.jar` in `keycloak/providers`.

## Deployment

Copy the `keycloak/providers` directory to your Keycloak folder, and the `keycloak/themes/steam`
folder to the corresponding themes folder in your Keycloak installation. If you're running
Keycloak in Docker, mount these directories into the container.

## The Theme - 

Keycloak22 uses a new Admin Theme that cant be customizable with partials. So you refactored the code to keep steamID in a .env file

## Adding the IdentityProvider

"Steam OpenID2" will now be available under "Identity Providers" within Keycloak. When creating
the provider, you can optionally add a Steam API key that can be retrieved from
https://steamcommunity.com/dev/apikey.

If the key is added, the provider will try to obtain the Steam user name from the Steam API
during registration. Please note that the availability of the user name may depend on the user's
privacy settings.

## Adding the SteamID to Tokens

The user's SteamID will be added as a user attribute named "steamid64". Under Clients ->
YourClientName -> Mappers you can create a User Attribute mapper that maps the
value of this attribute to a custom field ("claim") in the JWT tokens created by Keycloak.

The "Claim JSON Type" needs to be "String" or "long".

## Acknowledgements

The implementation of the OpenID2 protocol was heavily based on
https://github.com/BlackCetha/SteamAuthOOP.
