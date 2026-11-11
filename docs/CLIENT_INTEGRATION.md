# Client integration

This guide explains how a relying party (RP) can use Kagi Identity. Prefer a maintained OIDC client library for production applications; use the built-in SDK as a minimal demonstration and review its behavior against your own threat model.

## 1. Register a client

Register the exact callback URI. Scheme, host, port, path, and trailing slash must match exactly.

For a local demo, the seeded client ID is `demo-web`. For a new public browser client, register it through the authenticated dynamic registration endpoint:

```bash
export KAGI_REGISTRATION_TOKEN='use-the-secret-from-your-secret-manager'
curl --fail-with-body --request POST 'https://id.example.com/register' \
  --header "Authorization: Bearer $KAGI_REGISTRATION_TOKEN" \
  --header 'Content-Type: application/json' \
  --data '{
    "client_name": "Example Web App",
    "redirect_uris": ["https://app.example.com/auth/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "openid profile email offline_access",
    "token_endpoint_auth_method": "none"
  }'
```

Treat the registration response as sensitive. Do not log client credentials if a confidential client was registered.

Public clients (browser/mobile) cannot keep a client secret confidential; use Authorization Code + PKCE. Confidential clients should perform the token exchange on a trusted backend and use a supported client-authentication method.

## 2. Minimal browser SDK example

Load the SDK from the Kagi Identity origin:

```html
<script src="https://id.example.com/static/kagi.js"></script>
<button id="sign-in" type="button">Sign in</button>
<script>
  Kagi.configure({
    issuer: "https://id.example.com",
    clientId: "YOUR_CLIENT_ID",
    redirectUri: location.origin + "/auth/callback",
    scope: "openid profile email"
  });

  document.querySelector("#sign-in").addEventListener("click", () => {
    Kagi.login();
  });
</script>
```

On the callback route, load the SDK and configure the same issuer, client ID, and redirect URI:

```html
<script src="https://id.example.com/static/kagi.js"></script>
<script>
  Kagi.configure({
    issuer: "https://id.example.com",
    clientId: "YOUR_CLIENT_ID",
    redirectUri: location.origin + "/auth/callback",
    scope: "openid profile email"
  });

  (async () => {
    const session = await Kagi.handleCallback();
    const profile = await Kagi.userinfo();
    // Render only the profile fields the application actually needs.
    console.log({ subject: profile.sub, session });
  })();
</script>
```

API details can change; inspect `/demo` and `static/kagi.js` in the version you deploy. Never assume a successful callback alone is enough: validate the token and protocol requirements appropriate to your application. For production, prefer a mature OIDC library and validate issuer, audience, signature, expiry, nonce, state, and PKCE using the library's supported APIs.

## 3. Discovery and keys

Fetch the discovery document instead of hardcoding endpoint paths:

```bash
curl --fail 'https://id.example.com/.well-known/openid-configuration'
curl --fail 'https://id.example.com/jwks.json'
```

Cache JWKS according to the relying-party library's guidance and support key refresh when an unknown `kid` is encountered. Do not pin a single signing key indefinitely.

## 4. Optional OIDC features

These features are implemented but optional. Use them only after confirming the exact behavior of the commit and configuration you deploy.

### Requesting specific claims

Pass the standard `claims` parameter as JSON. Kagi supports `sub`, `auth_time`, `acr`, `amr`, `sid`, `name`, `preferred_username`, `email`, `email_verified`, and `iss`. Unknown names, oversized values, and `value`/`values` on anything other than `acr` are rejected. Scope is still the outer boundary: an essential claim outside the granted scope produces an authorization error instead of a silently incomplete token.

```bash
# URL-encode the JSON when putting it on the authorization request.
claims='{"id_token":{"email":{"essential":true}},"userinfo":{"name":null}}'
```

UserInfo returns only the claims named in `userinfo` when the parameter is present. Request `email_verified` explicitly if your application needs it.

### Device Authorization Grant (RFC 8628)

Use this for TVs, CLIs, and other input-constrained devices. Register the client with `grant_types` containing `urn:ietf:params:oauth:grant-type:device_code`.

```bash
curl --fail-with-body 'https://id.example.com/device_authorization' \
  --data-urlencode 'client_id=YOUR_CLIENT_ID' \
  --data-urlencode 'scope=openid profile offline_access'
# -> device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval

curl --fail-with-body 'https://id.example.com/token' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  --data-urlencode 'device_code=DEVICE_CODE' \
  --data-urlencode 'client_id=YOUR_CLIENT_ID'
```

Show `user_code` and `verification_uri` to the user. While waiting, poll no faster than `interval` and handle `authorization_pending` and `slow_down` (increase the interval by 5 seconds). The code is single-use and expires after `KAGI_DEVICE_TTL` (default 600 seconds).

### Client management (RFC 7592)

The registration response contains `registration_access_token` and `registration_client_uri`. Store the token as a secret: it is shown once and only its hash is kept.

```bash
export REGISTRATION_ACCESS_TOKEN='from-the-registration-response'

curl --fail-with-body 'https://id.example.com/register/CLIENT_ID' \
  --header "Authorization: Bearer $REGISTRATION_ACCESS_TOKEN"

curl --fail-with-body --request PUT 'https://id.example.com/register/CLIENT_ID' \
  --header "Authorization: Bearer $REGISTRATION_ACCESS_TOKEN" \
  --header 'Content-Type: application/json' \
  --data '{"redirect_uris":["https://app.example.com/auth/callback"],
           "backchannel_logout_uri":"https://app.example.com/oidc/logout"}'

# Rotate the client secret; the new value is returned once.
curl --fail-with-body --request PUT 'https://id.example.com/register/CLIENT_ID' \
  --header "Authorization: Bearer $REGISTRATION_ACCESS_TOKEN" \
  --header 'Content-Type: application/json' \
  --data '{"rotate_client_secret":true,
           "redirect_uris":["https://app.example.com/auth/callback"]}'

curl --fail-with-body --request DELETE 'https://id.example.com/register/CLIENT_ID' \
  --header "Authorization: Bearer $REGISTRATION_ACCESS_TOKEN"
```

Deletion removes the client's tokens, consents, device grants, and pending flows. Redirect URIs, scopes, grant types, JWKS material, and the back-channel URI are re-validated on every update.

### Back-Channel Logout 1.0

Register `backchannel_logout_uri` during registration or a management update. When a browser session ends (sign-out, session revocation, or account deletion), Kagi POSTs a signed `logout_token` as `application/x-www-form-urlencoded`.

- Validate `iss`, `aud`, `iat`, `jti`, `sub`, and the `events` member containing `http://schemas.openid.net/event/backchannel-logout`.
- Validate the JWT signature against the current JWKS and reject reused `jti` values.
- If `backchannel_logout_session_required` is true, the token includes `sid`; compare it with the RP session.
- Delivery is best effort. Kagi refuses redirects, URL credentials, non-HTTPS destinations in production, and private/link-local addresses. Loopback HTTP is allowed only outside production for local development.

## 5. Redirect and token safety

- Register exact redirect URIs; do not use wildcard callback URLs.
- Use Authorization Code + PKCE with S256; do not use the implicit flow.
- Generate cryptographically random `state` and `nonce` values and validate them in the callback.
- Do not put tokens in query strings, analytics events, or application logs.
- Avoid storing long-lived credentials in browser-accessible persistent storage.
- Keep access tokens short-lived and request only the scopes needed.
- For server-side sessions, keep tokens on the backend and issue an application session cookie with appropriate Secure, HttpOnly, and SameSite settings.

The built-in SDK is a convenience for evaluation, not a blanket recommendation to build production authentication logic by hand.
