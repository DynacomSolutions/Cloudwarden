# Single sign-on, trusted devices, Key Connector and claimed domains

TASKS #280 to #289. Cloudwarden is the identity server and the SSO service provider in one Worker.
Nothing here is derived from Bitwarden's SSO server (Bitwarden License); the flow is built from
what the GPL clients send and expect.

## Login flow

1. `GET /identity/sso/prevalidate?domainHint={identifier}` returns `{ token }` (5 minutes) when the
   organisation exists and SSO is on.
2. The client opens `GET /identity/connect/authorize` with `client_id`, `redirect_uri`,
   `response_type=code`, `scope` (must include `api`), `state`, `code_challenge`
   (`S256` only), `domain_hint`, `ssoToken` and optionally `user_identifier` (account linking).
   - Redirect URIs are allow-listed per client before anything else and errors never redirect:
     `web`, `browser`: `{DOMAIN}/sso-connector.html`; `desktop`: `bitwarden://sso-callback`,
     loopback `http://localhost|127.0.0.1:{port}` or the connector; `mobile`:
     `bitwarden://sso-callback`; `cli`: loopback only.
   - A flow row is stored and a `__Host-cw-sso` cookie (HttpOnly, Secure, SameSite=None) binds it
     to the browser; the callback must present it (login CSRF and code injection defence).
3. The browser goes to the identity provider:
   - OIDC (`oauth4webapi`): discovery from the authority (or metadata address, https only),
     authorization code with PKCE, `state`, `nonce`. Callback `/sso/oidc-signin` (GET, or POST for
     form post). The ID token is validated for issuer, audience, expiry and nonce, and its
     signature is checked against the JWKS (RS/ES/PS) or the client secret (HS*); `none` is
     refused. Optional UserInfo, additional scopes, claim type mappings, `acr_values` and the
     expected `acr`.
   - SAML 2.0 (`xmldsigjs` with `@xmldom/xmldom`): AuthnRequest over HTTP-Redirect (deflate,
     signed query string) or HTTP-POST (enveloped signature), per the signing behaviour setting.
     ACS `/sso/saml2/{orgId}/Acs`. Metadata `/sso/saml2/{orgId}` (SP key and self-signed
     certificate created per organisation on first use). Validation: no DTDs, exactly one
     assertion in the message, signature by the configured certificate(s) with one reference to
     the signed element's unique ID and only c14n/enveloped transforms, minimum algorithm (SHA-256
     unless lowered), signed assertions when required, issuer, destination, audience, bearer
     subject confirmation (recipient, NotOnOrAfter, InResponseTo), conditions with 2 minutes of
     skew, replay protection (assertion IDs stored until expiry), encrypted assertions (RSA-OAEP
     with AES-CBC or AES-GCM). `spValidateCertificates` checks the certificate validity period.
4. The account is found or provisioned (`src/sso/flow.ts`):
   - an existing SSO link decides the account;
   - an existing account with the asserted email is linked only when it is already an accepted or
     confirmed member, or when it signed in with its master password and started the link itself
     (`user_identifier`: single-use token, same email, must be invited or a member). A pending
     invitation or a claimed domain never links an existing account silently;
   - a new account (no master password) is created only for a domain the organisation claims or
     an address it invited; only a claimed domain marks the address verified;
   - revoked members are refused; invitations are accepted; new members join as accepted Users
     for an administrator to confirm.
   OIDC email comes only from the `email` claim (or claim types the administrator names). Linking
   or provisioning by email requires `email_verified: true` unless the organisation turns on
   "Accept email addresses the provider has not verified" (`allowUnverifiedEmail`); logins of
   already linked identities are not affected. SAML email comes from the standard email attributes or
   an email-shaped NameID.
5. A one-time code (5 minutes) bound to client, redirect URI and PKCE challenge goes to the
   client's redirect URI with its `state` unchanged. `POST /identity/connect/token` with
   `grant_type=authorization_code` redeems it; two-step login applies and the code is spent only
   once everything passed.

### Upstream SSO paths

SDK based clients use the paths of the official Identity SSO controller. They map onto the flow above
and add no behaviour of their own, so PKCE, `state`, the redirect allow-list and the prevalidation
token are all enforced by `/identity/connect/authorize` and the callbacks:

- `GET /identity/sso/Login?returnUrl=` reads the authorize request in `returnUrl` and redirects to
  `ExternalChallenge` with its `domain_hint`, `ssoToken` and `user_identifier`.
- `GET /identity/sso/ExternalChallenge?returnUrl=&domainHint=&ssoToken=&userIdentifier=` redirects to
  `/identity/connect/authorize` with the query of `returnUrl`, the explicit parameters overriding
  the ones inside it.
- `GET /identity/sso/ExternalCallback` is the OpenID Connect return, the same handler as
  `/sso/oidc-signin`.

`returnUrl` must be this server's own authorize endpoint (relative, or on its own origin); anything
else is an error page and is never redirected to.

### Reverse proxy cookie (`/api/sso-cookie-vendor`)

For deployments where a reverse proxy (for example a load balancer with an identity provider step)
authenticates users before the vault, clients open `GET /api/sso-cookie-vendor` to acquire the proxy
session cookie. Set `SSO_COOKIE_VENDOR_COOKIE_NAME` to the proxy cookie name: the endpoint then answers
200 when the browser arrives with that cookie (or sharded `name-N` cookies) and 401 otherwise. The
cookie value is never read back or returned. Without the setting the endpoint is a 404, like any
deployment without such a proxy.

## Secrets at rest and caching

The OIDC client secret and the SAML SP private key are encrypted with AES-256-GCM under a key
derived from `DATA_ENCRYPTION_KEY` (or, without it, from `JWT_SECRET`; `src/orgs/sealed.ts`). The
settings page shows the client secret as a placeholder; saving (or testing) with the placeholder
keeps the stored value, unless the authority, metadata address or client ID changed: then the
secret must be entered again. Account link tokens (`GET /api/accounts/sso/user-identifier`) are
issued only to sessions of accounts with a master password. Discovery documents are cached for 5 minutes and JWKS per issuer within an isolate. A
custom metadata address must be on the authority's host. SAML: AES-CBC encrypted assertions are
decrypted only inside a verified signed response, all decryption failures give one generic
error, and a signed response must carry `Destination`.

## Token response

`UserDecryptionOptions` carries `HasMasterPassword`, `MasterPasswordUnlock` (only with a password),
`TrustedDeviceOption` (`HasAdminApproval` = enrolled in account recovery, `HasLoginApprovingDevice`,
`HasManageResetPasswordPermission`, `IsTdeOffboarding`, and `EncryptedPrivateKey`/`EncryptedUserKey`
when this device is trusted) and `KeyConnectorOption { KeyConnectorUrl }`. `Key` is null for an
account without keys yet.

## Policies

- Require SSO (4): password, passkey and personal API key logins of non-admin members get 400
  with `SsoOrganizationIdentifier`, which the clients turn into an SSO redirect. Login with device
  stays allowed. Existing refresh tokens keep working until they expire (30 days of inactivity)
  or the account's sessions are revoked. Needs the single organisation policy first.
- Trusted devices turns on single organisation, require SSO and account recovery with automatic
  enrolment; these cannot be relaxed while it is on. Key Connector requires single organisation
  and require SSO, and cannot be turned off while members use it.

## Trusted device encryption

`PUT /api/devices/{identifier}/keys`, `POST /api/devices/{identifier}/retrieve-keys`,
`POST /api/devices/update-trust`, `POST /api/devices/lost-trust`, `POST /api/devices/untrust`.
Key rotation (`rotate-user-account-keys`) re-wraps devices in `deviceKeyUnlockData` and untrusts
the others. Approval paths: another device (auth requests), admin approval (account recovery
enrolment, workstream C) and master password. `PUT /api/accounts/update-tde-offboarding-password`
serves members whose organisation left trusted devices.

## Key Connector

`POST /api/accounts/set-key-connector-key`, `POST /api/accounts/convert-to-key-connector` (owners
and admins keep their password), `GET /api/accounts/key-connector/confirmation-details/{identifier}` and
`POST /api/accounts/key-connector/enroll` (an existing member of a Key Connector organisation, for
example one that unlocked with a trusted device, sends `keyConnectorKeyWrappedUserKey`, a type 2
encrypted string, with proof of ownership: `masterPasswordHash` when the account has a master
password, an emailed `otp` (`POST /api/accounts/request-otp`) when it has none. Only confirmed
members qualify. Any master password is removed, owners and admins with one are refused, the
security stamp rotates and the other devices are signed out. The official SDK request carries
neither proof field, so a stock client's enrolment is refused until it sends one).
The client talks to the Key Connector directly (`GET/POST {url}/user-keys`, `GET {url}/alive`).

### Token signing for a Key Connector

A Key Connector validates the bearer token the client sends it, so it must be able to verify
Cloudwarden access tokens:

- Set the Worker secret `JWT_SIGNING_KEY` to a P-256 private key (PKCS#8, base64 DER or PEM):

  ```sh
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    | openssl pkcs8 -topk8 -nocrypt -outform DER | base64 -w0
  ```

  Access tokens are then signed ES256 with a `kid`. Without the secret they stay HS256.
- Discovery: `GET {DOMAIN}/identity/.well-known/openid-configuration` (issuer is `{DOMAIN}`),
  keys at `GET {DOMAIN}/identity/.well-known/openid-configuration/jwks`.
- Rotation: move the old value to `JWT_SIGNING_KEY_PREVIOUS` (still published and accepted) and
  set a new `JWT_SIGNING_KEY`; drop the previous key after the access token lifetime (1 hour).
  HS256 tokens issued before the switch stay valid until they expire.

### Running the official Key Connector

Bitwarden's Key Connector is under the Bitwarden License (not GPL or AGPL). Users may run it under
that licence; Cloudwarden does not ship it, and its source was not read for this work. To use it:

1. Set `JWT_SIGNING_KEY` as above and deploy.
2. Run the Key Connector over https on a host your clients reach, following Bitwarden's
   documentation, and point its identity server and web vault settings at your Cloudwarden
   `DOMAIN` (identity at `{DOMAIN}/identity`). Its token validation uses the discovery document
   and JWKS above.
3. In the organisation's SSO settings choose Key Connector and enter its URL; use the Test
   button to check `GET {url}/alive` from the browser (the Key Connector must allow your vault
   origin for CORS).

This setup has not been tested end to end against the official Key Connector (it would require
running Bitwarden-licensed software in CI). The client side of the protocol (`GET`/`POST
{url}/user-keys`) is covered by Cloudwarden's tests of the server endpoints (TASKS #285).

## Claimed domains

`GET|POST /api/organizations/{orgId}/domain`, `GET .../domain/mini`, `GET|DELETE .../domain/{id}`,
`POST .../domain/{id}/verify`, anonymous `POST /api/organizations/domain/sso/verified` and
`.../sso/details` (SSO discovery by email). Verification looks for a TXT record on the domain equal
to the `bw=...` token through DNS over HTTPS (`cloudflare-dns.com`); the hourly cron re-checks
unverified domains every 12 hours, 6 times. A domain verified by one organisation cannot be
verified by another. Members on a claimed domain are claimed (`userIsClaimedByOrganization`,
`claimedByOrganization`): they cannot delete their account, purge the vault, change their email or
leave, and administrators with manage users can delete their accounts
(`DELETE .../users/{id}/delete-account`, bulk `DELETE .../users/delete-account`).

## End-to-end test

`pnpm e2e` runs `e2e/sso.mjs` against `e2e/oidc-idp.mjs`, a mock OpenID Connect provider on
`127.0.0.1` (TASKS #288). The provider is plain http, which the Worker accepts only with
`SSO_ALLOW_INSECURE_LOOPBACK=true`; that variable is declared only together with
`LOCAL_DEV_SECRETS` (local development and the e2e run) and must never be set in production.

## Web UI

`web/apps/web/src/app/cloudwarden/sso/`: Settings, Single sign-on (OIDC and SAML fields, member
decryption options, configuration test via `POST /api/organizations/{orgId}/sso/test`, Key
Connector reachability test) and Settings, Claimed domains.

## Libraries

| Library | Licence | Use |
|---|---|---|
| `oauth4webapi` | MIT | OIDC relying party |
| `xmldsigjs`, `xml-core` | MIT | XML signatures (WebCrypto) |
| `@xmldom/xmldom` | MIT | XML parsing |
| `pkijs`, `asn1js` | BSD-3-Clause | X.509 parsing and SP certificate creation |
