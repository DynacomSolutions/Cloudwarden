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
   existing SSO link; else the account with the asserted email when it is invited to or a member
   of the organisation, or its domain is claimed by it; else a new account without a master
   password (JIT). Linking with `user_identifier` requires the same email. Revoked members are
   refused; invitations are accepted; new members are added as accepted Users for an
   administrator to confirm.
5. A one-time code (5 minutes) bound to client, redirect URI and PKCE challenge goes to the
   client's redirect URI with its `state` unchanged. `POST /identity/connect/token` with
   `grant_type=authorization_code` redeems it; two-step login applies and the code is spent only
   once everything passed.

## Token response

`UserDecryptionOptions` carries `HasMasterPassword`, `MasterPasswordUnlock` (only with a password),
`TrustedDeviceOption` (`HasAdminApproval` = enrolled in account recovery, `HasLoginApprovingDevice`,
`HasManageResetPasswordPermission`, `IsTdeOffboarding`, and `EncryptedPrivateKey`/`EncryptedUserKey`
when this device is trusted) and `KeyConnectorOption { KeyConnectorUrl }`. `Key` is null for an
account without keys yet.

## Policies

- Require SSO (4): password and passkey logins of non-admin members get 400 with
  `SsoOrganizationIdentifier`, which the clients turn into an SSO redirect. Login with device
  stays allowed. Needs the single organisation policy first.
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
and admins keep their password), `GET /api/accounts/key-connector/confirmation-details/{identifier}`.
The client talks to the Key Connector directly (`GET/POST {url}/user-keys`, `GET {url}/alive`).

Bitwarden's Key Connector (github.com/bitwarden/key-connector) is under the Bitwarden License, not
GPL or AGPL, so Cloudwarden does not ship, test against or read it. A Key Connector must accept
Cloudwarden access tokens; Cloudwarden signs them with HS256 and publishes no JWKS, so a
deployment needs a Key Connector that validates tokens through Cloudwarden or shares the secret.
This is a known interoperability gap (TASKS #285).

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
