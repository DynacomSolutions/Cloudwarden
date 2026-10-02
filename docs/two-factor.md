# Two-factor authentication

Providers are stored in the `twofactor` table (one row per user and type, `data` is JSON). The
token endpoint hook is `enforceTwoFactor` in `src/auth/twofactor.ts`.

| Type | Provider | Status |
|---|---|---|
| 0 | Authenticator app (TOTP) | supported |
| 1 | Email | supported, needs the `EMAIL` binding and `MAIL_FROM` |
| 2 | Duo (Universal Prompt) | supported, user level |
| 3 | YubiKey OTP | supported, needs `YUBICO_CLIENT_ID` and `YUBICO_SECRET_KEY` to register or verify keys |
| 6 | Organisation Duo | supported, set by organisation owners and admins |
| 5 | Remember device | supported (30 days, per device) |
| 7 | WebAuthn | supported (ES256 and RS256) |
| 8 | Recovery code | via `POST /api/two-factor/recover` |

## Login flow

A password grant for a user with providers returns HTTP 400, `error: invalid_grant`,
`error_description: Two factor required.`, `TwoFactorProviders` (type numbers as strings) and
`TwoFactorProviders2` (per provider parameters: the masked address for email, assertion
options for WebAuthn). The client repeats the request with `twoFactorProvider`,
`twoFactorToken` and optionally `twoFactorRemember=1`, which adds `TwoFactorToken` to the
success body. Sending that value later as provider 5 skips the challenge on the same device.
Disabling a provider or using the recovery code clears all remember tokens. API key
(`client_credentials`) logins do not require a second factor.

## Management endpoints

Every endpoint under `/api/two-factor` accepts either `masterPasswordHash` or the
`userVerificationToken` returned by the `get-*` calls (valid 30 minutes). Calls are rate limited
per address, and verification and login attempts per user, through `LOGIN_LIMITER`.

## Security properties

- Recovery codes must match `^[A-Z2-7]{32}$` after normalisation, an empty stored code never
  matches, and spending a code is guarded on the old value so it works once. It is accepted
  at `/api/two-factor/recover` and as provider 8 at the token endpoint.
- A user with an enabled provider this server cannot verify (an unknown type) cannot log in with
  a password alone; only the recovery code gets through.
- `userVerificationToken` is bound to the user's security stamp.
- Email attempts are counted atomically before comparison. Without the `LOGIN_LIMITER`
  binding, 2FA paths fall back to a D1 fixed window (20 per user and 60 per address per minute).

## Notes and limits

- TOTP: SHA-1, 6 digits, 30 second step, steps `now-1..now+1`. The last accepted step is stored
  and any step at or below it is refused.
- Email codes are stored hashed, expire after 10 minutes and allow 5 wrong attempts. A new code
  resets the counter. Setup is refused when no mail transport is configured.
- WebAuthn challenges are stateless (timestamp, nonce and HMAC bound to the user and purpose,
  valid 5 minutes). A login challenge works once: the newest accepted challenge time is stored.
  The relying party id is the host of `DOMAIN` and the origin must equal the origin of `DOMAIN`.
  Attestation statements are not verified, so any attestation format is accepted as if it were
  `none`. Credentials must use ES256 or RS256, and a signature counter that does not advance is
  rejected (a counter that stays at zero is allowed).
- The WebAuthn parameters in `TwoFactorProviders2["7"]` are the assertion options object
  itself (`challenge`, `rpId`, `allowCredentials`, ...).

## Duo (#124)

Duo Universal Prompt (Web SDK v4), an OIDC code flow with HS512 JWTs, written from Duo's
published protocol description. Configuration is a Duo "Web SDK" application: API hostname
(`api-<id>.duosecurity.com` or `.duofederal.com`, anything else is refused), 20 character client
id and 40 character client secret.

| Endpoint | Purpose |
|---|---|
| `POST /api/two-factor/get-duo`, `PUT` or `POST /api/two-factor/duo`, `DELETE /api/two-factor/duo` | User Duo (type 2) |
| `GET /api/organizations/{id}/two-factor`, `POST .../two-factor/get-duo`, `PUT` or `POST .../two-factor/duo`, `DELETE .../two-factor/duo` | Organisation Duo (type 6), needs the `managePolicies` permission (owners and admins) |

- Saving calls Duo's health check with a signed client assertion, so a wrong host, id or secret is
  refused. The secret is returned masked; a masked value sent back keeps the stored secret.
- Login: the challenge carries `TwoFactorProviders2["2"]` (or `"6"`) with `Host` and `AuthUrl`.
  `AuthUrl` is the authorize URL with a signed `request` JWT (`duo_uname` is the account email,
  `redirect_uri` is `<DOMAIN>/duo-redirect-connector.html?client=<web|browser|desktop|mobile>`,
  taken from the `Bitwarden-Client-Name` header) and a stateless `state` (the same HMAC challenge
  as WebAuthn, bound to the user and to the login's device identifier, valid 5 minutes) and a
  `nonce` derived from it. The clients open it, Duo redirects to the
  connector page, which hands `code` and `state` back; the client sends `code|state` as the token.
- The server checks the state, exchanges the code at `https://<host>/oauth/v1/token` with a client
  assertion, verifies the `id_token` signature (HS512, client secret), issuer, audience, that
  `preferred_username` is the account email, the echoed `nonce`, a numeric `exp` and an `iat`
  within a sane window, and that `auth_result.result` is `allow`.
- A state works once: the newest accepted state time is stored (`last_used` of the user's Duo row,
  or a disabled ledger row for organisation Duo), so a replay or an older state is refused. The
  state is spent before Duo is contacted.
- Organisation Duo follows the official clients: it is one more selectable provider (type 6,
  listed first by the clients) for confirmed members of an organisation that enables it, not an
  extra mandatory step. The wire format has one entry per provider type, so with several
  organisations the challenge offers the first (by organisation id) and verification accepts any
  of them. Pending, accepted and revoked members are not offered it. Configuration lives in
  `organization_twofactor` (migration `0012`).
- The web client's `frame-src` allows `*.duosecurity.com` and `*.duofederal.com`.

## YubiKey OTP (#124)

Validation against YubiCloud (protocol 2.0) with HMAC-SHA1 signed requests and responses, written
from Yubico's published description. Get a client id and API key at the Yubico key portal and set
`YUBICO_CLIENT_ID` and `YUBICO_SECRET_KEY` (base64) as Worker secrets; `YUBICO_SERVER` optionally
replaces the default `api.yubico.com` to `api5.yubico.com` servers with a self-hosted validation
server (https URL).

- `POST /api/two-factor/get-yubikey`, `PUT` or `POST /api/two-factor/yubikey`, `DELETE
  /api/two-factor/yubikey`. Up to five keys (`key1` to `key5`) and the `nfc` flag. Each new key is
  an OTP (44 modhex characters) that YubiCloud must accept; only the 12 character public id is
  stored. A key already registered can be sent back by its public id without a new OTP.
- Login: `TwoFactorProviders2["3"]` is `{ Nfc }`. The token is an OTP whose public id must be one
  of the stored ids; YubiCloud must answer `OK` with a valid signature for that exact OTP and a
  fresh nonce. The signed session counter and use are stored per public id, and an OTP that is
  not later than the newest accepted one is refused locally as a replay, as well as by YubiCloud.
  The API key must be standard base64.
- Without the two variables registering a new key is refused with a message naming them.

## Login with passkey (#125)

Passwordless login with a discoverable WebAuthn credential, optionally unlocking the vault with
the PRF extension. Credentials live in `webauthn_credentials` (migration `0006_passkeys`), at most
five per account, and are separate from the second factor keys of provider 7.

| Endpoint | Purpose |
|---|---|
| `GET /api/webauthn` | List credentials with `prfStatus` (0 keyset stored, 1 PRF supported, 2 unsupported) |
| `POST /api/webauthn/attestation-options` | Creation options and `token` (needs `masterPasswordHash`) |
| `POST /api/webauthn` | Save a credential with `supportsPrf` and the optional keyset (`encryptedUserKey`, `encryptedPublicKey`, `encryptedPrivateKey`, all or none) |
| `POST /api/webauthn/assertion-options` | Assertion options for the account's own credentials (needs `masterPasswordHash`) |
| `PUT /api/webauthn` | Store a keyset on a saved credential, authorised by a fresh assertion |
| `POST /api/webauthn/{id}/delete` | Delete a credential (needs `masterPasswordHash`) |
| `GET /identity/accounts/webauthn/assertion-options` | Anonymous login options (discoverable, no `allowCredentials`) and `token` |
| `POST /identity/connect/token` with `grant_type=webauthn` | `token` and JSON `deviceResponse`; returns the usual tokens |

- User verification is required for creation, the key update and login; an assertion without the
  UV flag is refused. Attestation statements are not verified (same as the second factor).
- The `token` is a signed, five minute purpose token that carries the stateless challenge; it is
  bound to the purpose (create, assert, login) and, for signed in flows, to the user. A challenge
  works once: the newest accepted challenge time is stored on the credential and the update is
  guarded on it, so a replay changes nothing. The signature counter must advance when either
  side is non-zero.
- When the credential has a keyset the token response carries
  `UserDecryptionOptions.WebAuthnPrfOption` (`EncryptedPrivateKey`, `EncryptedUserKey`,
  `CredentialId`, `Transports`) and `/api/sync` lists every keyset in
  `userDecryption.webAuthnPrfOptions`. The server stores wrapped keys only; the PRF output never
  reaches it.
- A passkey login does not request a second factor: the verified assertion is the second
  factor, as in the official clients (they do not support a 2FA step after it).
- A creation token is single use: the challenge time is stored on the user (`passkey_create_at`,
  migration `0007`) and spent before the credential is saved, so a captured registration cannot be
  replayed after the credential is deleted.
- Key rotation (`rotate-user-account-keys`) re-wraps keysets from `passkeyUnlockData`. A
  credential with a keyset that the request omits loses the keyset (it stays a login credential
  and can enable encryption again; the legacy `POST /api/accounts/key` carries no passkey data, so it
  drops every keyset). The rewrite is guarded by each row's `updated_at` and followed by clearing
  statements in the same batch, so a keyset stored concurrently under the old key is removed; naming a credential that is not the caller's or has no
  keyset is rejected and nothing changes.
- Account deletion removes credentials with the user row.
