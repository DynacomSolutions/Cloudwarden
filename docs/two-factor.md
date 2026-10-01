# Two-factor authentication

Providers are stored in the `twofactor` table (one row per user and type, `data` is JSON). The
token endpoint hook is `enforceTwoFactor` in `src/auth/twofactor.ts`.

| Type | Provider | Status |
|---|---|---|
| 0 | Authenticator app (TOTP) | supported |
| 1 | Email | supported, needs the `EMAIL` binding and `MAIL_FROM` |
| 2 | Duo | not supported |
| 3 | YubiKey OTP | not supported |
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
- A user with an enabled provider this server cannot verify (Duo, YubiKey) cannot log in with a
  password alone; only the recovery code gets through.
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

## Deferred

- Duo and YubiKey OTP (#124) need outbound calls to third party services and are optional.
  Their endpoints return HTTP 400 with a "not supported" message.

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
