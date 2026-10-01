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
- Login with passkey (#125) needs a credential store with PRF wrapped user keys, the
  `/api/webauthn` management endpoints, `GET /identity/accounts/webauthn/assertion-options`
  and `grant_type=webauthn`. None of it is implemented yet.
