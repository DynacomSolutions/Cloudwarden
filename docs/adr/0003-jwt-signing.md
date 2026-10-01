# ADR 0003: Access token signing and rotation

Status: accepted (TASKS #24)

## Decision

- Access tokens are JWTs signed with HS256 through WebCrypto, using the secret `JWT_SECRET` (at least 32 characters; the Worker refuses to sign or verify with a shorter one).
- Claims: `nbf`, `exp` (one hour), `iss` (the `DOMAIN` value without a trailing slash), `sub` (user id), `email`, `name`, `premium`, `email_verified`, `sstamp` (security stamp), `device` (client device identifier), `scope` (`api`, `offline_access`) and `amr` (`Application`).
- `requireAuth` (`src/auth/middleware.ts`) verifies signature, `nbf`, `exp`, `iss`, the `api` scope, loads the user and compares `sstamp` with the stored security stamp. Changing the password, KDF, email or rotating the stamp therefore revokes all outstanding access tokens immediately, and clears every device refresh token.
- Refresh tokens are opaque (`<device id>.<random secret>`). Only the SHA-256 of the secret is stored. Each refresh rotates the secret, a replayed token fails, and tokens expire 30 days after the device last logged in or refreshed.
- Registration verification tokens use a derived secret (`register:` plus the signing secret) so they can never be accepted as access tokens.

## Rotating `JWT_SECRET`

1. Set `JWT_SECRET_PREVIOUS` to the current secret and `JWT_SECRET` to the new one, then deploy. New tokens are signed with the new secret, tokens signed with the old one still verify.
2. After at least one hour (the access token lifetime), remove `JWT_SECRET_PREVIOUS` and deploy again.
3. To force every client to log in again immediately, skip step 1 and just replace `JWT_SECRET`; refresh tokens are unaffected, so clients silently refresh.

Emergency revocation of all sessions: rotate the security stamp of affected users (or run an `UPDATE` on `users.security_stamp`).

## Consequences

- Revoking a single device removes its refresh token; its current access token stays valid for up to one hour.
- Registration verification tokens are derived from `JWT_SECRET`, so rotating it invalidates tokens issued within the last 30 minutes.
