# Admin UI

Server-rendered admin area at `/admin` (TASKS #140). It returns 404 unless `ADMIN_ENABLED` is `true`. It uses no JavaScript and no external resources; the CSP is `default-src 'none'` with a per-response style nonce.

## Configuration

| Name | Kind | Purpose |
|---|---|---|
| `ADMIN_ENABLED` | var | `true` to enable the UI |
| `ADMIN_EMAILS` | secret | Comma-separated admin addresses (case-insensitive) allowed to request a magic link |
| `ADMIN_TOKEN_HASH` | secret | Hash of an admin token for token login (optional) |
| `EMAIL` | `send_email` binding | Cloudflare Email Service, needed for magic links and invites |
| `MAIL_FROM` | var | Sender address, on an onboarded sending domain |
| `DOMAIN` | var | Public base URL used in emailed links |

With no `EMAIL` binding or `MAIL_FROM`, mail is silently skipped; use token login in that case.

## Sign-in

- **Magic link.** The form always answers "if that address is an admin, a link was sent". A 32 byte token is created (only its SHA-256 is stored, 15 minute expiry, single use). Opening the link only shows a confirm page; a POST from that page consumes the token, so mail scanner prefetches do not burn it. Requests are limited per email and per IP (fixed 15 minute window in D1).
- **Admin token.** `ADMIN_TOKEN_HASH` is either the 64 character hex SHA-256 of the token, for example `printf '%s' "$TOKEN" | sha256sum`, or `pbkdf2$<iterations>$<salt hex>$<hash hex>` (PBKDF2-HMAC-SHA-256, 32 byte output, at most 100000 iterations, the Workers limit). Comparison is constant time.

Sessions last 8 hours, live in D1 as hashes, and use the cookie `__Host-cw_admin` (HttpOnly, Secure, SameSite=Strict, Path=/). Every POST needs a same-origin `Origin` header and, once signed in, the per-session CSRF field.

## Pages

Dashboard (counts, version, config flags), users (disable, enable, deauthorise sessions by rotating the security stamp, delete with confirmation, invite by email), organisations (delete), diagnostics (storage and configuration).

Invitations are stored in the `invitations` table; registration gating (TASKS #22) is expected to consume them. Deleting a user or organisation also removes its R2 attachment and Send blobs.
