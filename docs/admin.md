# Admin UI

Server-rendered admin area at `/admin` (TASKS #140, #205). It returns 404 unless `ADMIN_ENABLED` is `true`. The admin pages use no JavaScript and no external resources; the CSP is `default-src 'none'` with a per-response style nonce.

## Configuration

| Name | Kind | Purpose |
|---|---|---|
| `ADMIN_ENABLED` | var | `true` to enable the UI |
| `ADMIN_EMAILS` | secret | Comma-separated admin addresses (case-insensitive). Vault accounts with these addresses are admins |
| `ADMIN_TOKEN_HASH` | secret | Hash of a break-glass recovery token (optional) |
| `EMAIL` | `send_email` binding | Cloudflare Email Service, needed for recovery magic links and invites |
| `MAIL_FROM` | var | Sender address, on an onboarded sending domain |
| `DOMAIN` | var | Public base URL, used for emailed links and the exchange origin check |

## Sign-in: the vault login

Admin sign-in is the normal web vault login. A vault user is an admin when their account is enabled and their email is in `ADMIN_EMAILS`. There is no separate admin password.

1. The web vault loads `cloudwarden/admin-link.js` (added by `pnpm web-vault:fetch`, see `docs/web-vault.md`). It wraps `window.fetch` and keeps the most recent same-origin `Authorization` bearer sent to `/api/` in a closure variable only. It never logs, stores or puts the token in a URL.
2. With a token it calls `GET /api/cloudwarden/me` (Bearer), which returns `{"isAdmin": boolean}`. `isAdmin` is false whenever `ADMIN_ENABLED` is not `true`.
3. For admins it adds an **Instance admin** item to the vault side navigation (found by `aria-label="Side navigation"`, styled by copying a neighbouring item's classes), with a small fixed button bottom-left as a fallback if the navigation cannot be found. A `MutationObserver` keeps it in place as the vault re-renders. The link is removed when a 401 is seen for the current token or the vault goes to login, lock or logout.
4. Clicking it sends `POST /admin/session/exchange` with `Authorization: Bearer <vault access token>`, then navigates to `/admin`.

`POST /admin/session/exchange`:

- requires `Origin` equal to the `DOMAIN` origin, and `Sec-Fetch-Site: same-origin` when that header is present (403 otherwise);
- is rate limited per IP (30 per 15 minutes, 429);
- verifies the token like any API call (signature, expiry, issuer, `api` scope, security stamp, account enabled; 401 otherwise);
- requires the address to be in `ADMIN_EMAILS` (403 otherwise);
- creates an admin session recording the user's email as subject, the user id and the current security stamp, and returns 204 with the session cookie.

On every request a vault-derived session is checked against the user row: it ends (and is deleted) when the security stamp has changed (password change, "deauthorise sessions", 2FA removal), the account is disabled or deleted, or the address is no longer in `ADMIN_EMAILS`.

An unauthenticated visit to `/admin` shows a short page pointing to the vault login (`/#/login`) and to recovery.

## Break-glass recovery

`/admin/recovery` keeps the earlier sign-in methods for when no admin can use the vault:

- **Magic link.** `POST /admin/recovery/magic-link`. The form always answers "if that address is an admin, a link was sent". A 32 byte token is created (only its SHA-256 is stored, 15 minute expiry, single use). Opening `/admin/recovery/magic?token=...` only shows a confirm page; a POST from that page consumes the token, so mail scanner prefetches do not burn it. Requests are limited per email and per IP (fixed 15 minute window in D1).
- **Admin token.** `POST /admin/recovery/token`. `ADMIN_TOKEN_HASH` is either the 64 character hex SHA-256 of the token, for example `printf '%s' "$TOKEN" | sha256sum`, or `pbkdf2$<iterations>$<salt hex>$<hash hex>` (PBKDF2-HMAC-SHA-256, 32 byte output, at most 100000 iterations, the Workers limit). Comparison is constant time.

Recovery sessions are not tied to a vault account.

## Sessions

Sessions last 8 hours, live in D1 as hashes, and use the cookie `__Host-cw_admin` (HttpOnly, Secure, SameSite=Strict, Path=/). Every POST needs a same-origin `Origin` header and, once signed in, the per-session CSRF field. The header shows the signed-in admin's email; **Sign out** ends the admin session only (the vault stays signed in), and **Back to vault** in the sidebar returns to the web vault.

## Pages

Dashboard (counts, version, config flags), users (disable, enable, deauthorise sessions by rotating the security stamp, remove 2FA with confirmation (deletes providers and remembered devices, rotates the stamp), delete with confirmation, per-user created date, last active, item count and 2FA providers, invite by email), organisations (delete), diagnostics (storage and configuration).

Invitations are stored in the `invitations` table; registration gating (TASKS #22) is expected to consume them. Deleting a user or organisation also removes its R2 attachment and Send blobs.
