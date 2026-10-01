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
2. With a token it calls `GET /api/cloudwarden/me` (Bearer), which returns `{"isAdmin": boolean, "email": string}`. `isAdmin` is false whenever `ADMIN_ENABLED` is not `true`.
3. For admins it adds an **Instance admin** item to the vault side navigation (found by `aria-label="Side navigation"`). The item is a deep clone of the vault's own Reports item (structure, classes and icon wrapper, icon switched to `bwi-wrench`, active state stripped), inserted directly after Settings, or after Reports when there is no Settings item, with a small fixed button bottom-left as a fallback if the navigation cannot be found. A `MutationObserver` keeps it in place as the vault re-renders. The link is removed when a 401 is seen for the current token or the vault goes to login, lock or logout.
4. Clicking it sends `POST /admin/session/exchange` with `Authorization: Bearer <vault access token>`, then navigates to `/admin`.

`POST /admin/session/exchange`:

- requires `Origin` equal to the `DOMAIN` origin, and `Sec-Fetch-Site: same-origin` when that header is present (403 otherwise);
- is rate limited per IP (30 per 15 minutes, 429);
- verifies the token like any API call (signature, expiry, issuer, `api` scope, security stamp, account enabled; 401 otherwise);
- requires the address to be in `ADMIN_EMAILS` (403 otherwise);
- creates an admin session recording the user's email as subject, the user id and the current security stamp, and returns 204 with the session cookie. Any prior admin session of the same browser is deleted. These sessions last 1 hour and are renewed on each admin request (sliding expiry).

`POST /admin/session/end` ends this browser's admin session without a CSRF field; instead it requires the strict same-origin check above. The vault script calls it when it sees a 401 for the current token or the vault goes to login, lock or logout, so vault logout also ends admin access.

On every request a vault-derived session is checked against the user row: it ends (and is deleted) when the security stamp has changed (password change, "deauthorise sessions", 2FA removal), the account is disabled or deleted, or the address is no longer in `ADMIN_EMAILS`.

An unauthenticated visit to `/admin` shows a short page pointing to the vault login (`/#/login`) and to recovery.

## Break-glass recovery

`/admin/recovery` keeps the earlier sign-in methods for when no admin can use the vault:

- **Magic link.** `POST /admin/recovery/magic-link`. The form always answers "if that address is an admin, a link was sent". A 32 byte token is created (only its SHA-256 is stored, 15 minute expiry, single use). Opening `/admin/recovery/magic?token=...` only shows a confirm page; a POST from that page consumes the token, so mail scanner prefetches do not burn it. Requests are limited per email and per IP (fixed 15 minute window in D1).
- **Admin token.** `POST /admin/recovery/token`. `ADMIN_TOKEN_HASH` is either the 64 character hex SHA-256 of the token, for example `printf '%s' "$TOKEN" | sha256sum`, or `pbkdf2$<iterations>$<salt hex>$<hash hex>` (PBKDF2-HMAC-SHA-256, 32 byte output, at most 100000 iterations, the Workers limit). Comparison is constant time.

Recovery sessions are not tied to a vault account.

## Sessions

Recovery sessions last 8 hours and vault-derived ones 1 hour (sliding). Sessions live in D1 as hashes, and use the cookie `__Host-cw_admin` (HttpOnly, Secure, SameSite=Strict, Path=/). Every POST needs a same-origin `Origin` header and, once signed in, the per-session CSRF field. The header shows the signed-in admin's email; **Sign out** ends the admin session only (the vault stays signed in), and **Back to vault** in the sidebar returns to the web vault. The sidebar uses the vault's navigation colours (light and dark).

## Pages

Dashboard (counts, version, config flags), users (disable, enable, deauthorise sessions by rotating the security stamp, remove 2FA with confirmation (deletes providers and remembered devices, rotates the stamp), delete with confirmation, per-user created date, last active, item count and 2FA providers, invite by email), organisations (delete), diagnostics (storage and configuration).

Invitations are stored in the `invitations` table; registration gating (TASKS #22) is expected to consume them. Deleting a user or organisation also removes its R2 attachment and Send blobs.

## JSON admin API

Native admin pages in the web vault use a JSON API under `/api/cloudwarden/admin/*` instead of the cookie session. It takes the vault's own access token (`Authorization: Bearer`), so it is not exposed to CSRF. The caller must be an enabled user whose address is in `ADMIN_EMAILS`, with `ADMIN_ENABLED` set to `true`; anything else is 403 in the standard error shape. Each admin is limited to 120 requests per minute (429). Responses are `Cache-Control: no-store`, camelCase JSON. The operations are documented under the `x-cloudwarden` tag in `docs/api/openapi.yaml`.

| Method and path | Purpose |
|---|---|
| `GET /overview` | Counts, version and configuration flags |
| `GET /users?page=&pageSize=` | Users, newest first (page size at most 100) |
| `POST /users/:id/disable`, `/enable`, `/deauthorize`, `/remove-2fa` | Account actions (204; 404 for an unknown user; you cannot disable yourself) |
| `DELETE /users/:id` | Delete a user and data. Refused for your own account and for the sole owner of an organisation (400) |
| `GET /invitations`, `POST /invitations` `{email}`, `DELETE /invitations/:email` | Invitations; create returns `emailStatus` of `sent`, `not-configured` or `failed` |
| `GET /organizations`, `DELETE /organizations/:id` | Organisations and deletion (members are kept) |
| `GET /diagnostics` | Storage figures and configuration |

Both the HTML admin and this API call `src/admin/service.ts`. Every write also inserts a row in `events` (types 9001 to 9008, outside the codes the official clients use). The API records the acting admin; the HTML admin session has no user id, so its events have no acting user. Invitation events never contain the address.
