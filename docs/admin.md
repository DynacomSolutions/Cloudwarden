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
| `DOMAIN` | var | Public base URL, used for emailed links |

## Sign-in: the web client

Day to day administration happens in the web client itself (TASKS #213): admins sign in to the
vault normally and choose **Instance admin** in the side navigation. A vault user is an admin
when their account is enabled, their email is verified and it is in `ADMIN_EMAILS`. There is no
separate admin password.

1. After login the client calls `GET /api/cloudwarden/me` with its own access token, which
   returns `{"isAdmin": boolean, "email": string}`. `isAdmin` is false whenever `ADMIN_ENABLED`
   is not `true`.
2. For admins it shows the Instance admin navigation group (overview, users, invitations,
   organisations, diagnostics). The pages are Angular components in
   `web/apps/web/src/app/cloudwarden/instance-admin/` built from the client's own component
   library, and a route guard keeps non-admins out of them.
3. The pages call the JSON admin API below through the client's authenticated `ApiService`, so
   the access token stays inside the client's normal request pipeline.

The earlier approach (an injected `admin-link.js` that exchanged the vault token for an admin
cookie at `POST /admin/session/exchange`) is removed, together with `POST /admin/session/end`.
Any vault-derived admin session that still exists is validated as before and expires within an
hour.

An unauthenticated visit to `/admin` shows a short page pointing to the vault and to recovery.

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

The Instance admin pages in the web client use a JSON API under `/api/cloudwarden/admin/*` instead of the cookie session. It takes the vault's own access token (`Authorization: Bearer`), so it is not exposed to CSRF. The caller must be an enabled user whose address is in `ADMIN_EMAILS` and whose email is verified, with `ADMIN_ENABLED` set to `true`; anything else is 403 in the standard error shape. Each admin is limited to 120 requests per minute (429). Responses are `Cache-Control: no-store`, camelCase JSON. The operations are documented under the `x-cloudwarden` tag in `docs/api/openapi.yaml`.

| Method and path | Purpose |
|---|---|
| `GET /overview` | Counts, version and configuration flags |
| `GET /users?page=&pageSize=` | Users, newest first (page size at most 100) |
| `POST /users/:id/disable`, `/enable`, `/deauthorize`, `/remove-2fa` | Account actions (204; 404 for an unknown user; refused with 400 for any account listed in `ADMIN_EMAILS`, yourself included) |
| `DELETE /users/:id` | Delete a user and data. Refused for your own account and for the sole owner of an organisation (400) |
| `GET /invitations`, `POST /invitations` `{email}`, `DELETE /invitations/:email` | Invitations; create returns `emailStatus` of `sent`, `not-configured` or `failed` |
| `GET /organizations`, `DELETE /organizations/:id` | Organisations and deletion (members are kept) |
| `GET /diagnostics` | Storage figures and configuration |

Both the HTML admin and this API call `src/admin/service.ts`. Every write also inserts a row in `events` (types 9001 to 9008, outside the codes the official clients use). The API records the acting admin; the HTML admin session has no user id, so its events have no acting user. Invitation events never contain the address.

Registration and admin addresses: invitations and `SIGNUPS_DOMAINS_WHITELIST` only say who may register, so those registrations need the emailed verification token (proof of mailbox control). Open signups may skip it, except for addresses in `ADMIN_EMAILS`, which always need the token (and get none when no mail transport is configured). Admin checks, including `/api/cloudwarden/me`, also require a verified email. Accounts registered before this rule were stamped verified regardless, so review `ADMIN_EMAILS` against existing accounts when upgrading.
