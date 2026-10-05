# Instance admin

Instance administration is the native **Instance admin** section of the web client
(`web/apps/web/src/app/cloudwarden/instance-admin/`), reached through the normal vault login and
backed by the JSON API under `/api/cloudwarden/admin/*` (`src/admin/api.ts`, `src/admin/service.ts`).
The earlier server-rendered `/admin` (magic link and admin token sign-in, cookie sessions) was
removed (TASKS #226): `/admin` and `/admin/*` now return the standard 404 JSON.

## Configuration

| Name | Kind | Purpose |
|---|---|---|
| `ADMIN_ENABLED` | var | `true` to enable the admin API. Anything else makes the API answer 403 and `/api/cloudwarden/me` report `isAdmin: false` |
| `ADMIN_EMAILS` | secret | Comma-separated owner addresses (case-insensitive). The bootstrap set of instance admins, shown as **Owner**; only changeable on the server side |
| `EMAIL` | `send_email` binding | Cloudflare Email Service, needed for invitations, verification and two-factor email |
| `MAIL_FROM` | var | Sender address, on an onboarded sending domain |
| `DOMAIN` | var | Public base URL, used for emailed links |

## Sign-in

There is no separate admin password. A vault user is an admin when `ADMIN_ENABLED` is `true`, the
account is enabled, its email is verified and it is an **owner** (address in `ADMIN_EMAILS`) or was
granted the **admin** role (see Instance roles).

1. After login the client calls `GET /api/cloudwarden/me` with its own access token, which returns
   `{"isAdmin": boolean, "email": string, "role": "owner" | "admin" | "user"}`.
2. For admins it shows the Instance admin navigation group (overview, users, invitations,
   organisations, diagnostics). A route guard keeps non-admins out of the pages.
3. The pages call the JSON admin API through the client's authenticated `ApiService`, so the access
   token stays inside the client's normal request pipeline.

## JSON admin API

The API takes the vault's own access token (`Authorization: Bearer`) and never a cookie, so it is
not exposed to CSRF. Anything other than an admin is 403 in the standard error shape. Each admin is
limited to 120 requests per minute (429). Responses are `Cache-Control: no-store`, camelCase JSON.
The operations are documented under the `x-cloudwarden` tag in `docs/api/openapi.yaml`.

| Method and path | Purpose |
|---|---|
| `GET /overview` | Counts, version and configuration flags |
| `GET /users?page=&pageSize=` | Users, newest first (page size at most 100) |
| `PUT` or `POST /users/:id/role` `{role: "admin" \| "user"}` | Set the instance role (204; see Instance roles). The users list returns each user's `role` and a `self` flag |
| `POST /users/:id/disable`, `/enable`, `/deauthorize`, `/remove-2fa` | Account actions (204; 404 for an unknown user; refused with 400 for any account listed in `ADMIN_EMAILS`, yourself included) |
| `DELETE /users/:id` | Delete a user and data. Refused for your own account and for the sole owner of an organisation (400) |
| `GET /invitations`, `POST /invitations` `{email}`, `DELETE /invitations/:email` | Invitations; create returns `emailStatus` of `sent`, `not-configured` or `failed` |
| `GET /organizations`, `DELETE /organizations/:id` | Organisations and deletion (members are kept) |
| `GET /diagnostics` | Storage figures and configuration |

Invitations are stored in the `invitations` table and gate registration. Deleting a user or
organisation also removes its R2 attachment and Send blobs. Every write inserts a row in `events`
(types 9001 to 9013, outside the codes the official clients use) recording the acting admin.
Invitation events never contain the address.

Registration and admin addresses: invitations and `SIGNUPS_DOMAINS_WHITELIST` only say who may
register, so those registrations need the emailed verification token (proof of mailbox control).
Open signups may skip it, except for addresses in `ADMIN_EMAILS`, which always need the token (and
get none when no mail transport is configured). Admin checks, including `/api/cloudwarden/me`, also
require a verified email.

## Instance roles

Every user has one of three instance roles, shown in the **Role** column of Instance admin, Users:

| Role | Source | May use the admin API |
|---|---|---|
| Owner | The address is in `ADMIN_EMAILS` (the bootstrap set). Not stored in the database | Yes |
| Admin | Granted in the database (`users.instance_role`) by an owner or admin | Yes |
| User | Default | No |

Owners and admins change a user's role from the Role menu (a confirmation dialog follows) or with
`PUT /api/cloudwarden/admin/users/:id/role`. The rules, all enforced on the server:

- Only an owner or admin may call it; everyone else gets 403, so nobody can promote themselves.
- The role must be `admin` or `user`; `owner` and anything else is a 400. Owners are only defined by
  `ADMIN_EMAILS`, which the UI cannot edit (the Owner row is locked, with a tooltip saying so).
- An owner cannot be granted a role (400), and nobody can change their own role (400). Owners always
  exist because they come from the server setting, so the instance cannot be left without an admin.
  Revoking (`user`) is allowed for an owner address: it changes nothing while the address stays in
  `ADMIN_EMAILS`, but it clears a stored `admin` role so it does not come back if the address is
  later removed from the setting (the D1 value is otherwise left as it was).
- A federation stand-in account (a peer's user on the hosting side) cannot be made an admin (400).
- Only a verified, enabled, non-stand-in user can be made an admin (400 otherwise). The grant
  statement re-checks all of this and the email read at check time. Taking the role away is always
  allowed; revoking a user that no longer exists answers 404. Admin rights still need a verified address at every request, so clearing verification
  removes them at once.
- A granted role is **cleared when the user changes their email address**, with or without mail
  (it was granted to the person at the old address, and a changed address must never inherit it).
  An owner or admin must grant it again. Owners are unaffected because `ADMIN_EMAILS` names addresses.
- Granting and revoking are audited as event 9013 (`UserRoleChanged`) with the acting admin and the
  target user. The endpoint shares the per-admin rate limit of 120 requests per minute.
- Instance admins are **not recoverable** by organisation admins or emergency contacts. Organisation
  account recovery (admin reset of master password or two-step login) and emergency access takeover
  answer 400 when the target is an owner address or holds a granted admin role, and both paths also
  set `instance_role = 'user'` when they change credentials, so a recovered or taken-over account
  never carries instance admin rights. To recover an admin, revoke the role first.
- The existing protection of owner accounts stays: disable, deauthorize, remove 2FA and delete are
  refused for owners. A granted admin is managed like any user (set them back to User first if you
  want them to lose the role).
- If a granted admin must be removed without any admin UI, run
  `UPDATE users SET instance_role = 'user' WHERE lower(email) = lower('admin@example.com')` with
  `cf d1 query` (see Recovery).

Federation admin routes (`/api/cloudwarden/federation/admin/*`, `isInstanceAdmin`) use the same
check, so granted admins can manage peers too.

## Recovery

If no admin can use the web client (for example the admin account is disabled, has lost its second
factor, or is not recognised as an admin), the operator restores access from the Cloudflare side
without any admin UI. Use `cf d1 query` against the database; replace the placeholders. Run the
`SELECT` first to confirm the row, and keep the statements to one account.

1. **Make sure the address is an admin.** Check that `ADMIN_ENABLED` is `true` and that the address
   is in the `ADMIN_EMAILS` secret (set it again with `pnpm exec cf workers secrets update
   ADMIN_EMAILS`; values are comma-separated and case-insensitive).
2. **Check the account state.**

   ```sh
   pnpm exec cf d1 query <database-id> --sql \
     "SELECT uuid, enabled, verified_at, created_at FROM users WHERE lower(email) = lower('admin@example.com')"
   ```

3. **Mark the email verified** (an unverified address is never an admin):

   ```sh
   pnpm exec cf d1 query <database-id> --sql \
     "UPDATE users SET verified_at = CAST(strftime('%s','now') AS INTEGER) * 1000 WHERE lower(email) = lower('admin@example.com') AND verified_at IS NULL"
   ```

4. **Re-enable a disabled account:**

   ```sh
   pnpm exec cf d1 query <database-id> --sql \
     "UPDATE users SET enabled = 1 WHERE lower(email) = lower('admin@example.com')"
   ```

5. **Clear two-factor** when the second factor is lost. This deletes every provider and remembered
   device and the recovery code, and rotates the security stamp so existing sessions end. Use the
   `uuid` from step 2:

   ```sh
   pnpm exec cf d1 query <database-id> --sql \
     "DELETE FROM twofactor WHERE user_uuid = '<uuid>'; UPDATE devices SET twofactor_remember = NULL WHERE user_uuid = '<uuid>'; UPDATE users SET totp_recover = NULL, security_stamp = lower(hex(randomblob(16))), updated_at = CAST(strftime('%s','now') AS INTEGER) * 1000 WHERE uuid = '<uuid>'"
   ```

6. Sign in to the web client normally and open **Instance admin**.

A forgotten master password cannot be recovered by the operator: the vault is encrypted with a key
derived from it. The account can only be deleted and registered again (invite the address first if
signups are closed). No secret is needed or printed by any step above; never paste tokens or
password hashes into tickets or logs.
