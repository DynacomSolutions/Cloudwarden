# Secrets Manager

Cloudwarden serves the Bitwarden Secrets Manager API (TASKS #220 to #225): projects, secrets, machine
accounts (called service accounts on the wire), access tokens, access policies, counts, events and
machine login. Like the rest of the server it stores only what clients encrypt: project names,
secret keys, values and notes, machine account and token names are EncStrings under the
organisation key, and the server never sees plaintext.

Phase 1 is the server API (TASKS #220 to #225). Phase 2 is a user interface in the forked web
client (TASKS #227 to #230, see "Web client" below).

## Sources and licensing

Built only from wire contracts observable in GPL-3.0 code, never from Bitwarden server code or any
`bitwarden_license/` directory:

| Source | Licence | Used for |
|---|---|---|
| github.com/bitwarden/sdk-internal, commit `9acb7241` (2026-10-01), `crates/bitwarden-api-api` (generated API client: `apis/*_api.rs` paths and methods, `models/*.rs` field names) | GPL-3.0-only OR Bitwarden SDK License (dual) | Every Secrets Manager path, request and response shape |
| same, `crates/bitwarden-core` (`auth/access_token.rs`, `auth/jwt_token.rs`, `auth/login/access_token.rs`, `auth/api/request/access_token_request.rs`, `auth/api/response/identity_*`) | same | Access token format, token request, token response fields, JWT claims the SDK reads |
| same, `crates/bitwarden-crypto` (`keys/shareable_key.rs`, `util.rs`) | same | Access token key derivation (e2e client only; the server never derives keys) |
| github.com/bitwarden/clients `web-v2026.9.1` (GPL parts, already vendored under `web/`) | GPL-3.0 | `accessSecretsManager` on member invite and update, `PUT .../users/enable-secrets-manager`, Secrets Manager event codes 2100 to 2305 |

`github.com/bitwarden/sdk-sm` (home of `bws` and the `bitwarden-sm` crate) is under the proprietary
Bitwarden Software Development Kit License Agreement, not GPL or a permissive licence. None of its
source is read or used to build Cloudwarden; the `bitwarden-sm` crate in sdk-internal sits under
`bitwarden_license/` and was deleted from the local checkout before anything else was read. The
official `bws` release binary is only run, as a client, against Cloudwarden. That is the owner
decision of 2 October 2026 (TASKS #225): Cloudwarden uses Bitwarden's official interoperable
clients, including `bws`, against Cloudwarden. The binary is downloaded by `pnpm e2e`, never
committed or redistributed.

Consequences:

- How `bws` sequences calls is whatever the official client does; the server implements the whole
  generated API surface, and `pnpm e2e` proves the `bws` command set below against it.
- `e2e/sm-client.mjs`, a small machine client written from the GPL contract above, still runs
  through the TLS proxy next to `bws`: parse the access token, derive its key, log in, decrypt the
  payload to the organisation key, then list, get and sync secrets. Its key derivation is checked
  against the vector published in `bitwarden-core` (`scripts/sm-client.test.mjs`).

## Using `bws` with Cloudwarden

Create a machine account and access token (see Machine login), grant the machine account the
projects it needs, then point `bws` at the server:

```sh
export BWS_ACCESS_TOKEN='0.<tokenId>.<clientSecret>:<seed>'
bws --server-url https://vault.example.com project list
bws --server-url https://vault.example.com secret get <secret-id>
```

`--server-url` (or `BWS_SERVER_URL`, or `server_url` in the `bws` config file) is the server root,
without `/api` or `/identity`. `bws` insists on HTTPS and uses the platform trust store; for a
private CA set `SSL_CERT_FILE` to the CA certificate. `bws secret create` needs a project the
machine account has write on. Supported and tested: `project list`, `secret list`, `secret get`,
`secret create`, `secret edit`, `secret delete`.

`pnpm e2e` runs exactly these against a local server through a TLS proxy with a throwaway CA. The
`bws` release is pinned in `e2e/bws.lock.json` (version, URL, sha256), verified before it is
extracted or run, and cached in the gitignored `e2e/.cache`. To bump it, change the lock file
from the release's published checksums and re-run `pnpm e2e` (Linux x64 only).

## Machine login

An access token as shown to the user is `0.<accessTokenId>.<clientSecret>:<seed>`; the seed is 16
random bytes in base64 and never reaches the server.

1. Admin creates a token: `POST /api/service-accounts/{id}/access-tokens` with `name`,
   `encryptedPayload`, `key` and `expireAt`. `encryptedPayload` is the EncString of
   `{"encryptionKey":"<org key b64>"}` under the key derived from the seed (HMAC-SHA256 keyed
   `bitwarden-accesstoken`, then HKDF-Expand with info `sm-access-token` to 64 bytes). `key` is
   opaque client data. The server generates a 30 character alphanumeric `clientSecret`, returns it
   once and stores only its SHA-256.
2. The client sends `POST /identity/connect/token` with `grant_type=client_credentials`,
   `scope=api.secrets`, `client_id=<accessTokenId>` (a bare UUID, no prefix) and
   `client_secret=<clientSecret>`.
3. The response is `access_token`, `expires_in`, `token_type`, `scope` and `encrypted_payload`
   (the stored payload). It deliberately has no `Kdf` or `Key`: the SDK first tries to read the
   body as a user login, which needs `Kdf`. The JWT carries `sub` (machine account id),
   `organization` (the SDK reads it to bind the key), `client_id` (token id), `scope: ["api.secrets"]`
   and `exp`, at most one hour and never past the token's own expiry.

Failures (`invalid_client`, HTTP 400): unknown token, wrong secret, expired token.

## Authorisation model

`requireSmAuth` (src/sm/auth.ts) guards only Secrets Manager paths. It accepts a member access
token (same checks as everywhere else) or a machine token, for which it re-reads the token row on
every request: a revoked token, a deleted machine account or a passed expiry fails at once, not at
JWT expiry. Every other route still uses `requireAuth`, which requires scope `api`, so machine
tokens get 401 there. The Secrets Manager router is mounted before the organisation routers so
their member-only middleware never sees machine requests.

Members:

- Need a confirmed membership with `accessSecretsManager`; otherwise the organisation is a 404.
  Owners get it when they create an organisation; the migration grants it to existing confirmed
  owners and admins. Admins toggle it per member (invite and update bodies) or in bulk
  (`PUT /api/organizations/{orgId}/users/enable-secrets-manager`).
- Owners and admins with access read and write everything.
- Other members reach a project through a member or group policy, a secret through a direct policy
  or any policy on its project, a machine account through a member or group policy on it. `write`
  implies `read`; policies from several sources combine to the most permissive.
- A member who creates a project or a machine account is granted read and write on it.
- Creating an access token needs write on the machine account and, for non-admins, read on every
  project and secret granted to it, so a token never reaches further than its creator.
- Only confirmed members can be grantees. `accessSecretsManager` is changed only by owners, admins
  or custom members who already have it, and never on oneself. Access decisions read the primary.
- Only owners and admins may keep a secret outside every project; at most one project per secret.

Machine accounts:

- Reach only their own organisation, and only projects and secrets granted to them (project
  policies via `PUT /api/projects/{id}/access-policies/service-accounts` or
  `PUT /api/service-accounts/{id}/granted-policies`, or direct secret policies).
- May read, create, edit and delete secrets and rename and delete projects where they hold write,
  and create projects (which grants them write). They never see machine accounts, tokens, access
  policies or counts (404).

Status codes: no read access is 404 (things you cannot see do not exist); read without write is
403 on a change. Bulk deletes return one row per id with `error: "access denied"` for ids that do
not exist or cannot be deleted. `get-by-ids` is all or nothing (404).

## Sync

`GET /api/organizations/{id}/secrets/sync?lastSyncedDate=` compares against a per-organisation
`secrets_revision_date`, bumped by every Secrets Manager write in the organisation (secrets,
projects, relations, policies) and by membership, group and access-flag changes. When nothing changed after `lastSyncedDate` the answer is
`hasChanges: false` with `secrets: null`; otherwise every secret the caller can read, with values.
This over-reports (a change a machine cannot see still sets `hasChanges`), never under-reports.

## Events

Recorded in the existing events table (new columns `secret_uuid`, `project_uuid`,
`service_account_uuid`, `granted_service_account_uuid`, returned as `secretId`, `projectId`,
`serviceAccountId`, `grantedServiceAccountId`):

| Code | When |
|---|---|
| 2100 Secret_Retrieved | A machine account reads secret values (get, get-by-ids, sync with data) |
| 2101, 2102, 2103 | Secret created, edited, deleted |
| 2201, 2202, 2203 | Project created, edited, deleted |
| 2300 to 2303 | Member or group added to, or removed from, a machine account |
| 2304, 2305 | Machine account created, deleted |

Machine actions set `serviceAccountId` and leave `actingUserId` null. They appear in the
organisation event log and in `GET /api/sm/events/service-accounts/{id}`.

## Endpoints

All under `/api`, documented under the `secrets-manager` tag in `docs/api/openapi.yaml`.
M = machine tokens accepted.

| Method and path | M |
|---|---|
| `POST /organizations/{orgId}/projects`, `GET /organizations/{orgId}/projects` | yes |
| `GET /projects/{id}`, `PUT /projects/{id}`, `POST /projects/delete` | yes |
| `POST /organizations/{orgId}/secrets`, `GET /organizations/{orgId}/secrets` | yes |
| `GET /organizations/{orgId}/secrets/sync` | yes |
| `GET /projects/{projectId}/secrets` | yes |
| `GET /secrets/{id}`, `PUT /secrets/{id}`, `POST /secrets/get-by-ids`, `POST /secrets/delete` | yes |
| `POST /organizations/{orgId}/service-accounts`, `GET /organizations/{orgId}/service-accounts` | no |
| `GET /service-accounts/{id}`, `PUT /service-accounts/{id}`, `POST /service-accounts/delete` | no |
| `GET`, `POST /service-accounts/{id}/access-tokens`, `POST .../access-tokens/revoke` | no |
| `GET`, `PUT /projects/{id}/access-policies/people` and `.../service-accounts` | no |
| `GET /secrets/{secretId}/access-policies` | no |
| `GET`, `PUT /service-accounts/{id}/access-policies/people` and `.../granted-policies` | no |
| `GET /organizations/{id}/access-policies/{people,service-accounts,projects}/potential-grantees` | no |
| `GET /organizations/{orgId}/sm-counts`, `/projects/{id}/sm-counts`, `/service-accounts/{id}/sm-counts` | no |
| `GET /sm/events/service-accounts/{id}` | no |
| `PUT /organizations/{orgId}/users/enable-secrets-manager` | no |

## Web client

Cloudwarden's web client has its own Secrets Manager pages under
`web/apps/web/src/app/cloudwarden/secrets-manager/`, written from scratch against this document
and the OpenAPI spec. Bitwarden's Secrets Manager web app is under the Bitwarden License
(`bitwarden_license/`) and was neither vendored nor read; `pnpm check:web-licence` guards that.

- Route `/#/sm/<organizationId>` (guarded: the organisation must use Secrets Manager and the
  member must have `accessSecretsManager`). The product switcher shows "Secrets Manager" when the
  user has such an organisation.
- Projects: list, create, rename, bulk delete; a project page with its secrets, a people and
  groups access editor (`PUT /projects/{id}/access-policies/people`) and the machine accounts
  that can reach it.
- Secrets: list for the organisation or a project, create, view (hidden value with reveal and
  copy), edit key, value, note and project, bulk delete. Only owners and admins are offered
  "No project".
- Machine accounts: list, create, rename, bulk delete; per-account project access with read or
  read and write (`PUT /service-accounts/{id}/granted-policies`), a people editor and access
  tokens.
- Access tokens: the client picks a 16 byte seed, derives the token key (as in "Machine login"),
  and sends `name` and `key` (the seed in base64) as EncStrings under the organisation key and
  `encryptedPayload` (`{"encryptionKey":"<org key b64>"}`) under the token key. The resulting
  `0.<id>.<clientSecret>:<seed>` is shown once with a copy button and a warning; it is never
  stored. Tokens can be listed and revoked.
- Members: the existing member dialog in the Admin Console carries the "Secrets Manager" access
  checkbox (`accessSecretsManager` on invite and update) and the bulk "Activate Secrets Manager"
  action; both are shown only to those who can manage members. The dialogs first read
  `GET /api/organizations/{id}/billing/vnext/self-host/metadata`, which Cloudwarden now serves
  (no Secrets Manager standalone plan, occupied seats = members not revoked); before that the
  member dialogs did not open at all.

Encryption uses the client's own `KeyService` (organisation key) and `EncryptService` (type 2
EncStrings). The token helpers (`sm-crypto.ts`) are checked by Jest against the `bitwarden-core`
vector and by running `e2e/sm-client.mjs`'s parser and decryptor over a UI-built token.

## Secret versions, import and export (TASKS #224)

Shapes come from `apis/secret_versions_api.rs`, `apis/secrets_manager_porting_api.rs` and the
`SecretVersionResponseModel`, `RestoreSecretVersionRequestModel`, `SmExportResponseModel` and
`SmImportRequestModel` models of the same `bitwarden-api-api` crate (GPL-3.0).

- A change that alters the stored value records the value it replaces (`sm_secret_versions`,
  migration `0018`) with the time of the change and the editor: a member (name read live from the
  account) or a machine account (its EncString name). The stored value decides, `valueChanged` is
  only accepted. At most 50 versions are kept per secret, the oldest are dropped. The current value
  is not a version. Restoring sets the secret to the version and records the value it replaced.
- `GET /secrets/{id}/versions` (newest first), `GET /secret-versions/{id}`,
  `POST /secret-versions/get-by-ids`, `POST /secret-versions/delete` (all-or-nothing, empty
  response) and `PUT /secrets/{id}/versions/restore`. Reading needs read access to the secret,
  restoring and deleting need write access; no access is a 404. Machine accounts may call them.
  `get-by-ids` takes at most 100 ids. History is not scoped to who made a change: anyone who gains
  read access to a secret later (a project grant, say) can read all its earlier values, so rotate a
  secret rather than relying on old versions being hidden, and delete versions that must go.
- `GET /sm/{organizationId}/export` returns the projects and secrets the caller can read (admins:
  all) as encrypted fields; `POST /sm/{organizationId}/import` creates them. Both are for members,
  not machine accounts. Ids in a file only link secrets to projects; every object is created under
  a fresh id, so an import cannot overwrite or claim existing data. Importers get creator access
  to the projects they create, and only owners and admins may import secrets without a project.
  Imports above 400 statements are written in several batches (D1 limit), projects first; a project
  and its creator access policy always share a batch. A failure part way keeps what was written (a
  partial import, to be retried or cleaned up) and the secrets revision is bumped regardless, so
  clients resync what exists.
- Web client (TASKS #230): the secret dialog has a "Version history" button (list with date and
  editor, reveal and copy a value, restore, delete; the last two only with write access). The
  Secrets page has Export, which downloads a JSON file of decrypted projects and secrets (not
  encrypted: store it safely), and Import, which reads such a file in the browser, validates it
  (ids, sizes, at most one project per secret, links inside the file, at most 5000 of each),
  shows a summary, encrypts with the organisation key and posts it. Loose secrets are blocked
  for non-admins before sending. The secret dialog also has an "Access" section: direct policies of
  members, groups and machine accounts on that secret (read from `GET /secrets/{id}/access-policies`,
  written with the secret through `accessPoliciesRequests`, as the contract does; there is no
  separate write endpoint). A machine account page has an "Events" tab listing
  `GET /sm/events/service-accounts/{id}` with paging. Specs: `sm-access-events.spec.ts`, `sm-import.spec.ts`,
  `sm-secret-versions-dialog.component.spec.ts`, `sm-secrets-page.spec.ts`.

## Not implemented (deferred)

- Machine account token refresh: tokens are re-issued by logging in again, as the SDK does.
- Seat or machine account limits: none apply on a self-hosted server.
