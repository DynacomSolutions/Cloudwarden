# Tasks

Live board for Cloudwarden. Every unit of work gets a stable number here before it starts. Numbers are never reused.

**Status key:** `todo` · `doing` · `blocked` · `done` · `dropped`

**Rules**

1. Add new work here immediately, including anything discovered mid-task.
2. Keep status, owner, blockers and evidence current. Evidence means concrete output (CI run, test count, command result), not "works".
3. Reference the task number in commits and code TODOs, e.g. `// TODO(TASKS #12)`.
4. Never record identifying information here (hosts, account IDs, emails, IPs).
5. Implementation is built from the Bitwarden API contract (#14). Never port code or logic from other server implementations.

---

## Phase 0: Repository foundation

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 1 | Create private repo, noreply commit identity | done | coordinator | Repo exists, private; commits use a noreply address |
| 2 | Toolchain: pnpm, TypeScript strict, Biome, Vitest in workerd, `cf` config | done | agent | `pnpm lint`, `pnpm typecheck`, `pnpm test` green |
| 3 | Worker skeleton: Hono app, route stubs, error format, security headers | done | agent | Stub routes respond; unimplemented routes return 501 |
| 4 | Initial D1 schema and migration (Drizzle) | done | agent | Migration applies in tests |
| 5 | Identifier guard (`scripts/check-identifiers.mjs`) with tests | done | agent | `pnpm test:scripts` green; repo scan clean |
| 6 | Git hooks (lefthook): Biome, identifiers, gitleaks, author email, commitlint, pre-push typecheck and tests | done | agent | Hooks install on `pnpm install` |
| 7 | CI: lint, typecheck, test, identifiers, commitlint, secret scan, actionlint, zizmor | done | agent | Workflows pass on `main` |
| 13 | Move all CI to the self-hosted `k3s-runners` scale set; gitleaks replaces trufflehog; drop GitHub Advanced Security workflows (CodeQL, dependency review, Scorecard) and CODEOWNERS (owner decision: security is gitleaks, own CI and local hooks only) | done | coordinator | All workflows green on `k3s-runners`; no GitHub-hosted jobs |
| 8 | Repo settings: Dependabot alerts (no update PRs), `main` ruleset (PR required, `CI Status` required, no force push, linear history) | done | coordinator | Settings visible via API; see evidence log |
| 9 | Architecture doc and storage ADR | done | coordinator | `docs/architecture.md`, `docs/adr/0001-storage-d1.md` |
| 10 | Choose licence. AGPL-3.0 is a placeholder; with no ported code the choice is open (AGPL-3.0 forces hosted forks to publish changes; MIT or Apache-2.0 maximise adoption) | todo | owner | Owner decision recorded; LICENSE updated |
| 11 | ~~Create `maintainers` team for CODEOWNERS~~ (never requested; CODEOWNERS removed under #13) | dropped | | |
| 14 | Bitwarden API contract as OpenAPI 3.1 (Swagger): `docs/api/openapi.yaml` covering every endpoint the official clients call (Identity, API, Notifications, Icons, Events), with exact paths, methods, headers, auth, request and response schemas, status codes and error shapes; source version recorded per endpoint; rendered static docs (`pnpm api:build`, no external CDN). Pass 1 covers the self-host core; billing, providers, groups, emergency access, Secrets Manager and SCIM are out of scope for now. This is the build contract for every later phase | doing | agent | Spec lints clean; every client-called endpoint present; static docs build; contract tests (#180) generated from it |
| 12 | Local dev on the cluster (`devdeploy`) without committing local hostnames | done | agent | `Dockerfile`, `scripts/dev-container.mjs`, runtime `DEV_ALLOWED_HOSTS`; chart stays out of the repo (`docs/local-dev.md`). Image built and answered `/alive` and API calls under foreign Host headers; an actual `devdeploy` run against the cluster was not done |

## Phase 1: Identity and accounts

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 20 | Decide server-side password hashing (Workers PBKDF2 caps at 100k iterations; options: capped PBKDF2, WASM Argon2id, pure-JS PBKDF2 for imports). Measure CPU time | done | | ADR written with benchmark numbers |
| 21 | `POST /identity/accounts/prelogin` and `/api/accounts/prelogin` backed by D1 | done | | Returns stored KDF settings; unknown users get defaults (no enumeration) |
| 22 | Registration (`/identity/accounts/register`, `register/finish`) gated by `SIGNUPS_ALLOWED` and invites | done | | Official client can create an account |
| 23 | Token endpoint: `password` grant, `refresh_token` grant, `client_credentials` (API key) | done | | Browser extension, desktop and CLI can log in and refresh |
| 24 | JWT signing and key management (algorithm choice, rotation, `JWT_SECRET` handling) | done | | Tokens validate; rotation documented |
| 25 | Devices: register, list, known-device check, trust, deactivate | done | | Device list matches clients |
| 26 | Account: profile, change password, change email, KDF change, key rotation (atomic via `db.batch`) | done | | Key rotation is all-or-nothing under test |
| 27 | Security stamp and session invalidation on credential change | done | | Old tokens rejected after password change |
| 28 | Account deletion and recovery-code flows | done | | |
| 29 | Rate limiting on login, prelogin and 2FA (Workers Rate Limiting binding) | done | | Exceeding limit returns 429 |

## Phase 2: Vault data

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 40 | `GET /api/sync` (profile, folders, ciphers, collections, policies, sends, domains) | done | | Fresh client sync matches stored data; round-trip test covers every cipher type |
| 41 | Ciphers CRUD, soft delete, restore, purge, bulk move and delete | done | | |
| 42 | Folders CRUD | done | | |
| 43 | Revision dates and conflict handling (`lastKnownRevisionDate`) | done | | Stale update rejected like upstream |
| 44 | Equivalent domains settings | done | | |
| 45 | Import endpoint (`/api/ciphers/import`) | done | | Bitwarden JSON export round-trips |

## Phase 3: Organisations

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 60 | Organisations: create, settings, delete | done | | Create returns a profile entry and default collection; delete needs the master password |
| 61 | Members: invite, accept, confirm, roles, revoke, remove | done | | Invite by email through the transport, signed accept token, owner, admin, user, manager and custom roles, bulk variants |
| 62 | Collections and access (users and groups) | done | | Read-only, hide-passwords and manage flags reach sync |
| 63 | Share cipher to organisation (atomic) | done | | Single and bulk share, collection updates and admin endpoints; failed shares change nothing |
| 64 | Policies (master password, 2FA required, personal ownership, send options) | done | | Stored for every type; master password (token response), two-step login and personal ownership are enforced; send options are stored for Phase 4 |
| 65 | Groups | done | | Group collection grants and access-all groups apply in sync and cipher checks |
| 66 | Emergency access | done | | Invite, accept, confirm, initiate, approve, reject, view, takeover and password; wait time is evaluated from timestamps, no scheduler |
| 67 | Event logs | done | | Server events on write paths, `/events/collect`, organisation, cipher and member listings with continuation tokens |

## Phase 4: Sends and attachments

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 80 | R2 attachment upload, download (signed short-lived URLs), delete | done | | Large file works within Worker body limit; limit documented |
| 81 | Text Sends | done | | |
| 82 | File Sends via R2 | done | | |
| 83 | Send access endpoints (password, max access count, expiry, deletion date) | done | | |
| 84 | Scheduled purge of expired Sends and orphaned blobs (Cron Trigger) | done | | |
| 250 | Per-member favourites and folders for organisation items: table `cipher_user_state` (favourite and archive date per member), returned in sync, cipher, organisation-details and share responses; a member's update or partial never touches another member's flags; folders were already per member (`folders_ciphers`) | done | agent | `test/archive.test.ts` (two members see independent favourite, archive and folder on one item) |
| 251 | Vault Archive (2026.9 clients): `PUT /ciphers/archive`, `/ciphers/unarchive` (bulk list) and `PUT /ciphers/:id/archive`, `/unarchive`; `archivedDate` in every cipher response and sync; per item for personal ciphers (`ciphers.archived_at`), per member for organisation items; archive on create and import; edits never change it | done | agent | `test/archive.test.ts`; browser check recorded in the evidence log |
| 252 | Email-protected Sends: `authType` 0 with a recipient list (`sends.emails`), `send_access` grant steps `email_required`, `email_and_otp_required` with `email` and `otp` form fields, mailed eight digit codes (hashed in `send_email_codes`, 10 minute life, 5 guesses, single use, 30 s resend window, per Send rate limit, no probing of the list), legacy `POST /sends/access/:id` takes `email` and `otp` in the body. Also fixes the `send_access` error body: `send_access_error_type` is now its own field as the SDK reads it | done | agent | `test/send-email.test.ts` (8 tests); browser check in the evidence log |
| 253 | Send field parity: no upper bound on `deletionDate` (clients offer a custom date), `authType` none, password, email with switching between them, `PUT /sends/:id/remove-auth`, expired codes purged by the cron | done | agent | `test/sends.test.ts`, `test/send-email.test.ts` |
| 254 | Missing cipher and folder endpoints found by diffing client calls against routes: `DELETE /folders` (bulk), `DELETE /folders/all`, attachments on organisation items (collection permissions, admin routes `GET` and `DELETE /ciphers/:id/attachment/:attachmentId/admin`), `POST /ciphers/:id/attachment/:attachmentId/share` | done | agent | `test/org-attachments.test.ts`, `test/archive.test.ts` |

## Phase 5: Live sync

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 100 | SignalR handshake (JSON and MessagePack) in `NotificationHub` with hibernation | done | agent | `GET /notifications/hub?access_token=` (same verification as `requireAuth`, incl. security stamp), `POST /notifications/hub/negotiate`, per-user Durable Object, 15s keep-alive pings via alarm. Real desktop client not yet exercised (tests drive both protocols) |
| 101 | Publish cipher, folder, send, logout events from write paths | done | agent | `src/notifications/publish.ts` (`pushUserUpdate`, `PushType`); LogOut wired to password, KDF, security stamp and key rotation. Cipher, folder, import, purge and domain settings routes publish through `src/notifications/vault-events.ts` (requesting device excluded). Send create, update and delete publish the same way |
| 102 | Anonymous hub for login-with-device requests | done | agent | `/notifications/anonymous-hub?Token=`, `/api/auth-requests` (create, pending, get, response poll, answer), password grant with `authRequest`. Admin approval (type 2) not supported |
| 103 | Mobile push via the Bitwarden push relay (optional, needs installation credentials) | done | agent | Implemented as #262; needs the owner to obtain installation credentials (`docs/push-notifications.md`). Live relay not exercised |

## Phase 6: Two-factor authentication

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 120 | TOTP | done | agent | RFC 6238 SHA-1, 6 digits, +-1 step, replay rejected via stored last step. Tests in `test/twofactor.test.ts`, `test/totp.test.ts` |
| 121 | Recovery code | done | agent | `get-recover`, anonymous `recover` (both paths) disables all providers and rotates the code |
| 122 | WebAuthn / passkeys as second factor | done | agent | ES256 and RS256, attestation not verified (none accepted), counter and one-shot challenge checks, own CBOR decoder |
| 123 | Email 2FA (needs task 141) | done | agent | 6 digit code, 10 minute expiry, 5 attempts, sent through `src/email`; setup refused without a transport |
| 124 | Duo (Universal Prompt, user and organisation) and YubiKey OTP (YubiCloud) | done | agent | `src/auth/duo.ts`, `src/auth/yubico.ts`, migration `0012`; fixed-vector and flow tests in `test/duo-yubikey.test.ts`. See `docs/two-factor.md` |
| 125 | Login with passkey (passwordless) | deferred | | Needs the `/api/webauthn` credential store with PRF key wrapping and `grant_type=webauthn`; not started. See `docs/two-factor.md` |

## Phase 7: Optional services

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 140 | Admin UI behind `ADMIN_ENABLED`: magic-link (`ADMIN_EMAILS`) and hashed `ADMIN_TOKEN_HASH` login; users, orgs, invites, diagnostics. See `docs/admin.md` | done | agent | Disabled returns 404; enabled requires login. Tests in `test/admin-ui.test.ts` |
| 141 | Email transport: Cloudflare Email Service `EMAIL` binding (legacy `EmailMessage` fallback), `MAIL_FROM`, no-op when unbound, templates in `src/email/` | done | agent | Fake-transport tests green; other HTTP providers not implemented |
| 142 | Icon proxy with SSRF protection and Cache API | done | agent | Private and link-local targets refused. `src/icons/`, `src/routes/icons.ts`, `ICONS_ENABLED`; tests in `test/icons.test.ts` |
| 143 | Serve the Bitwarden web vault via Workers static assets (build-time fetch, integrity check, licence notice); superseded by #210 | dropped | agent | `pnpm web-vault:fetch` pins and verifies the official image (docs/web-vault.md); worker-first routes keep the API unshadowed; browser login not yet exercised end to end |
| 144 | Admin UI: single per-request CSP nonce (the gate ran twice on `/admin`, so header and style tag nonces differed and CSS was blocked), sidebar restyle, per-user items count and 2FA providers, Remove 2FA action | done | agent | `test/admin-ui.test.ts` asserts header nonce equals style nonce on every page; Remove 2FA tested with confirm and CSRF |
| 145 | Admin JSON API under `/api/cloudwarden/admin/*` for native admin pages in the forked web vault: overview, users (list, disable, enable, deauthorize, remove 2FA, delete), invitations, organizations, diagnostics; `/api/cloudwarden/me` gains `email`. Shared logic moved to `src/admin/service.ts`; writes recorded as events (codes 9001 to 9008) | doing | agent | `test/admin-api.test.ts`; operations documented under the `x-cloudwarden` tag in `docs/api/openapi.yaml`; `docs/admin.md` |
| 210 | Fork the web client into this repository: curated GPL-3.0 import of bitwarden/clients `web-v2026.9.1` under `web/` (no `bitwarden_license/`), `web/NOTICE.md`, `pnpm web:build` into `web-vault/` under a memory-limited scope, deploy builds instead of fetching (supersedes #143), licence guard `pnpm check:web-licence`, tooling excludes. See `docs/web-client.md` | doing | agent | Build green locally and in deploy; served `/cloudwarden-build.json`; `pnpm check:web-licence` in CI |
| 211 | Rebrand and theme the web client as Cloudwarden: product name in titles and locale strings (product name only), own logo, favicons and manifest, footer credit, no premium upsell, Secrets Manager, Provider Portal or "More from" entries; colours, Montserrat and radii from the artifacts pages for light and dark | done | agent | Headless check shows Cloudwarden branding in both themes |
| 212 | Organisations on self-hosted: "New organization" shows a create form (name, billing email, Free plan) instead of the licence upload; no billing or payment steps | done | agent | Creating an organisation from the web client works against `pnpm dev` |
| 213 | Native Instance admin in the web client (overview, users with disable, enable, deauthorise, remove 2FA and delete, invitations, organisations, diagnostics) on the JSON admin API (#145), shown only when `/api/cloudwarden/me` says `isAdmin`; remove the injected `admin-link.js` and `/admin/session/exchange` (keep `/admin/recovery`) | done | agent | Admin user sees Instance admin and lists users in a headless check |

## Phase 8: Operations

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 160 | Deployment guide: create D1, R2, secrets, custom domain, using only placeholders | doing | | Fresh account deploy from docs alone. `docs/deploy.md`; config reads deploy values from env |
| 161 | CI deploy workflow (environment-protected, OIDC or scoped token in secrets) | doing | | `deploy.yml`: gate, `cf d1 migrations apply`, `cf deploy`, `/alive` smoke check. Worker secrets set once by hand |
| 162 | Scheduled D1 export to R2 for portable backups | done | agent | Daily cron, 14 day retention, `scripts/restore-backup.mjs`. `docs/backup.md`; tests in `test/backup.test.ts` and `scripts/restore-backup.test.mjs`. Restore tested at SQL generation level; live restore into a fresh D1 not yet run |
| 163 | Importer from other self-hosted Bitwarden-compatible servers (data only, no code reuse) | done | agent | `scripts/import-from-server.mjs` over the public API (prelogin, token, sync, register, ciphers/import), client side decryption, `--register` keeps the user key; `docs/data-import.md`; tests in `scripts/import-from-server.test.mjs` and a `pnpm e2e` step |
| 164 | Observability: structured logs without vault data, Workers Analytics | done | agent | `src/log.ts`, request middleware, Workers Logs enabled. `docs/observability.md`; `test/log.test.ts` asserts no body, query or email in logs. Manual log review on a deployed Worker still due |
| 165 | D1 Sessions API if read replication is enabled | done | agent | Replication stays off (documented); `D1_SESSIONS=true` opts in to a `withSession` wrapper (`src/db/sessions.ts`) with the `x-d1-bookmark` header, default off. Tests in `test/d1-sessions.test.ts`; see `docs/d1-sessions.md`. Not run against a replicated production database |

## Phase 9: Compatibility and quality

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 180 | API contract tests generated from the OpenAPI spec (#14) and checked against recorded client traffic (sanitised fixtures) | doing | | `test/contract.test.ts` validates 34 curated responses against the spec; 28 unimplemented operations are skipped and drift checked. Recorded client traffic fixtures still todo |
| 181 | End-to-end tests with the official Bitwarden CLI against `cf dev` | done | | `pnpm e2e` (`e2e/`): 20 steps pass, including login, sync, create, edit, delete, restore, Send, attachments and API key login. CI job `E2E (Bitwarden CLI)` |
| 182 | Client version support matrix and `/api/config` server version strategy | done | agent | `docs/compatibility.md`; `/api/config` reports `2026.9.0`; matrix rows stay "Target" until #181 verifies them |
| 183 | Threat model document | done | agent | `docs/threat-model.md` (STRIDE per area) |

## Phase 11: Secrets Manager

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 220 | Secrets Manager data model and API: migration `0009_secrets_manager` (projects, secrets, secret-project links, machine accounts, access tokens, access policies; event columns; `accessSecretsManager` per member; per-organisation secrets revision), projects and secrets CRUD, bulk delete, get-by-ids, sync, counts, events 2100 to 2305. Paths and shapes from the GPL-3.0 `bitwarden-api-api` crate only; see `docs/secrets-manager.md` | done | agent | `test/secrets-manager.test.ts`; contract cases; `pnpm db:generate` reports no drift |
| 221 | Machine login: `client_credentials` with `scope=api.secrets`, bare token id as `client_id`, `encrypted_payload` in the response, JWT `organization` claim; `requireSmAuth` accepts machine tokens only on Secrets Manager routes and re-reads the token row on every request (immediate revocation) | done | agent | Tests: login shape, bad and revoked credentials, machine token 401 on `/api/sync` and org routes, 404 on member-only SM routes |
| 222 | Access policies (security review: token minting bounded by the creator's reach, confirmed-only grantees, owner/admin control of `accessSecretsManager`, primary reads, revision bump on membership changes, confirmed-only backfill, dummy hash for unknown token ids): member, group and machine account policies on projects, secrets and machine accounts with read and write; potential grantees; `accessSecretsManager` toggle (invite, update, bulk `enable-secrets-manager`) | done | agent | Tests: no policy 404, read-only 403 on write, group write, creator grant, machine read and write grants |
| 223 | Spec and end-to-end: `secrets-manager` tag in `docs/api/openapi.yaml`; `pnpm e2e` drives a GPL-contract machine client (`e2e/sm-client.mjs`) through the TLS proxy | done | agent | `pnpm lint:api` clean; e2e steps 21 to 25 |
| 224 | Secret versions (`/secret-versions/*`, `/secrets/{id}/versions`) and Secrets Manager import and export (`/sm/{organizationId}/import`, `/export`) | done | agent | `test/sm-versions.test.ts`; OpenAPI paths and schemas; `docs/secrets-manager.md`; migration `0015_sm_secret_versions` |
| 225 | Run the official `bws` binary in `pnpm e2e` (owner decision 2026-10-02: official interoperable clients, including `bws`, are used against Cloudwarden) | done | claude | Pinned `bws` 2.1.0 in `e2e/bws.lock.json` with sha256 check; decision recorded in `docs/secrets-manager.md`; 6 `bws` commands pass in `pnpm e2e` (steps 26 to 31); no server changes were needed |
| 226 | Remove the server-rendered `/admin` entirely (owner decision, 2 October 2026): HTML app, magic-link and `ADMIN_TOKEN_HASH` sign-in, admin sessions and CSRF, `admin-link` remnants. Instance admin is only the native web client pages on `/api/cloudwarden/admin/*`. `/admin*` stays worker-first and returns the standard 404 JSON. Migration `0010_remove_html_admin` drops `admin_login_tokens` and `admin_sessions` (`admin_rate_limits` kept: the D1 rate limit fallback uses it). `docs/admin.md` rewritten with a Recovery section | done | agent | `test/admin.test.ts` asserts `/admin`, `/admin/users` and `/admin/recovery` are 404 JSON with `ADMIN_ENABLED` false and true; `test/admin-api.test.ts` still passes; lint, typecheck, test, test:scripts, check:identifiers, licence and e2e green; supersedes #140, #144, #205 and the HTML parts of #213 |
| 227 | Secrets Manager web UI: route `/sm/:organizationId` with guard, side navigation and product switcher entry for members with access; projects (list, create, rename, bulk delete, project view with secrets, people and machine accounts) and secrets (organisation and project lists, create, view with reveal and copy, edit, bulk delete), encrypted with the organisation key. Written from scratch, nothing from `bitwarden_license/` | done | agent | Jest component specs; headless browser run; `pnpm check:web-licence` |
| 228 | Secrets Manager web UI: machine accounts (list, create, rename, bulk delete, per-account project read or read-write access, people access) and access tokens (create with seed, key derivation and payload per `docs/secrets-manager.md`, shown once with copy and warning; list; revoke) | done | agent | Jest: SDK vector and `e2e/sm-client.mjs` parses and decrypts a UI-built token; headless: UI token reads the secret with `e2e/sm-client.mjs` |
| 229 | Secrets Manager web UI: project and machine account people and group access editor; Admin Console member "Secrets Manager" access toggle (existing dialog field). Fix: serve `GET /api/organizations/{id}/billing/vnext/self-host/metadata`, without which the member edit and invite dialogs never opened | done | agent | `test/orgs.test.ts` (metadata for managers, 403 for users); headless: member dialog shows the checkbox |
| 230 | Secrets Manager web UI follow-ups: direct secret access policies, machine account events view, secret versions and import or export once #224 lands | todo | | |
| 231 | Interoperability audit (workstream G): `docs/parity-matrix.md` generated by `scripts/parity-matrix.mjs` from call inventories of the web, browser, desktop, CLI, Android, iOS clients and the SDK API client (`docs/parity/*.tsv`); implement every remaining client-called endpoint not owned by workstreams A to F (accounts and devices misc, folders, attachments admin, organisation misc, notifications centre, tasks, Secrets Manager events and trash, self-host billing, plans, sponsorships and provider answers) | doing | agent | Matrix committed; tests per endpoint; e2e extended; invite links (status, validate, accept, confirm, invite), auto-confirm tied to policy 18, limit item deletion in cipher permissions |

## Phase 12: Bitwarden parity (push and account emails)

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 260 | New device login verification: `verifyDevices` account setting (`POST /api/accounts/verify-devices`, in the profile), emailed code, token endpoint answers "new device verification required" and accepts `newDeviceOtp`, new device notice. Migration `0011_parity_account_email` | done | agent | `test/account-email.test.ts` |
| 261 | Account emails: password hint, verify email and token, request and verify OTP, delete by email, two-step login changed and recovery used notices, email change notices to both addresses, welcome, emergency access accepted, confirmed, approved, rejected and elapsed-wait sweep, organisation accepted and confirmed. See `docs/account-email.md` | done | agent | `test/account-email.test.ts`; contract list shrunk by 8 operations |
| 262 | Push relay: installation credentials (`PUSH_INSTALLATION_ID`, `PUSH_INSTALLATION_KEY`, `PUSH_RELAY_URI`, `PUSH_IDENTITY_URI`), relay token, device register, update and delete, send for every hub event with user and organisation targeting and device exclusion, no-op when unconfigured, diagnostics `push` status. See `docs/push-notifications.md` | done | agent | `test/push-relay.test.ts` against a stand-in relay; not run against the live relay (needs credentials) |

## Phase 13: Organisation API, directory sync, SCIM and integrations

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 270 | Organisation API keys: `POST api-key`, `rotate-api-key`, `GET api-key-information[/{type}]` (Public API key owner only, SCIM key `manageScim`), sealed at rest under `DATA_ENCRYPTION_KEY` (fallback derived from `JWT_SECRET`); `client_credentials` grant for `organization.<id>` with `scope=api.organization`, tokens bound to the key revision; `useApi`, `useDirectory`, `useScim` on; events carry `systemUser`. Migration `0014_org_api_scim_integrations` | done | agent | `test/public-api.test.ts`: owner only, password check, stable key, sealed row, rotation revokes tokens, organisation tokens refused elsewhere |
| 271 | Bitwarden Public API at `/api/public/*` and `/public/*`: members (CRUD, group ids, reinvite, revoke, restore), groups (CRUD, member ids), collections (get, update, delete), policies, events (filters, continuation); Public API error envelope; `PublicApi` tag in `docs/api/openapi.yaml` | done | agent | Contract cases validate every response against the spec |
| 272 | Directory Connector: `POST /public/organization/import` (match by external id then email, invite, link, `deleted`, group upsert and membership, `overwriteExisting`, `inviteUsersAfterProvisioning`, owners kept); `pnpm e2e` runs the pinned official `bwdc` CLI (GPL-3.0) against an in-process LDAP server | done | agent | Import test; e2e `bwdc` login, test, sync, overwrite sync |
| 273 | SCIM 2.0 at `/scim/v2/{orgId}` and `/v2/{orgId}`: Users and Groups (list with RFC 7644 filters, pagination and attribute selection, create, get, replace, PATCH, delete), ServiceProviderConfig, Schemas, ResourceTypes; SCIM key auth when enabled; revoke and restore on `active`; Entra ID and Okta request forms; SCIM settings API and page | done | agent | `test/scim.test.ts` (filter and PATCH conformance, Entra and Okta sequences) |
| 274 | Event integrations: signed webhook (HMAC-SHA256 over timestamp and body), Splunk HEC, Datadog, Microsoft Sentinel (Logs Ingestion API); minute cron delivery in insertion order with lease, exponential back-off and status; test event; secrets sealed; integrations page | done | agent | `test/integrations.test.ts` |
| 275 | Web client: SCIM settings (`settings/scim`) and integrations (`integrations`) pages under `web/apps/web/src/app/cloudwarden/org-integrations/`; event log CSV export (upstream) works against the event API | done | agent | Jest specs; `pnpm web:build` |
| 276 | Docs: `docs/integrations.md` (setup for Entra ID, Okta, Directory Connector, webhook verification, `DATA_ENCRYPTION_KEY`) | done | agent | |
| 277 | Instance admin managed mobile push settings: `instance_settings` table (migration `0017_instance_settings`), installation key sealed at rest and never returned, region us, eu or custom with derived URIs, `GET`/`PUT`/`DELETE /api/cloudwarden/admin/push-settings` and rate-limited `POST .../test`, Worker secrets override the store, re-registration of mobile devices on change, admin audit events 9009 to 9011, Instance admin > Mobile push page. See `docs/push-notifications.md` | done | agent | `test/push-settings.test.ts` (403 for non-admin, key never returned, sealed row, env precedence, URI derivation, stand-in relay test, re-registration); Jest spec for the page |

## Phase 14: Single sign-on, trusted devices, Key Connector, claimed domains

See `docs/sso.md`. Bitwarden's SSO server and SSO settings screens are Bitwarden-licensed and were not read.

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 280 | SSO login flow: `/identity/sso/prevalidate`, `/identity/connect/authorize` (allow-listed redirect URIs, PKCE S256, browser-bound flow cookie), one-time codes, `authorization_code` grant with two-step login, organisation `identifier`, profile SSO fields, `/api/config` `sso` URL. Migration `0015_sso_tde_domains` | done | agent | `test/sso-oidc.test.ts` |
| 281 | OIDC relying party (`oauth4webapi`): discovery, code flow with state, nonce, PKCE, ID token claims and signature (JWKS or client secret), UserInfo, claim mappings, acr | done | agent | Mock provider in vitest (`test/oidc-idp.ts`); negative cases for aud, iss, nonce, expiry, key, `none` |
| 282 | SAML 2.0 service provider (`xmldsigjs`): metadata, signed AuthnRequest (redirect and POST), Response validation (signature, wrapping, issuer, destination, audience, times, InResponseTo, replay), encrypted assertions | done | agent | `test/sso-saml.test.ts` with generated certificates |
| 283 | JIT provisioning and linking rules, `set-password`, Require SSO policy (with single organisation dependency), account link and unlink | done | agent | `test/sso-oidc.test.ts` |
| 284 | Trusted device encryption: device key endpoints, `TrustedDeviceOption`, offboarding password, policies auto-enabled, key rotation re-wraps devices | done | agent | `test/sso-tde.test.ts` |
| 285 | Key Connector: organisation option, `set-key-connector-key`, `convert-to-key-connector`, confirmation details, `KeyConnectorOption`. Bitwarden's Key Connector is Bitwarden-licensed: not tested against; HS256 tokens without JWKS are a known gap | doing | agent | `test/sso-tde.test.ts`; interoperability with a third-party Key Connector open |
| 286 | Claimed domains: CRUD, DNS TXT verification over DoH, hourly cron, SSO discovery by email, claimed account rules and admin account deletion | done | agent | `test/sso-tde.test.ts` |
| 287 | Web UI: Settings, Single sign-on (OIDC, SAML, member decryption, test) and Settings, Claimed domains, written from scratch | done | agent | `pnpm web:build`; `pnpm check:web-licence` |
| 288 | E2E SSO with the official CLI and a mock OIDC provider | todo | | `pnpm e2e` step |

## Phase 10: Going public

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 200 | Full-history identifier and secret scan (`check-identifiers`, gitleaks) | todo | | Zero findings |
| 201 | Publish a private vulnerability reporting channel in SECURITY.md before going public | todo | owner | Channel documented, no personal contact details |
| 204 | Runners for public visibility: the Default runner group (holding `k3s-runners`) disallows public repositories. Give Cloudwarden a dedicated scale set or a group that allows public repos, hardened for untrusted fork PRs (ephemeral, no secrets, approval required for outside contributors) | todo | owner | CI runs after the visibility flip; fork PRs need approval |
| 205 | Unified admin: admin login is the vault login (`ADMIN_EMAILS` plus enabled account), reached from an Instance admin link injected into the web vault; token and magic link kept as break-glass recovery at `/admin/recovery`. See `docs/admin.md` | done | agent | `test/admin-exchange.test.ts` (exchange, cookie flags, non-admin 403, bad, expired and stamp-rotated 401, cross-origin 403, session ends on stamp rotation, `/api/cloudwarden/me`); `scripts/fetch-web-vault.test.mjs` (single tag with SRI, idempotent); `pnpm dev` serves the tag and script with a matching sha384. Vault logout ends the admin session (`/admin/session/end`); vault sessions 1 hour sliding. Nav item cloned from Reports and placed after Settings (`scripts/admin-link.test.mjs`, happy-dom); live browser test passed |
| 202 | Trademark review: name and wording do not imply affiliation with Bitwarden | todo | owner | |
| 203 | Flip visibility to public | todo | owner | Owner approval recorded |

---

## Evidence log

Newest first. One line per verified fact.

- 2026-10-02 · #103, #260 to #262 · Branch `feat/parity-push-emails`: `pnpm lint`, `pnpm typecheck`, `pnpm test` (43 files, 515 passed, 16 skipped; 17 new tests in `test/account-email.test.ts`, 8 in `test/push-relay.test.ts`), `pnpm test:scripts`, `pnpm lint:api`, `pnpm check:identifiers` green; migration `0011_parity_account_email` (`pnpm db:generate` reports no drift). The push relay request shapes come from public documentation and client behaviour and are tested against a stand-in relay only: no installation credentials were available, so the live relay has not been exercised.
- 2026-10-02 · #225 · Owner decision (Thomas, 2 October 2026): official interoperable clients, including `bws`, are used against Cloudwarden. `pnpm e2e` now downloads `bws` 2.1.0 (Linux x64, sha256 `ba8233c3a4aee5d43e3c73bbd04d99e9bc5aba13bbbfd06d89b073abe732b860`, verified before use, tampered hash refused) and, with a machine token, `--server-url` at the TLS proxy and `SSL_CERT_FILE` for its CA, runs `project list`, `secret list`, `secret get` (decrypted value and note asserted), `secret create`, `secret edit`, `secret delete`: 31 steps pass (6 new). No server incompatibility found. Only fix was in the e2e proxy: `bws` (rustls) rejects a self-signed certificate used as its own trust anchor, so the proxy now issues a leaf from a throwaway CA.
- 2026-10-02 · #227 to #229 · Branch `feat/sm-ui`: Jest `src/app/cloudwarden` 4 suites, 24 tests (SDK vector, `e2e/sm-client.mjs` parses and decrypts a UI-built token, list component specs); `pnpm web:build` 335 s, scope peak 8560 MiB; `pnpm check:web-licence`, `pnpm check:identifiers`, `pnpm lint`, `pnpm typecheck`, `pnpm lint:api`, Vitest `orgs` and `contract` green. Headless Chromium against `pnpm dev` behind the e2e TLS proxy: product switcher shows Secrets Manager; empty states; project, secret (reveal shows the plaintext), machine account, project grant and access token created in the UI; `e2e/sm-client.mjs list` with that token returns the decrypted secret; revoking it makes login fail with 400; bulk delete with confirmation; member dialog shows "This user can access Secrets Manager".
- 2026-10-02 · #220 to #223 · Branch `feat/secrets-manager`: `pnpm lint`, `pnpm typecheck`, `pnpm test` (42 files, 506 passed, 24 skipped; 31 in `test/secrets-manager.test.ts`, 32 new contract cases), `pnpm test:scripts`, `pnpm lint:api`, `pnpm check:identifiers`, `pnpm check:web-licence` green; `pnpm e2e` 25 steps (5 Secrets Manager steps). Sources: GPL-3.0 crates of github.com/bitwarden/sdk-internal at `9acb7241` with `bitwarden_license/` removed before reading; sdk-sm (Bitwarden SDK License) not used beyond its LICENSE file. Access token key derivation matches the `bitwarden-core` vector. `bws` itself not run (#225).
- 2026-10-02 · #210 to #213 · Security review fixes: deploy sets Cloudflare credentials only on migrate, `cf build` and `cf deploy` and migrates after the web build; licence guard flags any `@bitwarden/bit-*` or `bitwarden_license/` reference (5 tests) and commercial targets are gone from the configs; identifier check scans every changed `web/` file by upstream blob id (`web/UPSTREAM-BLOBS.txt`); gitleaks allowlists named fixture files only; CSP without bare `wss:` (4 tests, no inline scripts in built HTML); organisation delete needs the typed name (Jest spec, new CI job; headless: button disabled until the exact name). Rebuild: 442 s, peak 8611 MiB.
- 2026-10-02 · #210 · `pnpm web:build` (webpack 5, `ENV=selfhosted`, production, no source maps) inside `systemd-run --user --scope -p MemoryHigh=8G -p MemoryMax=12G -p MemorySwapMax=512M`: 308 s and 372 s wall time, scope peak 8460 MiB and 8580 MiB, `web-vault/` 83 MB. A first attempt with upstream source maps and an 8 GiB heap sat at MemoryHigh (about 15% memory pressure stall) and was stopped after more than 40 minutes, so source maps are now opt-in. `pnpm check:web-licence` passes over 6090 files; gitleaks over the tree clean with the `web/` fixture allowlist; `pnpm lint`, `pnpm typecheck`, `pnpm test` (41 files, 443 passed), `pnpm test:scripts` (57) and `pnpm check:identifiers` green.
- 2026-10-02 · #211 to #213 · Headless Chromium (puppeteer-core) against `pnpm dev` behind the e2e TLS proxy: login page titled Cloudwarden with the new mark in light and dark, footer "Cloudwarden, based on Bitwarden clients (GPL-3.0)"; registration through the emailed finish-signup link logs in; no premium upsell, Secrets Manager, Provider Portal or "More from" entries; `/#/create-organization` shows name, billing email and the Free plan and creating "Example Org" lands on its vault; a normal user has no Instance admin item; an `ADMIN_EMAILS` user sees Instance admin and the users page lists both accounts, plus overview, invitations, organisations and diagnostics render. `pnpm e2e` 20 steps pass.

- 2026-10-01 · #12 · `docker build` of the repo `Dockerfile` succeeded; the container applied the local D1 migrations, started Vite on `0.0.0.0:8080` and served `/alive`, `/api/config` and prelogin under arbitrary Host headers. `pnpm e2e` still 20 steps after moving the migrate helper to `scripts/local-migrate.mjs`.
- 2026-10-01 · #165 · `pnpm lint`, `pnpm typecheck`, `pnpm test` green; 7 tests in `test/d1-sessions.test.ts` (inert when off, `first-primary` without a bookmark, chained bookmarks keep `revisionDate` strictly increasing across three edits, stale updates still 400). Local miniflare D1 only; real replica lag was not exercised.
- 2026-10-01 · #125 · Wire shapes read from github.com/bitwarden/clients tag `web-v2026.9.1` (`webauthn-login-admin-api.service.ts`, the save, enable-encryption and assertion request models, `WebAuthnPrfDecryptionOptionResponse`, key rotation `passkeyUnlockData`). `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm lint:api`, `pnpm check:identifiers` and `pnpm e2e` (20 steps) green; 34 tests in `test/passkey.test.ts`; migration `0006_passkeys` (`pnpm db:generate` reports no changes). No real authenticator or PRF client run yet.
- 2026-10-01 · #181 · `pnpm e2e` with `@bitwarden/cli` 2026.9.0 pinned: 20 steps (including registration through the nested `register/finish` body) pass against the Vite dev server (local D1 migrated with `cf d1 migrations apply --local`). The CLI hard-refuses non-HTTPS server URLs in its production build, so the runner fronts the dev server with a throwaway self-signed TLS proxy (`NODE_EXTRA_CA_CERTS`). Account registration is done over HTTP with WebCrypto key derivation (`e2e/crypto.mjs`) because `bw` cannot register. First real client run found and fixed: missing `POST /identity/accounts/prelogin/password`, `JWT_SECRET` not delivered to local dev (undeclared secret; now declared only when `LOCAL_DEV_SECRETS=true`, so deploys never touch the production secret), missing `MasterPasswordUnlock` and `AccountKeys` in the token response, cipher `data` returned as an object instead of a string, no `POST /api/accounts/key-management/user-key-id`, and the v2 attachment slot response omitting the reserved attachment.
- 2026-10-01 · #180 · `test/contract.test.ts` (vitest in workerd, `@cfworker/json-schema` because Ajv needs `eval`, which workerd forbids): 34 responses checked against `docs/api/openapi.yaml`. Found the spec too strict for `fields`, `attachments`, `passwordHistory` (null when empty) and `server` in `/api/config` (null); the spec now allows null there. Unimplemented operations (28, listed in the test) include `rotate-user-account-keys`, device trust, password hint, verify-email and SSO endpoints.

- 2026-10-01 · #8 · Owner decision: no Dependabot branches or PRs. Dependabot security updates disabled via API, `dependabot.yml` removed, its open PR closed. Alerts remain on.
- 2026-10-01 · #60 to #67 · Branch `feat/orgs` on `main`: `pnpm lint`, `pnpm typecheck`, `pnpm test` (240 tests, 32 files), `pnpm check:identifiers` green; migration `0005_organizations` (`pnpm db:generate` reports no changes). Collections now belong to organisation members (`users_collections` is keyed by organisation user, so invitees can be pre-assigned). `hidePasswords` is a display restriction: a writable grant that hides passwords still has `edit: true` (use `readOnly` to forbid changes). Custom members cannot edit themselves or grant access they lack. Live sync pushes cipher events to members who can see the item, SyncVault for structural changes and SyncOrgKeys on confirm. Known gaps: favourites on organisation items are shared, not per member; organisation SSO, key connector, reset password, API keys and billing endpoints are not implemented; emergency access notifications are limited to the invite and the initiate notice; `GET /api/ciphers` lists personal items only (sync carries organisation items).
- 2026-10-01 · #142, #162, #164, #182, #183 · `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm test:scripts`, `pnpm check:identifiers` and `cf build` green on branch `feat/ops`.
- 2026-10-02 · #226 · Removed the HTML admin (about 1,000 lines of app, views and helpers plus `test/admin-ui.test.ts`); `/admin*` kept worker-first and covered by `test/admin.test.ts`. `admin_rate_limits` is kept because `src/ratelimit.ts` uses it as the D1 fallback. Deploy smoke check now asserts `/admin` is 404 JSON. lint, typecheck, test (487 passed), test:scripts, check:identifiers, check:web-licence and e2e (31 steps) green locally.
- 2026-10-01 · #140, #141 · `pnpm lint`, `pnpm typecheck`, `pnpm test` (32 tests, 6 files), `pnpm check:identifiers` green on branch `feat/admin`; migration `0002_admin`.

- 2026-10-01 · #20 to #29 · Branch `feat/identity` rebased on #6: `pnpm lint`, `pnpm typecheck`, `pnpm test` (88 tests), `cf build` (no global-scope randomness) and invitation gating plus emailed verification and email-change codes and `pnpm check:identifiers` green. Covers register, prelogin, password, refresh and API-key grants, devices, profile, password, KDF, email, key rotation (all-or-nothing) and deletion, stamp invalidation of access and refresh tokens, and 429 limiting.
- 2026-10-01 · #20 · PBKDF2-SHA256 at 100000 iterations measured at about 15 ms median (Node 22); see ADR 0002. Production timing to be re-measured after deploy.
- 2026-10-01 · #29 · `LOGIN_LIMITER` declared through `bindings.rateLimit` in `cloudflare.config.ts` (20 requests per 60 s per client address); the limiter is skipped when the binding is absent and tested with a stub binding.
- 2026-10-01 · #28 · Account deletion is implemented; the delete-by-recovery flow is not (the 2FA recovery code in #121 is separate). Attachment and Send blob cleanup is deferred to #80.
- 2026-10-01 · #120 to #125 · Branch `feat/2fa`: `pnpm lint`, `pnpm typecheck`, `pnpm test` (159 tests, 19 files), `pnpm check:identifiers` green; no migration needed (`twofactor` and `devices.twofactor_remember` already exist, `pnpm db:generate` reports no changes). #124 and #125 deferred, see `docs/two-factor.md`.
- 2026-10-01 · #28 · Recovery-code flows depend on two-factor (Phase 6) and are not implemented; account deletion is. Attachment and Send blob cleanup landed with #80 and #82.

- 2026-10-01 · #14 · `docs/api/openapi.yaml` (OpenAPI 3.1, 193 operations over 157 paths, 217 schemas) read from github.com/bitwarden/clients tag `web-v2026.9.1` (older tags `web-v2025.8.0` and `web-v2025.1.0` for prelogin, register and KDF change that moved into the SDK); each operation carries `x-source-version` and `x-source-file`. `pnpm lint:api` (Redocly) reports zero errors and zero warnings; `pnpm api:build` renders `docs/api/build/index.html` (gitignored). Not yet verified against recorded client traffic (#180); SDK-only shapes (send_access grant, policy and URI match enum values) are flagged in the spec.
- 2026-10-01 · #13 · PR #2: all 9 jobs on `k3s-runners` green (Lint, Typecheck, Test, Identifier Check, Commit Lint, CI Status, Gitleaks full history, Lint Actions, Zizmor) plus Dependabot config validation. `pnpm/action-setup` held at v4 because v5+ needs libatomic, absent from the runner image.
- 2026-10-01 · #13 · GitHub secret scanning and push protection disabled via API (owner decision: no GitHub Advanced Security features).
- 2026-10-01 · #8 · Ruleset active on the default branch: no deletion, no force push, linear history, signed commits, PR required (squash only, threads resolved), `CI Status` required and up to date. Admin bypass only through a PR. Main commits show as verified on GitHub.
- 2026-10-01 · #7 · First push to `main`: CI succeeded (Lint, Typecheck, Test, Identifier Check, CI Status), Secret Scanning succeeded; CodeQL and Scorecard skipped by design while private. actionlint 1.7.12 and zizmor 1.30.1 (medium and above) clean locally.
- 2026-10-01 · #2 to #6 · Local: `pnpm lint`, `pnpm typecheck` and `pnpm test` (7 tests) green; `pnpm test:scripts` (48 tests) green; identifier scan and gitleaks history scan found nothing. Every commit passed the pre-commit hooks.
- 2026-10-01 · #8 · Enabled via API: secret scanning, push protection, Dependabot alerts, Dependabot security updates, squash-only merges, delete branch on merge. Private vulnerability reporting returned 404 (public repos only).
- 2026-10-01 · #1 · Repo created private; local commit email set to the GitHub noreply form.
- 2026-10-01 · #40-#45 · `pnpm lint`, `pnpm typecheck`, `pnpm test` (114 tests, 15 files), `pnpm check:identifiers` green on `feat/vault`; existing tables sufficed, so no migration 0003.
- 2026-10-01 · #80-#84 · `pnpm lint`, `pnpm typecheck`, `pnpm test` (176 tests, 21 files), `pnpm check:identifiers` green on `feat/sends`; migration `0003_sends` adds `uploaded_at` to attachments and sends so unfinished uploads can be told apart and swept.
- 2026-10-01 · #80 · Upload limit is 100 MB, the lowest Workers request body cap (Free and Pro). The v2 upload streams the multipart file part into R2 through a fixed length stream sized from the declared `fileSize`; the legacy single step upload buffers in memory. Signed download links are HMAC tokens (5 minutes) bound to one blob.
- 2026-10-01 · #83 · Both the `send_access` grant plus `POST /api/sends/access` (current clients) and the access id in the path flow (legacy) are served. Email-protected Sends are served since #252. File Sends count an access when the download URL is issued; text Sends when read. Live push on Send changes is pending the notifications module.
- 2026-10-01 · #84 · `purgeExpired(env)` runs from the `scheduled` handler (hourly cron in `cloudflare.config.ts`): Sends past deletion date, abandoned uploads older than 24 hours, and one page of orphaned R2 objects per run with a cursor kept in the bucket.
- 2026-10-01 · #100 to #103 · Local: 207 tests; lint, typecheck, identifier check and tests green (hub JSON and MessagePack handshakes, push delivery, device exclusion, user isolation, invalid token, stamp rotation with socket close, login-with-device flow, decoy requests, parser hardening). Wire contract checked against the bitwarden/clients notification types and auth request models.
- 2026-10-02 · #250-#254 · Branch `feat/parity-sends-archive`: `pnpm lint`, `pnpm typecheck`, `pnpm test`, `pnpm check:identifiers`, `pnpm lint:api` green; migration `0013_sends_archive_favorites` adds `ciphers.archived_at`, `sends.emails`, `cipher_user_state` and `send_email_codes`. The route diff of `docs/api/openapi.yaml` against the Hono routes leaves no unserved operation in the ciphers, folders, sends, sync and attachments areas.
