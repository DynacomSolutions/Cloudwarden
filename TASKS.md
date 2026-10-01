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
| 12 | Local dev on the cluster (`devdeploy`) without committing local hostnames | todo | | Dev server reachable locally; no host-specific files committed |

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
| 60 | Organisations: create, settings, delete | todo | | |
| 61 | Members: invite, accept, confirm, roles, revoke, remove | todo | | |
| 62 | Collections and access (users and groups) | todo | | |
| 63 | Share cipher to organisation (atomic) | todo | | |
| 64 | Policies (master password, 2FA required, personal ownership, send options) | todo | | |
| 65 | Groups | todo | | |
| 66 | Emergency access | todo | | |
| 67 | Event logs | todo | | |

## Phase 4: Sends and attachments

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 80 | R2 attachment upload, download (signed short-lived URLs), delete | done | | Large file works within Worker body limit; limit documented |
| 81 | Text Sends | done | | |
| 82 | File Sends via R2 | done | | |
| 83 | Send access endpoints (password, max access count, expiry, deletion date) | done | | |
| 84 | Scheduled purge of expired Sends and orphaned blobs (Cron Trigger) | done | | |

## Phase 5: Live sync

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 100 | SignalR handshake (JSON and MessagePack) in `NotificationHub` with hibernation | done | agent | `GET /notifications/hub?access_token=` (same verification as `requireAuth`, incl. security stamp), `POST /notifications/hub/negotiate`, per-user Durable Object, 15s keep-alive pings via alarm. Real desktop client not yet exercised (tests drive both protocols) |
| 101 | Publish cipher, folder, send, logout events from write paths | done | agent | `src/notifications/publish.ts` (`pushUserUpdate`, `PushType`); LogOut wired to password, KDF, security stamp and key rotation. Cipher, folder, import, purge and domain settings routes publish through `src/notifications/vault-events.ts` (requesting device excluded). Send create, update and delete publish the same way |
| 102 | Anonymous hub for login-with-device requests | done | agent | `/notifications/anonymous-hub?Token=`, `/api/auth-requests` (create, pending, get, response poll, answer), password grant with `authRequest`. Admin approval (type 2) not supported |
| 103 | Mobile push via the Bitwarden push relay (optional, needs installation credentials) | deferred | agent | Not configured: needs Bitwarden installation credentials. Mobile clients still sync live over the WebSocket hub while the app is open; the device `pushToken` is stored (`PUT /api/devices/identifier/:id/token`) for a future relay |

## Phase 6: Two-factor authentication

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 120 | TOTP | done | agent | RFC 6238 SHA-1, 6 digits, +-1 step, replay rejected via stored last step. Tests in `test/twofactor.test.ts`, `test/totp.test.ts` |
| 121 | Recovery code | done | agent | `get-recover`, anonymous `recover` (both paths) disables all providers and rotates the code |
| 122 | WebAuthn / passkeys as second factor | done | agent | ES256 and RS256, attestation not verified (none accepted), counter and one-shot challenge checks, own CBOR decoder |
| 123 | Email 2FA (needs task 141) | done | agent | 6 digit code, 10 minute expiry, 5 attempts, sent through `src/email`; setup refused without a transport |
| 124 | Duo and YubiKey OTP (optional) | deferred | | Endpoints answer 400 "not supported". See `docs/two-factor.md` |
| 125 | Login with passkey (passwordless) | deferred | | Needs the `/api/webauthn` credential store with PRF key wrapping and `grant_type=webauthn`; not started. See `docs/two-factor.md` |

## Phase 7: Optional services

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 140 | Admin UI behind `ADMIN_ENABLED`: magic-link (`ADMIN_EMAILS`) and hashed `ADMIN_TOKEN_HASH` login; users, orgs, invites, diagnostics. See `docs/admin.md` | done | agent | Disabled returns 404; enabled requires login. Tests in `test/admin-ui.test.ts` |
| 141 | Email transport: Cloudflare Email Service `EMAIL` binding (legacy `EmailMessage` fallback), `MAIL_FROM`, no-op when unbound, templates in `src/email/` | done | agent | Fake-transport tests green; other HTTP providers not implemented |
| 142 | Icon proxy with SSRF protection and Cache API | todo | | Private and link-local targets refused |
| 143 | Serve the Bitwarden web vault via Workers static assets (build-time fetch, integrity check, licence notice) | done | agent | `pnpm web-vault:fetch` pins and verifies the official image (docs/web-vault.md); worker-first routes keep the API unshadowed; browser login not yet exercised end to end |

## Phase 8: Operations

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 160 | Deployment guide: create D1, R2, secrets, custom domain, using only placeholders | doing | | Fresh account deploy from docs alone. `docs/deploy.md`; config reads deploy values from env |
| 161 | CI deploy workflow (environment-protected, OIDC or scoped token in secrets) | doing | | `deploy.yml`: gate, `cf d1 migrations apply`, `cf deploy`, `/alive` smoke check. Worker secrets set once by hand |
| 162 | Scheduled D1 export to R2 for portable backups | todo | | Restore tested |
| 163 | Optional data importer from other self-hosted Bitwarden-compatible servers (data only, no code reuse) | todo | | Imported users log in without re-registering (depends on 20) |
| 164 | Observability: structured logs without vault data, Workers Analytics | todo | | Log review confirms no secrets or ciphertext logged |
| 165 | D1 Sessions API if read replication is enabled | todo | | No revision-date regressions under test |

## Phase 9: Compatibility and quality

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 180 | API contract tests generated from the OpenAPI spec (#14) and checked against recorded client traffic (sanitised fixtures) | todo | | |
| 181 | End-to-end tests with the official Bitwarden CLI against `cf dev` | todo | | Login, sync, create, edit, delete pass |
| 182 | Client version support matrix and `/api/config` server version strategy | todo | | |
| 183 | Threat model document | todo | | |

## Phase 10: Going public

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 200 | Full-history identifier and secret scan (`check-identifiers`, gitleaks) | todo | | Zero findings |
| 201 | Publish a private vulnerability reporting channel in SECURITY.md before going public | todo | owner | Channel documented, no personal contact details |
| 204 | Runners for public visibility: the Default runner group (holding `k3s-runners`) disallows public repositories. Give Cloudwarden a dedicated scale set or a group that allows public repos, hardened for untrusted fork PRs (ephemeral, no secrets, approval required for outside contributors) | todo | owner | CI runs after the visibility flip; fork PRs need approval |
| 202 | Trademark review: name and wording do not imply affiliation with Bitwarden | todo | owner | |
| 203 | Flip visibility to public | todo | owner | Owner approval recorded |

---

## Evidence log

Newest first. One line per verified fact.

- 2026-10-01 · #8 · Owner decision: no Dependabot branches or PRs. Dependabot security updates disabled via API, `dependabot.yml` removed, its open PR closed. Alerts remain on.
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
- 2026-10-01 · #83 · Both the `send_access` grant plus `POST /api/sends/access` (current clients) and the access id in the path flow (legacy) are served. Email-protected Sends (authType 0) are rejected. File Sends count an access when the download URL is issued; text Sends when read. Live push on Send changes is pending the notifications module.
- 2026-10-01 · #84 · `purgeExpired(env)` runs from the `scheduled` handler (hourly cron in `cloudflare.config.ts`): Sends past deletion date, abandoned uploads older than 24 hours, and one page of orphaned R2 objects per run with a cursor kept in the bucket.
- 2026-10-01 · #100 to #103 · Local: 207 tests; lint, typecheck, identifier check and tests green (hub JSON and MessagePack handshakes, push delivery, device exclusion, user isolation, invalid token, stamp rotation with socket close, login-with-device flow, decoy requests, parser hardening). Wire contract checked against the bitwarden/clients notification types and auth request models.
