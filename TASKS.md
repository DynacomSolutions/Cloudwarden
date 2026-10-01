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
| 8 | Repo settings: Dependabot alerts and updates, `main` ruleset (PR required, `CI Status` required, no force push, linear history) | done | coordinator | Settings visible via API; see evidence log |
| 9 | Architecture doc and storage ADR | done | coordinator | `docs/architecture.md`, `docs/adr/0001-storage-d1.md` |
| 10 | Choose licence. AGPL-3.0 is a placeholder; with no ported code the choice is open (AGPL-3.0 forces hosted forks to publish changes; MIT or Apache-2.0 maximise adoption) | todo | owner | Owner decision recorded; LICENSE updated |
| 11 | ~~Create `maintainers` team for CODEOWNERS~~ (never requested; CODEOWNERS removed under #13) | dropped | | |
| 14 | Bitwarden API contract as OpenAPI 3.1 (Swagger): `docs/api/openapi.yaml` covering every endpoint the official clients call (Identity, API, Notifications, Icons, Events), with exact paths, methods, headers, auth, request and response schemas, status codes and error shapes; source version recorded per endpoint; rendered Swagger UI. This is the build contract for every later phase | todo | | Spec lints clean; every client-called endpoint present; Swagger UI renders; contract tests (#180) generated from it |
| 12 | Local dev on the cluster (`devdeploy`) without committing local hostnames | todo | | Dev server reachable locally; no host-specific files committed |

## Phase 1: Identity and accounts

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 20 | Decide server-side password hashing (Workers PBKDF2 caps at 100k iterations; options: capped PBKDF2, WASM Argon2id, pure-JS PBKDF2 for imports). Measure CPU time | todo | | ADR written with benchmark numbers |
| 21 | `POST /identity/accounts/prelogin` and `/api/accounts/prelogin` backed by D1 | todo | | Returns stored KDF settings; unknown users get defaults (no enumeration) |
| 22 | Registration (`/identity/accounts/register`, `register/finish`) gated by `SIGNUPS_ALLOWED` and invites | todo | | Official client can create an account |
| 23 | Token endpoint: `password` grant, `refresh_token` grant, `client_credentials` (API key) | todo | | Browser extension, desktop and CLI can log in and refresh |
| 24 | JWT signing and key management (algorithm choice, rotation, `JWT_SECRET` handling) | todo | | Tokens validate; rotation documented |
| 25 | Devices: register, list, known-device check, trust, deactivate | todo | | Device list matches clients |
| 26 | Account: profile, change password, change email, KDF change, key rotation (atomic via `db.batch`) | todo | | Key rotation is all-or-nothing under test |
| 27 | Security stamp and session invalidation on credential change | todo | | Old tokens rejected after password change |
| 28 | Account deletion and recovery-code flows | todo | | |
| 29 | Rate limiting on login, prelogin and 2FA (Workers Rate Limiting binding) | todo | | Exceeding limit returns 429 |

## Phase 2: Vault data

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 40 | `GET /api/sync` (profile, folders, ciphers, collections, policies, sends, domains) | todo | | Fresh client sync matches stored data |
| 41 | Ciphers CRUD, soft delete, restore, purge, bulk move and delete | todo | | |
| 42 | Folders CRUD | todo | | |
| 43 | Revision dates and conflict handling (`lastKnownRevisionDate`) | todo | | Stale update rejected like upstream |
| 44 | Equivalent domains settings | todo | | |
| 45 | Import endpoint (`/api/ciphers/import`) | todo | | Bitwarden JSON export round-trips |

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
| 80 | R2 attachment upload, download (signed short-lived URLs), delete | todo | | Large file works within Worker body limit; limit documented |
| 81 | Text Sends | todo | | |
| 82 | File Sends via R2 | todo | | |
| 83 | Send access endpoints (password, max access count, expiry, deletion date) | todo | | |
| 84 | Scheduled purge of expired Sends and orphaned blobs (Cron Trigger) | todo | | |

## Phase 5: Live sync

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 100 | SignalR handshake (JSON and MessagePack) in `NotificationHub` with hibernation | todo | | Desktop client receives sync push |
| 101 | Publish cipher, folder, send, logout events from write paths | todo | | |
| 102 | Anonymous hub for login-with-device requests | todo | | |
| 103 | Mobile push via the Bitwarden push relay (optional, needs installation credentials) | todo | | Documented as optional |

## Phase 6: Two-factor authentication

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 120 | TOTP | todo | | |
| 121 | Recovery code | todo | | |
| 122 | WebAuthn / passkeys as second factor | todo | | |
| 123 | Email 2FA (needs task 141) | todo | | |
| 124 | Duo and YubiKey OTP (optional) | todo | | |
| 125 | Login with passkey (passwordless) | todo | | |

## Phase 7: Optional services

| # | Task | Status | Owner | Acceptance |
|---|---|---|---|---|
| 140 | Admin UI behind `ADMIN_ENABLED`: magic-link (`ADMIN_EMAILS`) and hashed `ADMIN_TOKEN_HASH` login; users, orgs, invites, diagnostics. See `docs/admin.md` | done | agent | Disabled returns 404; enabled requires login. Tests in `test/admin-ui.test.ts` |
| 141 | Email transport: Cloudflare Email Service `EMAIL` binding (legacy `EmailMessage` fallback), `MAIL_FROM`, no-op when unbound, templates in `src/email/` | done | agent | Fake-transport tests green; other HTTP providers not implemented |
| 142 | Icon proxy with SSRF protection and Cache API | todo | | Private and link-local targets refused |
| 143 | Serve the Bitwarden web vault via Workers static assets (build-time fetch, integrity check, licence notice) | todo | | Web vault loads and logs in |

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

- 2026-10-01 · #140, #141 · `pnpm lint`, `pnpm typecheck`, `pnpm test` (32 tests, 6 files), `pnpm check:identifiers` green on branch `feat/admin`; migration `0002_admin`.
- 2026-10-01 · #13 · PR #2: all 9 jobs on `k3s-runners` green (Lint, Typecheck, Test, Identifier Check, Commit Lint, CI Status, Gitleaks full history, Lint Actions, Zizmor) plus Dependabot config validation. `pnpm/action-setup` held at v4 because v5+ needs libatomic, absent from the runner image.
- 2026-10-01 · #13 · GitHub secret scanning and push protection disabled via API (owner decision: no GitHub Advanced Security features).
- 2026-10-01 · #8 · Ruleset active on the default branch: no deletion, no force push, linear history, signed commits, PR required (squash only, threads resolved), `CI Status` required and up to date. Admin bypass only through a PR. Main commits show as verified on GitHub.
- 2026-10-01 · #7 · First push to `main`: CI succeeded (Lint, Typecheck, Test, Identifier Check, CI Status), Secret Scanning succeeded; CodeQL and Scorecard skipped by design while private. actionlint 1.7.12 and zizmor 1.30.1 (medium and above) clean locally.
- 2026-10-01 · #2 to #6 · Local: `pnpm lint`, `pnpm typecheck` and `pnpm test` (7 tests) green; `pnpm test:scripts` (48 tests) green; identifier scan and gitleaks history scan found nothing. Every commit passed the pre-commit hooks.
- 2026-10-01 · #8 · Enabled via API: secret scanning, push protection, Dependabot alerts, Dependabot security updates, squash-only merges, delete branch on merge. Private vulnerability reporting returned 404 (public repos only).
- 2026-10-01 · #1 · Repo created private; local commit email set to the GitHub noreply form.
