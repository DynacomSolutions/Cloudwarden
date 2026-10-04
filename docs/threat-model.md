# Threat model

Scope: the Cloudwarden Worker, its D1 database, R2 bucket and Durable Object, as deployed on Cloudflare, serving
official Bitwarden clients. Method: STRIDE per area. Status reflects the code at the time of writing; areas whose
implementation is still in `TASKS.md` are modelled against the intended design and marked as such.

## Assets

| Asset | Why it matters |
|---|---|
| Vault ciphertext (ciphers, folders, sends, attachments) | The user's secrets; encrypted client-side, server never holds keys |
| Account key material (`akey`, private key, KDF parameters) | Wrapped by the master key; theft enables offline guessing |
| Master password hash (server-side hash of the client hash) | Authenticates login; offline guessing target |
| Tokens (access, refresh, device) | Bearer credentials |
| `JWT_SECRET` | Forging tokens, admin access |
| Metadata (emails, org membership, event log, timestamps) | Privacy, social graph |
| Backups in R2 | Full copy of the database |
| Availability of the vault | Users lock themselves out of their credentials |

## Actors

Anonymous internet client; authenticated user; malicious org member; malicious or compromised admin; person with a
stolen device or backup; compromised dependency or CI; Cloudflare account takeover; curious server operator
(an honest-but-curious operator is in scope because the design must hold against it).

## Trust boundaries

1. Internet to Worker (TLS terminated by Cloudflare; all input untrusted).
2. Worker to D1 and R2 (platform-internal, trusted for integrity, protected by account access).
3. Worker to the public internet via `fetch` (icon proxy; destination untrusted, response untrusted).
4. Worker to Cloudflare Email Service (outbound only).
5. Client to Durable Object (WebSocket after authentication).
6. Operator tooling to Cloudflare account (API tokens, `cf` CLI, CI).
7. Browser to the Instance admin pages in the web client (same origin as the vault; they call the Bearer-authenticated JSON admin API).

## STRIDE by area

### Identity (login, tokens, 2FA; TASKS #1, #120 to #125)

| | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Credential stuffing, token forgery | Server hashes the client-supplied master hash again; JWTs signed with `JWT_SECRET`; per-account and per-IP rate limits planned (#1) | No CAPTCHA; 2FA strongly advised |
| T | Tampered refresh token | Refresh tokens stored server-side, rotated, bound to a device | |
| R | User denies action | Event log (#7) records auth events without secrets | Events are not tamper-evident |
| I | User enumeration through prelogin or login errors | Prelogin returns deterministic fake KDF params for unknown accounts; uniform error text | Timing differences are not eliminated |
| D | Login flood | Cloudflare WAF and rate limiting rules at the edge | Needs operator configuration |
| E | Stolen access token reused after password change | `security_stamp` rotation invalidates tokens | Window equals token lifetime |

### Vault (ciphers, folders, sends, attachments, orgs; TASKS #2 to #6)

| | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Acting as another user | Every query scoped by authenticated user uuid; org access checked through membership rows | Logic bugs are the main risk; negative tests per route required |
| T | Overwriting newer data with stale clients | Revision dates compared on write; atomic changes through `db.batch()` | Last-writer-wins within a revision |
| R | Disputed deletion | Soft delete and trash, event log | |
| I | Server operator reads secrets | Only ciphertext stored; plaintext never sent to the server. Logs carry no bodies (see `docs/observability.md`) | Metadata (titles are encrypted, but item counts, sizes and timestamps are visible) |
| I | Attachment or Send file access by guessing | Random ids, authorisation on download, short-lived signed URLs | Public Send links are bearer by design |
| D | Oversized payloads, storage exhaustion | Size limits per request and per attachment; D1 and R2 quotas | Quota exhaustion by an authenticated user until per-user limits land |
| E | Org member gains admin rights | Role checks on every org route; invite flow requires acceptance and confirmation | |

### Admin (`ADMIN_ENABLED`; `docs/admin.md`)

The server-rendered `/admin` (magic link, admin token, cookie sessions) was removed. Instance admin is only the native web client pages on the JSON admin API, authenticated with the vault's own access token.

| | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Impersonating an admin | Admin is a normal vault login (master password, second factor) for an enabled account whose verified address is in `ADMIN_EMAILS`; admin addresses cannot be claimed by registering them (verification token required); disabled by default (API 403, `/admin` is 404) | A compromised admin vault account is a compromised admin |
| T | CSRF against admin actions | Bearer token only, no cookie authentication, so a cross-site request carries no credential | |
| R | Unattributed admin changes | Every write inserts an `events` row (types 9001 to 9011) with the acting admin | No per-field audit trail |
| I | Admin sees vault contents | Admin can view accounts and metadata, not decrypt vaults | Admin can still delete or disable accounts |
| D | Admin lockout | No recovery web surface to attack; the operator restores access with documented D1 statements (`docs/admin.md`, Recovery) | Needs Cloudflare account access |
| E | Email access becomes admin access | There is no email sign-in any more; a mailbox alone grants nothing. Admin addresses must be verified | Account recovery by email (if enabled elsewhere) is out of scope |
| E | Stale `/admin` links or probes | `/admin` and `/admin/*` return the standard 404 JSON and are served by the Worker first, never by the vault's SPA fallback | |

### Email (Cloudflare Email Service; TASKS #141)

| | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Spoofed sender | Sending domain onboarded with SPF, DKIM and DMARC through Cloudflare | Depends on operator DNS |
| T | Link tampering in mail | Links carry opaque single-use tokens; origin comes from `DOMAIN`, not the request | Mail is not end-to-end encrypted |
| I | Tokens in logs or mail provider | Tokens never logged; short expiry | Mail providers can read messages |
| D | Mail bombing through invite or verify endpoints | Per-address and per-IP limits (planned with #1) | |
| E | Header injection through names or addresses | Addresses validated; templates escape user text | |

### Email-less installations (TASKS #350 to #354; `docs/emailless.md`)

With no mail transport nobody can prove control of a mailbox, so every flow that used a mailbox as proof or channel changed. The rule is that missing mail may remove a feature or substitute a stronger proof, never weaken the proof an attacker must give.

| | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Registering an `ADMIN_EMAILS` address first to become admin | Without mail, such an address registers only with `ADMIN_SETUP_TOKEN` (32+ characters, constant-time compare after hashing), through a registration token carrying a `setup` claim that `register` re-checks; the secret is spent in the same D1 batch as the account (`admin_setup_uses`, keyed by its hash), refused when any `ADMIN_EMAILS` account exists, and never accepted again until the secret is rotated; ignored when mail works | Whoever holds the secret before the operator can create the admin: set it, register at once, then remove it |
| S | Guessing the setup or an invite code | Counted per address (5 per 10 minutes in D1) and per client; every refusal reads the same; codes are 192 bits (invites, stored as a hash, 7 days, reissue retires the old one) or 32+ characters | An attacker can exhaust the per-address allowance and delay the operator by 10 minutes |
| S | Taking an invited or whitelisted address without owning it | An invited address cannot get a registration token without its invite code when mail is off. The domain whitelist cannot prove the address and keeps working as before | Whitelisting a domain on a mail-off server lets anyone register any address of that domain: prefer invite links |
| E | Becoming admin by changing an account email to an admin address | Without mail an email change to an `ADMIN_EMAILS` address is refused (the new address cannot be verified); `isAdminUser` still needs `verifiedAt`, which is never inferred from "mail is off" | |
| E | Weaker email change | The master password is required to ask for and again to confirm the change; with mail the emailed code is required as before | The code proved the new mailbox; without mail the new address is unverified, as for any registration |
| S | Account takeover through recovery mail | Delete by email, password hint, verification codes and org deletion by email answer 400 without mail; deleting needs the master password | A user who forgot the password cannot recover by mail: only a recovery code or an admin helps |
| E | Skipped second factor | New device codes are skipped without mail (nothing can deliver them); accounts with two-step login are unchanged. Email two-step is refused and not offered next to other providers; an account whose only provider is email must use its recovery code | New device verification adds nothing on a mail-off server, so a stolen master password logs in from a new device unless another second factor is on: advise two-step login |
| R | Missing notices | New device, emergency access and organisation notices are skipped; events and push still record them | A grantor is not told by mail of an emergency access request |

### Icons (`GET /icons/:domain/icon.png`; TASKS #142)

The proxy makes server-side requests to attacker-chosen hosts, so SSRF is the main threat.

| | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Request appears to come from Cloudflare infrastructure | Fixed `User-Agent`; no credentials or cookies forwarded | |
| T | Malicious image or markup returned as an icon | Magic-number check, allow-list of raster types, SVG rejected, 512 KB cap, served with `nosniff` and a locked-down CSP | Decoder bugs in the client image stack |
| I | SSRF to internal or metadata addresses | Strict hostname validation (ASCII DNS names with an alphabetic TLD, at least two labels); every IP literal form refused (decimal, hex, octal, short, v6, v4-mapped); reserved suffixes refused; only ports 80 and 443; no credentials in URLs; https only on every hop; manual redirects, at most 3, each hop revalidated; icon URLs from HTML validated too | DNS rebinding: a public hostname whose record resolves to a private or internal address. The Worker cannot validate the resolved IP, so it relies on Cloudflare's platform refusing to route `fetch` to private ranges and to the Worker's own zone. If that guarantee changes, the proxy must be disabled |
| I | Probing which hosts are refused | Refusals return the same fallback image as any miss | |
| D | Amplification, slow servers | 5 s per request and 15 s overall, byte caps, per-client rate limit on cache misses (shared `LOGIN_LIMITER` binding), Cache API with 7 day positive TTL, 1 day for definitive misses and 1 hour for transient failures | Distributed callers can still trigger many distinct fetches; limits are per client address |
| E | None expected: the endpoint is unauthenticated and has no privileges | Disable with `ICONS_ENABLED=false` | Domains requested by users are visible to the operator and the target site |

### Notifications (`NotificationHub` Durable Object; TASKS #9)

| | Threat | Mitigation | Residual |
|---|---|---|---|
| S | Connecting as another user | WebSocket upgrade requires a valid access token; hub keyed by user id | Token in query string is a client protocol requirement, so it must be excluded from logs (query strings are not logged) |
| T | Forged sync messages | Messages are produced only by server code, never relayed from clients | |
| I | Cross-user delivery | One hub per user, messages carry ids not content | Presence of activity is visible to the user's own devices only |
| D | Connection flood | Per-user connection cap, idle timeout | DO costs scale with connections |
| E | Client sends privileged frames | Server ignores client frames other than protocol pings | |

### Secrets Manager (TASKS #220 to #225, `docs/secrets-manager.md`)

- **Spoofing:** machine logins check a SHA-256 of a 30 character random client secret in constant time, against a fixed dummy hash for unknown token ids; the token endpoint is rate limited. Machine JWTs are accepted only by `requireSmAuth`; every other route requires scope `api`.
- **Tampering and information disclosure:** values are client-encrypted EncStrings; the server cannot read the organisation key inside `encrypted_payload` (the seed never leaves the client). Access is decided per request from policies; no read is 404, so ids of other projects and secrets are not confirmed.
- **Elevation of privilege (token minting):** an access token carries everything its machine account can reach, so a non-admin may create one only when they can already read every project and secret granted to that account (403 otherwise). Owners and admins with Secrets Manager access may always.
- **Elevation of privilege (access flag):** only owners, admins, or custom members who already have Secrets Manager access may change `accessSecretsManager`, never their own. Only confirmed members can be grantees.
- **Elevation of privilege:** machine accounts are confined to their organisation and granted projects and secrets, and cannot manage machine accounts, tokens or policies. Members need `accessSecretsManager`; non-admins only grant access to machine accounts they can see.
- **Repudiation:** creates, edits, deletes and machine reads are events (2100 to 2305) with the acting member or machine account.
- **Residual:** revocation is immediate (token row read per request), but a copied access token string stays valid until revoked or expired; tokens without `expireAt` never expire.

### Federated organisations (TASKS #300 to #309, `docs/federation.md`)

- **Spoofing:** peer requests carry an RFC 9421 Ed25519 signature checked against a key pinned at pairing, after both admins compared fingerprints out of band; pairing binds the key to the domain through the https descriptor. Unknown, unapproved and suspended peers get 403.
- **Tampering and replay:** the signature covers method, full URL, Content-Digest and the user and device headers; 300 second window; per-peer nonce store.
- **Information disclosure:** a peer sees only the EncStrings its user may see; organisation keys are wrapped in the browser for the member's public key. Outbound calls are https only to public addresses (DoH checks, no redirects).
- **Elevation of privilege:** forwarded requests run as the peer user's stand-in account through the normal authorisation, restricted to cipher, organisation and attachment download paths; the stand-in account has no usable password and cannot be registered over. Events are accepted only for local users who hold something from the calling peer.
- **Denial of service:** per-peer rate limit, request size caps, timeouts; admins suspend a peer instantly.
- **Residual:** a compromised serving instance can act as its users within their organisation permissions until the hosting admin suspends it; server-side policy checks on the serving side do not see federated organisations.

### Operations and supply chain

| Threat | Mitigation | Residual |
|---|---|---|
| Backup theft (R2) | Private bucket, token scoping, 14 day retention, device refresh and push tokens redacted, `backups/` prefix never served (`src/blob-keys.ts`), `docs/backup.md` | Backups are as sensitive as the database |
| Inconsistent backup | Exports are paged, not a snapshot; documented, with D1 Time Travel as the consistent option | Related rows may be out of step after a restore |
| Platform invocation logs leak URLs | Invocation logs disabled; only allow-listed app logs kept | |
| Secret or identifier leaks in the repository | `check-identifiers`, gitleaks, signed commits, PR-only main | |
| Malicious dependency | Lockfile, Dependabot, small dependency set, CI with minimal permissions | Transitive compromise |
| Cloudflare account takeover | Hardware-key 2FA on the account, scoped API tokens, protected deploy environment | Full compromise yields ciphertext and hashes, not plaintext vaults |
| Log leakage | Allow-list logging, tests, review checklist | New call sites must follow the rule |

## Cross-cutting residual risks

- Offline guessing of master passwords from a stolen database or backup is bounded only by KDF cost and
  password strength. Argon2id parameters and minimum iteration counts are enforced at registration (#1).
- Metadata (who, when, how much) is visible to the operator and to Cloudflare.
- A malicious Worker deployment can capture credentials at login; protect the deploy pipeline and account.
- Availability depends on Cloudflare; clients keep an offline vault copy, and backups cover data loss.

## Review cadence

Revisit this document when adding an externally reachable route, a new outbound integration, or a new stored
secret, and before the visibility flip (TASKS #203).
