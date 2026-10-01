# ADR 0001: Cloudflare D1 as the primary store

- Status: accepted
- Date: 2026-10-01

## Context

Cloudwarden must store everything a Bitwarden-compatible server stores: users, devices, folders, ciphers, organisations, collections and their many-to-many memberships, Sends, two-factor settings, events, and binary attachments.

Vault contents are end-to-end encrypted by the clients. The server stores opaque ciphertext plus relational metadata (ownership, sharing, revision dates). The access pattern is relational: `/api/sync` joins a user's ciphers, folders, collections and organisation memberships in one response.

The Bitwarden API contract (TASKS #14) defines the resources and relationships the schema must support.

## Options considered

| Option | Fit | Problems |
|---|---|---|
| **D1 (SQLite)** | Relational, managed migrations, Time Travel point-in-time restore, read replication | 10 GB per database, single write primary, no interactive transactions |
| Durable Objects with SQLite storage (one per user) | Strongly consistent, colocated compute and storage | Organisation sharing spans users, so sync needs cross-object fan-out; backups and admin queries are harder |
| Workers KV | Simple | Eventually consistent; unsafe for revision dates, security stamps and refresh tokens |
| Hyperdrive + external PostgreSQL | Full SQL, no size ceiling | Extra infrastructure to run and secure; defeats a Cloudflare-only deploy |

## Decision

1. **D1** is the system of record for all relational data.
2. **R2** stores attachment and file-Send blobs. D1 holds only their metadata.
3. A **Durable Object** (`NotificationHub`, WebSocket hibernation API) fans out live sync notifications. It holds no durable vault data.
4. Schema and migrations are managed with Drizzle (`src/db/schema.ts`, `migrations/`).

## Consequences

- **No interactive transactions.** D1 does not support `BEGIN ... COMMIT` across awaits. Multi-statement writes that must be atomic (key rotation, organisation sharing, account deletion) use `db.batch([...])`, which runs as one implicit transaction. Code review must reject read-modify-write sequences that rely on isolation.
- **Size ceiling.** 10 GB is far above any personal or small-team vault (ciphers are typically a few KB). Large multi-tenant hosting would need sharding or a move to per-tenant Durable Objects; that is out of scope until there is demand.
- **Read replicas.** If read replication is enabled, every request must use the D1 Sessions API with a bookmark so a client never reads older data than it just wrote (revision-date regressions break client sync).
- **Backups.** Time Travel gives 30 days of point-in-time restore. A scheduled export to R2 is still planned for portability (see TASKS.md).

## Related constraint: server-side password hashing

The Workers Web Crypto implementation caps PBKDF2 at 100,000 iterations, below the 600,000 iterations commonly used for server-side hashing. This does not weaken the client KDF (clients still run PBKDF2 at 600,000+ or Argon2id before sending a hash), but it affects defence in depth and data imports from other servers. The choice between capped PBKDF2, a WASM Argon2id, or a pure-JS PBKDF2 for imported hashes is tracked in TASKS.md and needs measurement against the Workers CPU limit.
