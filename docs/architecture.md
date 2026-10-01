# Architecture

Cloudwarden is a single Cloudflare Worker that implements the Bitwarden server API, so official Bitwarden clients (browser extensions, desktop, mobile, CLI, web vault) can use it as a self-hosted server.

```
 Bitwarden clients
        |
        v
+-------------------- Cloudflare Worker (Hono) --------------------+
|  /identity/*        login, token refresh, prelogin, register     |
|  /api/*             sync, ciphers, folders, sends, orgs, account |
|  /notifications/*   WebSocket upgrade -> NotificationHub DO      |
|  /icons/*           optional favicon proxy                       |
|  /admin/*           optional admin UI (ADMIN_ENABLED)            |
|  /                  optional web vault static assets             |
+-------+------------------+-------------------+-------------------+
        |                  |                   |
        v                  v                   v
   D1 (SQLite)        R2 bucket          Durable Object
   relational data    attachments,       NotificationHub
                      file Sends         (live sync fan-out)
```

## Components

| Path | Purpose |
|---|---|
| `src/index.ts` | Worker entry, Hono app, Durable Object export |
| `src/routes/` | One module per API area |
| `src/db/schema.ts` | Drizzle schema (source of truth for migrations) |
| `migrations/` | Generated SQL migrations applied to D1 |
| `src/do/notification-hub.ts` | WebSocket hub (SignalR protocol) |
| `test/` | Vitest suites running inside workerd |

## Principles

1. **The server never sees plaintext.** Vault data is encrypted client-side. The server stores and returns opaque strings. Never log request bodies.
2. **Behavioural compatibility over reinvention.** The Bitwarden clients define the contract. Vaultwarden's observable behaviour is the reference when Bitwarden's own server and Vaultwarden differ.
3. **Everything optional is off by default.** Signups, admin UI, icon proxy, web vault, email and push are opt-in via configuration.
4. **No identifying data in the repository.** Real hosts, IDs and secrets live only in deploy-time configuration and secrets. See `CONTRIBUTING.md`.

## Decisions

- [ADR 0001: D1 as the primary store](adr/0001-storage-d1.md)
