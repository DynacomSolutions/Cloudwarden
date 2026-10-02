# Cloudwarden

A Bitwarden-compatible password manager server for Cloudflare Workers, written in TypeScript.

Cloudwarden implements the Bitwarden server API, built from an explicit API contract (OpenAPI), so the official Bitwarden clients can use a self-hosted server. It runs serverless on Cloudflare:

- **Workers** for the API (Hono)
- **D1** (SQLite) for relational data
- **R2** for attachments and file Sends
- **Durable Objects** for live sync notifications
- An **optional instance admin** (native pages in the web client), off by default

> **Status: early scaffold.** Nothing works yet beyond health and config endpoints. Do not store real passwords in it. See [TASKS.md](TASKS.md) for the roadmap.

## Why D1

The Bitwarden data model is relational (users, organisations, collections, many-to-many sharing) and fits SQLite well. D1 gives managed SQLite with migrations and point-in-time restore. The trade-offs (no interactive transactions, 10 GB per database, PBKDF2 iteration cap in Workers) are recorded in [ADR 0001](docs/adr/0001-storage-d1.md).

## Quick start

Requirements: Node 22, pnpm 9, and the Cloudflare `cf` CLI.

```sh
pnpm install
pnpm dev
```

`JWT_SECRET` is a Worker secret; to supply it locally run `LOCAL_DEV_SECRETS=true JWT_SECRET=<32+ characters> pnpm dev`.

Then point a Bitwarden client's self-hosted server URL at the local address `pnpm dev` prints.

## Configuration

| Name | Kind | Default | Purpose |
|---|---|---|---|
| `DOMAIN` | var | `https://vault.example.com` | Public base URL |
| `SIGNUPS_ALLOWED` | var | `false` | Allow open registration |
| `ADMIN_ENABLED` | var | `false` | Enable the admin API behind the web client's Instance admin |
| `JWT_SECRET` | secret | none | Token signing key |
| `ADMIN_EMAILS` | secret | none | Comma-separated instance admin addresses |

## Documentation

- [Architecture](docs/architecture.md)
- [Local development and the dev container](docs/local-dev.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Disclaimer

Cloudwarden is not affiliated with, endorsed by, or associated with Bitwarden, Inc. or the Vaultwarden project. Bitwarden is a trademark of Bitwarden, Inc.

## Licence

[GNU AGPL-3.0](LICENSE).
