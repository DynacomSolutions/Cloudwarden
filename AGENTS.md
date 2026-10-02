# Agent instructions

Instructions for AI coding agents working in this repository. Human contributors should read `CONTRIBUTING.md`.

## Before you start

1. Read `TASKS.md`. Add your task there (new stable number) before starting work, and keep its status and evidence current.
2. Read `docs/architecture.md` and the ADRs in `docs/adr/`.

## Non-negotiable rules

1. **No identifying information.** This repository will be public. Never write real hostnames, domains, IP addresses, account, zone or database IDs, email addresses, usernames or absolute local paths into any file or commit message. Use `example.com`, `user@example.com`, `127.0.0.1` and all-zero UUIDs. `pnpm check:identifiers` and the pre-commit hook enforce this.
2. **Never log or persist plaintext secrets or vault contents.** Request bodies contain encrypted vault data and password hashes.
3. **Atomic writes use `db.batch()`.** D1 has no interactive transactions.
4. **Conventional Commits**, one logical change per commit.
5. **No em dashes** in code, comments, docs or commit messages.
6. **Build from the API contract.** `docs/api/openapi.yaml` (TASKS #14) is the source of truth. Never port code or logic from other server implementations.
7. **Use the `cf` CLI**, not Wrangler, for Cloudflare operations.

## Commands

| Command | Purpose |
|---|---|
| `pnpm install` | Install dependencies and git hooks |
| `pnpm dev` | Local Worker with D1, R2 and Durable Objects simulated |
| `pnpm lint` / `pnpm format` | Biome check / fix |
| `pnpm typecheck` | TypeScript |
| `pnpm test` | Vitest inside workerd |
| `pnpm e2e` | End-to-end run of the official Bitwarden CLI and the pinned `bws` Secrets Manager CLI (downloaded, needs network) against a local dev server (`e2e/`, about 2 minutes, needs `openssl`) |
| `pnpm check:identifiers` | Identifier guard over tracked files |
| `pnpm db:generate` | Generate a migration from `src/db/schema.ts` |

All of `lint`, `typecheck`, `test` and `check:identifiers` must pass before pushing.
