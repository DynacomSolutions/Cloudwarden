# Importing data from another server

TASKS #163 asked for an optional script that reads the exported SQLite database of another
self-hosted Bitwarden-compatible server and loads users and vaults into Cloudwarden. It is
**not built as a database reader**, for the reasons below. The importer that was built instead
talks to both servers over their public APIs; it is described last.

## Why a database importer is deferred

1. **The source schema is not part of the contract.** Cloudwarden is built from the Bitwarden
   client API (`docs/api/openapi.yaml`), the only thing both servers must share. Another server's
   table and column names, how it splits ciphers, attachments, organisation membership and
   two-factor state across tables, and how it stores timestamps are internal choices. They can
   only be learned from that server's source or migrations, and the project rule is to never port
   code or logic from other implementations (AGENTS.md rule 6). Guessing a schema from client
   visible shapes would mean an importer that silently drops or corrupts data.
2. **Password hashes are server specific.** Logging in without re-registering (the acceptance
   criterion) needs the source server's stored password hash and its derivation parameters, which
   again are internal. Verifying them means re-implementing that server's hashing scheme and
   keeping its iteration counts, which ADR 0002 and the 100000 iteration WebCrypto cap make costly.
3. **Everything else is encrypted client side anyway.** Cipher bodies, folder names and the account
   key are opaque to every server, so no server specific database read adds anything the client
   export does not already carry, apart from the password hash and server only metadata (events,
   device lists, Send access counts).

Because of 1 and 2 a database importer cannot be written without porting, so it is not built.

## What works today

- **Per account, with the official clients.** Export the vault from the old server (the encrypted
  JSON export keeps item data protected), register on Cloudwarden, and import the file in the web
  vault or CLI. The import endpoint `POST /api/ciphers/import` (TASKS #45) round-trips the
  Bitwarden JSON export. Master passwords, 2FA, devices and Sends are not carried over; set them up
  again on the new server.
- **Organisations.** Recreate the organisation and use the organisation import
  (`/api/ciphers/import-organization`) with an organisation export.

## Server to server importer (TASKS #163)

`scripts/import-from-server.mjs` (`pnpm import:server`) is the follow-up described above, built
only from the public client API: `prelogin`, the password grant at `/identity/connect/token`,
`/api/sync` on the source, `/identity/accounts/register` and `/api/ciphers/import` on Cloudwarden.
It reads no database and uses no code or schema of the other server, so it works with any server
that speaks the Bitwarden client API.

```sh
SOURCE_PASSWORD=... pnpm import:server \
  --source https://old.example.com --source-email me@example.com \
  --target https://vault.example.com --register
```

- The source vault is decrypted on your machine with the master password (PBKDF2 or Argon2id from
  the account's own KDF settings, type 2 EncStrings). Nothing is decrypted server side; each
  server only ever receives the usual master password hash.
- `--register` creates the target account (default: same email; `--target-email` to change it)
  with the source account's user key and key pair, wrapped under a new master key derived from
  `TARGET_PASSWORD` (default: the source password). Items are then carried over as they are,
  with no re-encryption. Without `--register` the script logs in to an existing target account
  (it needs `TARGET_PASSWORD`), and re-encrypts: per item keys are re-wrapped, items without a
  key have every encrypted field re-encrypted under the target user key.
- Two-factor on either side: codes are read from `SOURCE_2FA_TOKEN` or `TARGET_2FA_TOKEN`, or
  prompted for on a terminal, never taken from arguments (which show in process lists);
  `--source-2fa-provider` and `--target-2fa-provider` pick a provider type (default: the first one
  offered). Email codes can be requested from the source's own client first. `--dry-run` decrypts
  and counts without touching the target; `--skip-errors` skips an item that cannot be converted.
- Both server URLs must be https; plain http is accepted for localhost only, because the master
  password hash and tokens are sent. Redirects are refused.
- Copied: logins (including passkeys and URIs), cards, identities, secure notes, SSH keys, custom
  fields, password history, favourites, folders. Not copied: organisations and their items,
  Sends, attachments, trash, devices, two-factor setup and events. Accounts using the newer
  key hierarchy (COSE keys) are refused with a clear error.
- Imports over 6000 items are split into several requests; a folder used by items in more than one
  request is created once per request.
- `pnpm e2e` copies the vault it just built into a second account and compares the decrypted
  item names. `scripts/import-from-server.test.mjs` covers key derivation, re-encryption, item
  keys, chunking, registration and a dry run against a stand-in server.

The KDF code uses `@noble/hashes` (MIT) for Argon2id.
