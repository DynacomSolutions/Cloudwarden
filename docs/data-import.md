# Importing data from another server

TASKS #163 asked for an optional script that reads the exported SQLite database of another
self-hosted Bitwarden-compatible server and loads users and vaults into Cloudwarden. It is
**deferred**, for the reasons below. What works today is listed after them.

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

Because of 1 and 2 an importer cannot be written without porting, so it is not built.

## What works today

- **Per account, with the official clients.** Export the vault from the old server (the encrypted
  JSON export keeps item data protected), register on Cloudwarden, and import the file in the web
  vault or CLI. The import endpoint `POST /api/ciphers/import` (TASKS #45) round-trips the
  Bitwarden JSON export. Master passwords, 2FA, devices and Sends are not carried over; set them up
  again on the new server.
- **Organisations.** Recreate the organisation and use the organisation import
  (`/api/ciphers/import-organization`) with an organisation export.

## Possible follow-up that stays inside the contract

A migration script that talks to both servers over their public APIs, using the account owner's
master password: log in to the source (`/identity/connect/token`), read `/api/sync`, create the
account on Cloudwarden with the same KDF settings, wrapped user key and key pair (the register
endpoint takes exactly these), then post the encrypted ciphers and folders to
`/api/ciphers/import`. It uses only documented request and response shapes, needs no database
access and no knowledge of the source implementation, and keeps the user key so items stay
decryptable with the unchanged master password. It does not move attachments, Sends or
organisations. Not started; open a task before building it.
