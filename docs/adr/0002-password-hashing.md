# ADR 0002: Server-side password hashing

Status: accepted (TASKS #20)

## Context

Bitwarden clients never send the master password. They derive a master key with the account KDF (PBKDF2-SHA256 or Argon2id, chosen per account) and send a `masterPasswordHash` derived from it with one more PBKDF2 round. That value is the effective password as far as the server is concerned. A stolen database must not hand out values that log in directly, so the server stores a further hash of it.

Workers expose PBKDF2 through WebCrypto with a hard cap of 100000 iterations. Argon2id would need a WASM build, with extra CPU and bundle size, and buys little here because the input is already a high-entropy KDF output rather than a human password.

## Decision

- Store `PBKDF2-SHA256(masterPasswordHash, random 16 byte salt, 100000 iterations)` as base64url, with the salt and iteration count in the row (`password_hash`, `salt`, `password_iterations`).
- Compare in constant time. Unknown accounts run the same derivation against a random dummy so response time does not reveal whether an account exists.
- The per-account client KDF (`kdf`, `kdf_iterations`, `kdf_memory`, `kdf_parallelism`) is independent and returned by prelogin.
- The stored iteration count lets a later change raise the cost (for example a WASM hasher) and re-hash on next login without a flag day. Imported accounts (TASKS #163) can keep their own parameters the same way.

## Measurement

WebCrypto PBKDF2-SHA256, 32 byte output, median of 15 runs on a development machine (Node 22, OpenSSL backend):

| Iterations | Median |
|---|---|
| 100000 | 14.7 ms |
| 600000 | 80.3 ms |

100000 iterations costs roughly 15 ms of CPU per login or password check on that hardware, and the derivation runs in native code rather than in the Worker's JavaScript. Production figures depend on Cloudflare hardware and should be re-measured after deploy. The Workers Free plan CPU limit (10 ms per request) is below this cost, so running Cloudwarden needs the Paid plan.

## Consequences

- Each password check, login, password change and account deletion costs one PBKDF2 derivation.
- Rate limiting (TASKS #29) bounds guessing against the stored hash.
