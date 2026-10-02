# Client compatibility

Cloudwarden implements the Bitwarden server API as observed from the official open-source clients
(`bitwarden/clients`). The wire contract is the source of truth (TASKS #14); no other server's code is used.

## Version matrix

Bitwarden clients use calendar versions (`YYYY.M.patch`) and ship roughly monthly. Support is stated per
client family and per release line.

| Client | Release line | Status | Notes |
|---|---|---|---|
| Web vault | 2026.9.x | Target | Served by Cloudwarden once TASKS #143 lands |
| Browser extension (Chrome, Firefox, Edge, Safari) | 2026.9.x | Target | Needs login, sync, ciphers, folders |
| Desktop | 2026.9.x | Target | Same API surface as the extension |
| CLI | 2026.9.x | Target | Used for end-to-end tests (TASKS #181) |
| Mobile (iOS, Android) | 2026.9.x | Target | Push is not provided; sync happens on open and by polling |
| Any client | 2026.1.x to 2026.8.x | Best effort | Expected to work; not tested |
| Any client | before 2026.1 | Unsupported | Older auth and sync shapes are not targeted |

"Target" means the release line the implementation is built against. Nothing is listed as "Verified" until the
end-to-end suite (TASKS #181) has run it; update this table with the date and the exact client version at that point.

Secrets Manager is served as an API (machine accounts and the SDK wire contract, see
[secrets-manager.md](secrets-manager.md)); the official `bws` CLI has not been run against it (TASKS #225).

Not supported by design: SSO, SCIM, directory connectors, key connector, and Bitwarden-hosted
push relay. Clients treat the corresponding config fields as absent.

## `/api/config` and the server version

`GET /api/config` is unauthenticated and is the first call a client makes. Clients use it to:

- pick API, identity, vault and notifications URLs (`environment`);
- gate features by server version (`version`) and flags (`featureStates`);
- decide whether to show registration (`settings.disableUserRegistration`);
- choose a push mechanism (`push.pushTechnology`, `0` means none).

Cloudwarden returns:

| Field | Value |
|---|---|
| `object` | `config` |
| `version` | `SERVER_VERSION` in `src/routes/config.ts` (currently `2026.9.0`) |
| `gitHash` | `GIT_HASH` var when set, otherwise `unknown` |
| `server` | `{ name: "Cloudwarden", url: <DOMAIN> }` |
| `environment` | `cloudRegion: null`; `vault`, `api`, `identity`, `notifications` derived from `DOMAIN`; `sso: ""` |
| `featureStates` | `{}` |
| `push` | `{ pushTechnology: 0 }` |
| `settings` | `{ disableUserRegistration: <SIGNUPS_ALLOWED is not "true"> }` |

## Version strategy

The `version` string is not Cloudwarden's release number. Clients compare it with minimum-server-version
gates that ship with each feature, so it must express "the newest client API shape this server implements".

1. `SERVER_VERSION` is the newest client release line whose API behaviour the server implements and tests cover.
2. Bump it only when a new client line is verified (all matrix rows for that line pass TASKS #181), in the same
   commit that updates the matrix above.
3. Never advertise a version ahead of what is implemented: a client would enable features the server cannot
   serve. Lagging is safe; clients simply hide newer features.
4. Keep `featureStates` empty unless a flag is needed to keep a client working. Do not mirror upstream flags.
5. Cloudwarden's own release number lives in `package.json` and is unrelated.

## Upgrade checklist for a new client line

1. Read the client release notes and diff the API layer in `bitwarden/clients` for the models Cloudwarden serves.
2. Update `docs/api/openapi.yaml` (TASKS #14) first, then the code.
3. Run the end-to-end suite against the new CLI and record the client versions here.
4. Bump `SERVER_VERSION`.
