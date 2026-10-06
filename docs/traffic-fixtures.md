# Recorded client traffic fixtures

TASKS #367 and #387. `test/fixtures/traffic/*.json` hold sanitised request and response pairs
recorded from the official Bitwarden CLI (`cli-*`) and the official web vault (`web-*`) while they
drove a local Cloudwarden dev server. `test/traffic-replay.test.ts`
replays them against the Worker inside Vitest. They complement the curated responses in
`test/contract.test.ts` with what a real client actually sends: header sets, request ordering,
token refreshes, form bodies and the exact JSON the CLI builds.

## What a replay checks

For every fixture, starting from a freshly registered account:

1. The recording contains nothing identifying (`findIdentifying` in `scripts/traffic-sanitise.mjs`).
2. Recorded requests and responses conform to `docs/api/openapi.yaml`.
3. Each request is sent to the Worker with tokens and ids rebound from the live responses.
4. The live status equals the recorded status, the live body conforms to the spec, and it has the
   same JSON shape (keys and value types, nulls and array lengths ignored) as the recording.

The recordings come from Cloudwarden itself, because no official server is available here. The
OpenAPI check is the independent one; the shape check guards against regressions.

## Coverage

| Client | Status | Flows |
|---|---|---|
| Official CLI (`bw`, the version pinned in `package.json`) | recorded | login (prelogin, password grant, token refresh), sync, folder and cipher create, edit, delete, restore, permanent delete, Send create, edit, list, get, anonymous access, password protected access (wrong and right password) and delete |
| Official web vault (the vendored client, built unmodified into `web-vault/`, driven by headless Chromium) | recorded | `web-register`: account creation (`send-verification-email`, `register/finish`) followed by the automatic login and first sync. `web-login-sync`: prelogin, `knowndevice`, password grant, config, sync, revision-date polling, token refresh, reload. `web-cipher-write`: folder create, rename and delete; login item create, edit, send to bin, restore, bin again, permanent delete. `web-send`: text Send create, edit, anonymous recipient access (`POST /api/sends/access`) and delete |
| Official mobile apps | gap | They cannot run on the capture host, and fabricated traffic would not be a recording (TASKS #388) |

Not recorded: multipart uploads (attachments, file Sends), API key login, two-step login, SSO and
organisation flows, and the web vault's other pages (organisations, settings, reports, import).
Only `/api` and `/identity` calls are kept; static assets, icons and the notifications hub are not.

## Re-capturing

```sh
pnpm install
pnpm capture:traffic
pnpm test -- traffic-replay
pnpm check:identifiers
```

`scripts/capture-traffic.mjs` starts `vite dev` with a throwaway TLS proxy and a recording proxy in
front of it, registers a fresh account per scenario over HTTP (the CLI cannot register), then drives
`bw`. Bodies are sanitised in memory before anything is written, and the written files are checked
again. Review the diff of a re-capture before committing it.

### Web vault

```sh
pnpm web:build                       # once; publishes web-vault/ (see docs/web-client.md)
CHROMIUM_PATH=/path/to/chrome pnpm capture:web-traffic
pnpm test -- traffic-replay
```

`scripts/capture-web-traffic.mjs` (shared proxy and fixture code in `scripts/capture-lib.mjs`) serves
the built vault from the Worker under `vite dev` behind the same throwaway TLS proxy (the client
refuses plain http) and drives it with `playwright-core`: one browser context per scenario, a fresh
account per scenario (registered over HTTP, with new device verification off, except `web-register`
which signs up through the UI). Without `CHROMIUM_PATH` it uses a browser installed with
`pnpm exec playwright-core install chromium`. `CAPTURE_ONLY=send` records one scenario;
`CAPTURE_DEBUG_DIR` keeps screenshots of each step for debugging a changed UI (never commit them).
The selectors follow the vault UI of the pinned upstream tag, so a client upgrade may need them
adjusted.

Web specifics in the replay: `GET /api/devices/knowndevice` needs `X-Request-Email` (the address as
base64url, rebuilt from the replay account) and `X-Device-Identifier`; `web-register` replays the
registration itself, so the test does not pre-register that account.

## Sanitisation rules

`scripts/traffic-sanitise.mjs` is deterministic and idempotent:

| Value | Replaced by |
|---|---|
| UUIDs | `00000000-0000-0000-0000-00000000000N`, numbered by first appearance |
| Passwords, hashes, API secrets, tokens, JWTs | `__NAME__`, `__NAME_2__` and so on, one per distinct value |
| Email addresses | `user@example.com` |
| Local hosts and ports | `vault.example.com` |
| Dates | `2099-01-01T00:00:00.000Z` |
| EncStrings, keys and other long base64 values | the same shape with every data character zeroed |

Only the `Bitwarden-Client-*` and `Device-Type` request headers are kept, plus the `Authorization`
header with a placeholder token. Response headers are not stored.
