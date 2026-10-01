# Web vault

Cloudwarden serves the official Bitwarden web vault from the same origin as the API, using
Workers static assets (TASKS #143). The vault is not vendored into git: it is fetched at build
time from Bitwarden's published container image and verified against a pinned digest.

## Fetching

```sh
pnpm web-vault:fetch    # download, verify and extract into web-vault/ (gitignored)
pnpm web-vault:update   # resolve the newest stable tag, rewrite the lock file, then fetch
```

`web-vault.lock.json` records the image, tag, index digest, platform manifest digest and the
sha256 and size of every layer. The script checks the manifest digest, that the layer list matches
the lock, and every layer sha256 before anything is published into `web-vault/`. It talks to the
registry over plain HTTPS with an anonymous pull token and needs no extra tools. Update the lock
in its own commit so the change is reviewable.

Extraction keeps only the image's `/app` web root, drops source maps and the upstream
`app-id.json`, and adds:

- `LICENSE-NOTICE.txt`: GPL-3.0 notice with the exact source image, digest and upstream location.
- `_headers`: security headers for static responses (see below).
- `cloudwarden/admin-link.js`: copied from `web-vault-overlay/admin-link.js`, plus one
  `<script src="cloudwarden/admin-link.js" integrity="sha384-..." defer>` tag before `</head>` in
  `index.html`. The integrity value is the SHA-384 of the copied file, computed at fetch time.
  Injection replaces any earlier tag, so it is deterministic and idempotent, and it runs even when
  the vault is already up to date. The script is same-origin, so `script-src 'self'` allows it.
  See `docs/admin.md`.
- `.fetched`: stamp so repeat runs are no-ops. Use `--force` to refetch.

Only Bitwarden's own image is used. Nothing from any third-party web vault build is used.

## Deploying

`web-vault/` must exist before `cf build` or `cf deploy`, because Vite copies it (its `publicDir`)
into the asset bundle:

```sh
pnpm web-vault:fetch
cf deploy
```

The deploy workflow builds first and fails unless the built `index.html` references
`cloudwarden/admin-link.js` and the built script matches `web-vault-overlay/admin-link.js`. After
deploying it also checks that the served `/` contains the tag.

Without the directory the Worker still builds and all tests pass (the API works, `/` has no
vault). CI test runs do not need the vault.

## Routing

`cloudflare.config.ts` sets `assets.runWorkerFirst` so the Worker handles `/api/*`, `/identity/*`,
`/admin*`, `/notifications/*`, `/icons/*`, `/events/*`, `/attachments/*`, `/send-files/*`, `/alive`
and `/app-id.json` before any
static lookup. Everything else is served from assets, with unknown paths falling back to
`index.html` (single-page application routing).

## Runtime configuration

The official build needs no generated config file. Its default environment URLs are relative
(`/api`, `/identity`, `/notifications`, `/icons`, `/events`), which resolve against the page origin.
The only upstream file that embeds an origin is `app-id.json` (the FIDO U2F facet list); the Worker
serves that dynamically from `DOMAIN` instead.

## Headers

Static asset responses bypass the Worker, so their headers come from the generated `_headers`
file: a Content-Security-Policy that allows `wasm-unsafe-eval` (needed by the vault's WebAssembly
SDK), same-origin scripts and connections, Duo frames and the breach-check API, plus
`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy`. The policy
is our own, written for this deployment; the current image no longer ships an nginx config to
mirror. Loosen `connect-src` or `frame-src` in `scripts/fetch-web-vault.mjs` if you enable
integrations that need other origins.

## Licence

The web vault is Copyright Bitwarden Inc. and licensed under GPL-3.0. Cloudwarden does not modify
Bitwarden's code; it only adds the admin link script tag described above. The notice shipped at `/LICENSE-NOTICE.txt` points to the corresponding source for the pinned
version (https://github.com/bitwarden/clients). Bitwarden is a trademark of Bitwarden Inc.; this
project is not affiliated with it.
