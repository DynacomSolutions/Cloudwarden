# Web client

Cloudwarden serves its own web client from the same origin as the API (TASKS #210). It is a
fork of the Bitwarden web vault: the upstream source is vendored under `web/` and built in this
repository. Nothing is fetched from a published image any more (that approach, TASKS #143, is
retired).

## Layout

`web/` is a curated copy of https://github.com/bitwarden/clients at tag `web-v2026.9.1`:

| Path | Content |
|---|---|
| `web/apps/web` | The web vault application |
| `web/libs/*` | Shared libraries it builds from |
| `web/package.json`, `package-lock.json`, `tsconfig*.json`, `tailwind.config.js`, ... | Root build configuration (workspaces trimmed to `apps/web` and `libs/**`) |
| `web/LICENSE*.txt` | Upstream licence files, kept unchanged |
| `web/NOTICE.md` | What was taken, what Cloudwarden changed, trademark notice |

The browser, desktop and CLI apps are not included. Nothing from upstream `bitwarden_license/`
(Bitwarden License v1.0) is vendored: the build is the open source (`oss`) variant, and
`pnpm check:web-licence` (`scripts/check-web-licence.mjs`, run in CI) fails if any
`bitwarden_license` path, `@bitwarden/bit-*` import or Bitwarden License header appears under
`web/`.

Cloudwarden's own code lives in directories named `cloudwarden/` where practical:

- `web/apps/web/src/app/cloudwarden/instance-admin/`: the Instance admin pages.
- `web/apps/web/src/app/cloudwarden/organizations/`: the organisation create form.
- `web/libs/components/src/cloudwarden/`: theme overrides and the Montserrat font files.

Small edits elsewhere are marked with a `Cloudwarden:` comment so they are easy to find when
merging upstream changes (`git grep -n "Cloudwarden:" -- web`).

## Building

```sh
pnpm web:build    # npm ci in web/, webpack (selfhosted, production), publish into web-vault/
```

`scripts/build-web.mjs` runs `npm ci` in `web/` (skip with `--skip-install`), then webpack with
`ENV=selfhosted NODE_ENV=production` and a 6 GiB Node heap. The output is copied into
`web-vault/` (gitignored), which Vite publishes as the Worker's static assets (`publicDir`), so
`cf build` and `cf deploy` pick it up. The script also:

- drops source maps (only produced with `CLOUDWARDEN_SOURCEMAPS=1`) and the static
  `app-id.json` (the Worker serves it from `DOMAIN`);
- writes `LICENSE-NOTICE.txt` (GPL-3.0 notice pointing at the corresponding source),
  `_headers` (security headers, see below) and `cloudwarden-build.json` (build marker with
  product, version, upstream tag and commit, checked by the deploy workflow).

The build is memory hungry. On a shared host, check `free -g` first and run one build at a time.
Outside CI the script refuses to start with less than 12 GiB available and wraps webpack in a
transient systemd scope (`MemoryHigh=8G`, `MemoryMax=12G`, `MemorySwapMax=512M`) when
`systemd-run` exists; `--no-scope` disables that. It prints the elapsed time and the scope's
peak memory. See the evidence log in `TASKS.md` for measured numbers.

Without `web-vault/` the Worker still builds and all tests pass (the API works, `/` has no web
client). CI test jobs do not build the client.

## Deploying

The deploy workflow runs `pnpm web:build` before `cf build`, caches npm downloads for
`web/package-lock.json`, has a 90 minute job timeout, and fails unless the built assets carry
`cloudwarden-build.json` and the `Cloudwarden` page title. After deploying it checks the served
marker and page title.

If the `k3s-runners` pods run out of memory or time for the webpack build, build once on a
larger machine and cache the result instead: publish `web-vault/` as an artifact keyed by the
hash of `web/` (for example `git rev-parse HEAD:web`), and have the deploy job download it when
the key matches and build only on a miss.

## Upgrading upstream

`web/` is a curated import, not a full subtree, so upgrades are done by diffing upstream tags:

1. Pick the new tag (`web-vYYYY.M.P`) and read the upstream release notes.
2. Clone both tags and produce a patch restricted to the vendored paths, without
   `bitwarden_license/`:

   ```sh
   git clone --filter=blob:none https://github.com/bitwarden/clients upstream
   cd upstream
   git diff web-v2026.9.1 web-vNEW -- apps/web libs package.json package-lock.json \
     tsconfig.base.json tsconfig.json tailwind.config.js babel.config.json angular.json nx.json \
     LICENSE.txt LICENSE_GPL.txt > ../upstream.patch
   ```

3. Apply it under `web/`: `git apply --3way --directory=web ../upstream.patch`. Resolve
   conflicts, preferring upstream except in `Cloudwarden:` edits and `cloudwarden/` directories.
4. Keep the workspaces trimmed (`apps/web`, `libs/**/*`) and regenerate the lock with
   `npm install --package-lock-only` in `web/`.
5. Re-run the locale rebrand (product name only) on new strings, update the tag in
   `scripts/build-web.mjs` (`UPSTREAM_TAG`), `web/NOTICE.md` and this file.
6. `pnpm check:web-licence`, `pnpm web:build`, `pnpm dev` and a browser check of login, vault,
   organisation creation and Instance admin, then `pnpm e2e`.

Commit the upstream patch and the conflict resolutions separately so the Cloudwarden changes stay
reviewable.

## Repository tooling

- Biome ignores `web/` (upstream uses its own ESLint and Prettier setup).
- The identifier check skips upstream files under `web/` (they contain upstream's own domains,
  emails, UUIDs and fixtures) but scans `cloudwarden/` directories, `web/NOTICE.md` and
  `web/scripts/`.
- gitleaks allowlists upstream unit test fixtures, spec data and public sandbox configuration
  under `web/` (`.gitleaks.toml`).
- TypeScript (`pnpm typecheck`) and Vitest do not include `web/`.

## Routing and headers

`cloudflare.config.ts` sets `assets.runWorkerFirst` so the Worker handles `/api/*`,
`/identity/*`, `/admin*`, `/notifications/*`, `/icons/*`, `/events/*`, `/attachments/*`,
`/send-files/*`, `/alive` and `/app-id.json` before any static lookup. Everything else is served
from assets, with unknown paths falling back to `index.html`.

The client needs no generated runtime config: its default environment URLs are relative and
resolve against the page origin. Static responses get their headers from the generated
`_headers`: a Content-Security-Policy that allows `wasm-unsafe-eval` (WebAssembly SDK),
same-origin scripts and connections, Duo frames and the breach-check API, plus
`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy`. Edit
`scripts/build-web.mjs` to loosen `connect-src` or `frame-src`.

## Licence and trademarks

The web client is GPL-3.0 (upstream Copyright Bitwarden Inc.; Cloudwarden's changes under the
same licence). The served `/LICENSE-NOTICE.txt` points to the corresponding source. Bitwarden is
a trademark of Bitwarden Inc.; Cloudwarden is not affiliated with it, and the product name, logos
and icons in the client are Cloudwarden's own.
