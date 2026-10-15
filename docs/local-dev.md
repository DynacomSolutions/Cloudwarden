# Local development

## On your machine

```sh
pnpm install
LOCAL_DEV_SECRETS=true JWT_SECRET=<32+ characters> pnpm dev
```

`pnpm dev` runs the Worker with D1, R2 and the Durable Object simulated in workerd. The local D1
starts empty: apply the migrations once with `pnpm db:migrate:local` (or let the container
entrypoint below do it). Useful checks:

| Command | What it covers |
|---|---|
| `pnpm test` | Vitest inside workerd, no server needed |
| `pnpm e2e` | The official Bitwarden CLI against a local dev server (about 2 minutes) |
| `pnpm capture:traffic` | Re-records the sanitised client traffic fixtures (about 10 minutes, see [traffic-fixtures.md](traffic-fixtures.md)) |
| `pnpm lint`, `pnpm typecheck`, `pnpm check:identifiers` | Required before pushing |

## In a container

The `Dockerfile` builds a dev image that runs the same simulator on `0.0.0.0:8080`. It is a
development convenience, not the production deployment path (see `docs/deploy.md`); state lives in
the container and is lost with it.

```sh
docker build -t cloudwarden-dev .
docker run --rm -p 8080:8080 -e SIGNUPS_ALLOWED=true cloudwarden-dev
```

`scripts/dev-container.mjs` applies the migrations, generates a `JWT_SECRET` when none is given
(kept in the state directory), and starts `vite dev`. Settings come from the environment at run
time:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Listen port |
| `JWT_SECRET` | generated | Token signing key |
| `DEPLOY_DOMAIN` | unset (`vault.example.com`) | Host Cloudwarden reports as its own (`DOMAIN`) |
| `DEV_ALLOWED_HOSTS` | `*` in the container | Host headers the Vite dev server accepts (`*` or a comma separated list); unset outside the container keeps Vite's default |
| `SIGNUPS_ALLOWED`, `ADMIN_ENABLED` | `false` | As in the README configuration table |

Build with `--build-arg WEB_VAULT=true` to build the web client into the image (see `docs/web-client.md`), or run `pnpm web:build` first so the prebuilt `web-vault/` is copied in.
