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
| `PORT` or `DEVDEPLOY_PORT` | `8080` | Listen port |
| `JWT_SECRET` | generated | Token signing key |
| `DEPLOY_DOMAIN` | unset (`vault.example.com`) | Host Cloudwarden reports as its own (`DOMAIN`) |
| `DEV_ALLOWED_HOSTS` | `*` in the container | Host headers the Vite dev server accepts (`*` or a comma separated list); unset outside the container keeps Vite's default |
| `SIGNUPS_ALLOWED`, `ADMIN_ENABLED` | `false` | As in the README configuration table |

Build with `--build-arg WEB_VAULT=true` to bake in the official web vault (see `docs/web-vault.md`).

## On the cluster with `devdeploy`

`devdeploy` builds the `Dockerfile`, pushes the image and deploys a Helm chart through Argo CD,
then prints the local, LAN and public URLs for the instance. The chart is where hostname values
live (`devdeploy init` writes the LAN suffix and public domain into its `values.yaml`), so it
must **not** be committed here. Keep it in a private repository or a directory outside this
checkout:

```sh
# once, from a scratch directory outside this repository
devdeploy init cloudwarden          # scaffolds ./chart; commit and push it to your private repo
# then, from this repository
devdeploy <instance> --template /path/to/private-repo/chart
devdeploy logs <instance> --template /path/to/private-repo/chart
devdeploy down <instance> --template /path/to/private-repo/chart
```

(`DEVDEPLOY_TEMPLATE` sets the template path for every command.) The `chart/` and `k8s/`
directories are git-ignored in this repository as a guard, and `pnpm check:identifiers` rejects
hostnames if one slips through. Hostnames reach the app only at run time, for example
`DEPLOY_DOMAIN` set in the chart or the instance's environment secret.

Limits of the dev ingress:

- Development Mappings are HTTP only. The official CLI refuses non-HTTPS server URLs, and
  WebAuthn (passkeys, #125) needs an HTTPS origin equal to `DOMAIN`. Browser web vault use over a
  `*.localhost` name works for everything else; for CLI or passkey work use `pnpm test` and
  `pnpm e2e`, which front the server with a local TLS proxy.
- `DOMAIN` is always `https://` plus `DEPLOY_DOMAIN`; the Host header Vite sees is independent of
  it (`DEV_ALLOWED_HOSTS`).
