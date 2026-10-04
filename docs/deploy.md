# Deployment guide

Deploy Cloudwarden to a fresh Cloudflare account. All values below are placeholders; never commit real
identifiers. Commands use the `cf` CLI (not Wrangler). Run them with `pnpm exec cf ...` from the repository root
after `pnpm install`.

## 1. Authenticate

For local use run `pnpm exec cf auth login`, or export an API token:

```sh
export CLOUDFLARE_API_TOKEN=<token>
export CLOUDFLARE_ACCOUNT_ID=<account-id>
```

The token needs edit permission for Workers Scripts, D1, R2 and Workers Routes or custom domains on the zone.
Use `pnpm exec cf cli search "<task>"` to discover exact commands if a flag differs in your `cf` version.

## 2. Create resources

```sh
pnpm exec cf d1 create cloudwarden
pnpm exec cf r2 buckets create cloudwarden-attachments
```

Record the D1 database id printed by the first command. The R2 bucket name must match `cloudflare.config.ts`.

## 3. Email sending domain

Outbound mail (invites, verification) uses Cloudflare Email Sending. Onboard your sending domain
(`example.com`) in the dashboard under Email Sending, add the DNS records it lists, and wait for verification.
Then choose a sender address on that domain and set it as `MAIL_FROM` (for example `vault@example.com`).

## 4. Worker secrets

Worker secrets are set once and are not managed by CI. Create the Worker first by running a deploy (step 6), or set
them afterwards; they persist across deploys.

```sh
pnpm exec cf workers secrets update JWT_SECRET        # long random string, e.g. openssl rand -base64 48
pnpm exec cf workers secrets update JWT_SIGNING_KEY   # optional: ES256 access tokens and JWKS for a Key Connector (docs/sso.md)
pnpm exec cf workers secrets update ADMIN_EMAILS      # comma-separated admin addresses
# optional mobile push (docs/push-notifications.md):
# pnpm exec cf workers secrets update PUSH_INSTALLATION_ID
# pnpm exec cf workers secrets update PUSH_INSTALLATION_KEY
pnpm exec cf workers secrets update DATA_ENCRYPTION_KEY  # 32+ characters; seals API keys and integration tokens (docs/integrations.md)
```

Optional, for YubiKey OTP two-factor (see `docs/two-factor.md`): `YUBICO_CLIENT_ID` and
`YUBICO_SECRET_KEY` (base64) from the Yubico key portal. Duo is configured per account or
organisation in the web vault and needs no server settings.

Each command prompts for the value (see `--help` for non-interactive input).

## 5. Custom domain

Add the zone for `example.com` to the account. Set `DEPLOY_DOMAIN=vault.example.com` at deploy time; the config
then attaches that hostname as a Workers custom domain and sets the `DOMAIN` variable to `https://vault.example.com`.

## 6. Manual deploy

```sh
export CF_D1_DATABASE_ID=<database-id>
export DEPLOY_DOMAIN=vault.example.com
# optional: ADMIN_ENABLED=true  MAIL_FROM=vault@example.com
pnpm exec cf d1 migrations apply "$CF_D1_DATABASE_ID" --dir migrations
pnpm exec cf deploy
curl -i https://vault.example.com/alive
```

## 7. Continuous deployment

`.github/workflows/deploy.yml` runs on every push to `main` (and manually). A `build` job runs lint, typecheck,
tests and the identifier check, builds the web client once, and uploads it as the `web-vault` artifact. A `deploy` job
then runs once per GitHub environment (a matrix of `production` and `personal`, `fail-fast` off, so one failing
environment does not stop the other). Each deploy downloads the artifact, builds the Worker, applies D1 migrations,
deploys, then smoke-checks `/alive` and the served web client with retries. Deploys to the same environment are
serialised (`deploy-<environment>` concurrency group, queued rather than cancelled).

1. In the repository settings create one environment per deployment: `production` and `personal`. Add required
   reviewers or branch restrictions to each as you see fit. To add another deployment, create the environment and add
   its name to `matrix.environment` in the workflow.
2. In each environment add these secrets (every environment holds its own values, for example its own Cloudflare account,
   D1 database and domain):

   | Secret | Value |
   |---|---|
   | `CLOUDFLARE_API_TOKEN` | Scoped API token from step 1 |
   | `CLOUDFLARE_ACCOUNT_ID` | Account id |
   | `CF_D1_DATABASE_ID` | D1 database id from step 2 |
   | `DEPLOY_DOMAIN` | Hostname, for example `vault.example.com` |
   | `MAIL_FROM` | Optional sender, for example `Cloudwarden <noreply@example.com>` |

   Optionally add the variables (not secrets) `ADMIN_ENABLED`, `SIGNUPS_ALLOWED`, and `FEDERATION_ENABLED`; all
   default to `false`. A repository variable applies to every environment, and an environment variable of the same name
   overrides it, so you can set a shared default at repository level and differ per environment. Federation is
   enabled on a deployment by setting `FEDERATION_ENABLED=true` for it.

   An environment whose `CLOUDFLARE_ACCOUNT_ID` secret is empty or missing is skipped cleanly (a notice, no failure),
   so forks and not-yet-configured environments do not break the workflow.

3. Jobs run on the `k3s-runners` label (self-hosted). Register a runner with that label, or change `runs-on` in the
   workflow to match your runner.

Each domain is masked in logs. Worker secrets (step 4) are intentionally not touched by CI.
