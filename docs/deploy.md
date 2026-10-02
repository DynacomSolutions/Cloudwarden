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
pnpm exec cf workers secrets update ADMIN_EMAILS      # comma-separated admin addresses
# optional mobile push (docs/push-notifications.md):
# pnpm exec cf workers secrets update PUSH_INSTALLATION_ID
# pnpm exec cf workers secrets update PUSH_INSTALLATION_KEY
```

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

`.github/workflows/deploy.yml` runs on every push to `main` (and manually). It runs lint, typecheck and tests,
applies D1 migrations, deploys, then smoke-checks `/alive` with retries.

1. In the repository settings create an environment named `production`. Add required reviewers or branch
   restrictions as you see fit.
2. Add these environment secrets:

   | Secret | Value |
   |---|---|
   | `CLOUDFLARE_API_TOKEN` | Scoped API token from step 1 |
   | `CLOUDFLARE_ACCOUNT_ID` | Account id |
   | `CF_D1_DATABASE_ID` | D1 database id from step 2 |
   | `DEPLOY_DOMAIN` | Hostname, for example `vault.example.com` |
   | `MAIL_FROM` | Optional sender, for example `Cloudwarden <noreply@example.com>` |

   Optionally add environment variables (not secrets) `ADMIN_ENABLED` and `SIGNUPS_ALLOWED`; both default to `false`.

3. Jobs run on the `k3s-runners` label (self-hosted). Register a runner with that label, or change `runs-on` in the
   workflow to match your runner.

The domain is masked in logs. Worker secrets (step 4) are intentionally not touched by CI.
