import { bindings, defineConfig, exports, triggers } from 'cf/config'

// Secrets (set with `cf workers secrets update`, never committed): JWT_SECRET (32+ characters),
// JWT_SECRET_PREVIOUS (only while rotating), ADMIN_EMAILS. Deploy-time values
// come from the environment (see docs/deploy.md); the committed defaults are placeholders.
const env = process.env
const domain = env.DEPLOY_DOMAIN || undefined
export default defineConfig({
  worker: {
    name: 'cloudwarden',
    compatibilityDate: '2026-09-25',
    compatibilityFlags: ['nodejs_compat'],
    entrypoint: 'src/index.ts',
    ...(domain ? { domains: [domain] } : {}),
    // Official Bitwarden web vault, populated by `pnpm web-vault:fetch` (TASKS #143). Vite copies
    // `web-vault/` (its publicDir) into the client build output, which is what gets deployed.
    assets: {
      htmlHandling: 'auto-trailing-slash',
      notFoundHandling: 'single-page-application',
      // The Worker handles API, auth, push, icon, events and health routes first, so a static
      // file can never shadow them. `/admin*` stays worker-first so the removed server-rendered
      // admin returns the standard 404 JSON instead of the single-page fallback (the vault).
      runWorkerFirst: [
        '/api/*',
        '/identity/*',
        '/admin*',
        '/notifications/*',
        '/icons/*',
        '/events/*',
        '/attachments/*',
        '/send-files/*',
        '/alive',
        '/app-id.json',
      ],
    },
    // Workers Logs: structured JSON lines from src/log.ts (TASKS #164), see docs/observability.md.
    observability: {
      enabled: true,
      logs: { enabled: true, invocationLogs: false },
      headSamplingRate: 1,
    },
    env: {
      // Local dev only: the dev server drops secrets that are not declared, so
      // `LOCAL_DEV_SECRETS=true JWT_SECRET=... ADMIN_EMAILS=... pnpm dev` (or `.dev.vars`) declares
      // JWT_SECRET and ADMIN_EMAILS (to try the web client's Instance admin pages). Never set the
      // flag when deploying; production secrets are set out of band with `cf workers secrets`.
      ...(env.LOCAL_DEV_SECRETS === 'true'
        ? { JWT_SECRET: bindings.secret(), ADMIN_EMAILS: bindings.secret() }
        : {}),
      DOMAIN: bindings.text(domain ? `https://${domain}` : 'https://vault.example.com'),
      SIGNUPS_ALLOWED: bindings.text(env.SIGNUPS_ALLOWED || 'false'),
      ADMIN_ENABLED: bindings.text(env.ADMIN_ENABLED || 'false'),
      // D1 Sessions API wrapper, off by default; needs read replication (docs/d1-sessions.md).
      D1_SESSIONS: bindings.text(env.D1_SESSIONS || 'false'),
      ICONS_ENABLED: bindings.text(env.ICONS_ENABLED || 'true'),
      MAIL_FROM: bindings.text(env.MAIL_FROM || 'Cloudwarden <noreply@example.com>'),
      // Cloudflare Email Service (TASKS #141). Onboard the sending domain first.
      EMAIL: bindings.sendEmail(),
      // Comma-separated domains or addresses allowed to register while SIGNUPS_ALLOWED is false.
      SIGNUPS_DOMAINS_WHITELIST: bindings.text(''),
      DB: bindings.d1({
        name: 'cloudwarden',
        // Placeholder default; CI supplies the real id via CF_D1_DATABASE_ID.
        id: env.CF_D1_DATABASE_ID || '00000000-0000-4000-8000-000000000000',
      }),
      // Applied per client address to prelogin, token and register (TASKS #29).
      LOGIN_LIMITER: bindings.rateLimit({ namespace: '1001', simple: { limit: 20, period: 60 } }),
      ATTACHMENTS: bindings.r2({
        name: 'cloudwarden-attachments',
      }),
      NOTIFICATIONS: bindings.durableObject({
        worker: 'cloudwarden',
        exportName: 'NotificationHub',
      }),
    },
    // Hourly purge of expired Sends and orphaned blobs (TASKS #84) and a daily D1 export to R2 at
    // 03:17 UTC (TASKS #162, see docs/backup.md). src/scheduled.ts dispatches on the cron string, so
    // the daily expression must equal BACKUP_CRON in src/backup.ts.
    triggers: [
      triggers.scheduled({ schedule: '17 * * * *' }),
      triggers.scheduled({ schedule: '17 3 * * *' }),
    ],
    exports: {
      NotificationHub: exports.durableObject({ storage: 'sqlite' }),
    },
  },
})
