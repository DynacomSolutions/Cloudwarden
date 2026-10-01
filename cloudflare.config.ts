import { bindings, defineConfig, exports } from 'cf/config'

// Secrets (set with `cf secrets`, never committed): JWT_SECRET, ADMIN_TOKEN_HASH, ADMIN_EMAILS.
export default defineConfig({
  worker: {
    name: 'cloudwarden',
    compatibilityDate: '2026-09-25',
    compatibilityFlags: ['nodejs_compat'],
    entrypoint: 'src/index.ts',
    env: {
      DOMAIN: bindings.text('https://vault.example.com'),
      SIGNUPS_ALLOWED: bindings.text('false'),
      ADMIN_ENABLED: bindings.text('false'),
      MAIL_FROM: bindings.text('Cloudwarden <noreply@example.com>'),
      // Cloudflare Email Service (TASKS #141). Onboard the sending domain first.
      EMAIL: bindings.sendEmail(),
      DB: bindings.d1({
        name: 'cloudwarden',
        // Placeholder: replace with the real database id at deploy time.
        id: '00000000-0000-4000-8000-000000000000',
      }),
      ATTACHMENTS: bindings.r2({
        name: 'cloudwarden-attachments',
      }),
      NOTIFICATIONS: bindings.durableObject({
        worker: 'cloudwarden',
        exportName: 'NotificationHub',
      }),
    },
    exports: {
      NotificationHub: exports.durableObject({ storage: 'sqlite' }),
    },
  },
})
