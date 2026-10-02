import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers'
import { defineConfig } from 'vitest/config'

// Tests run inside workerd. Bindings are declared inline here (mirroring
// cloudflare.config.ts) because the pool reads Miniflare options, not cf config.
export default defineConfig(async () => {
  const migrations = await readD1Migrations('./migrations')
  return {
    plugins: [
      cloudflareTest({
        main: './src/index.ts',
        miniflare: {
          // Newest date supported by the workerd bundled with the test pool.
          compatibilityDate: '2026-08-22',
          compatibilityFlags: ['nodejs_compat'],
          bindings: {
            DOMAIN: 'https://vault.example.com',
            SIGNUPS_ALLOWED: 'true',
            ADMIN_ENABLED: 'false',
            JWT_SECRET: 'test-secret-test-secret-test-secret-0123456789',
            TEST_MIGRATIONS: migrations,
          },
          // DB_PEER is the second instance of the federation tests (TASKS #308).
          d1Databases: {
            DB: '00000000-0000-0000-0000-000000000000',
            DB_PEER: 'cloudwarden-peer',
          },
          r2Buckets: ['ATTACHMENTS'],
          durableObjects: { NOTIFICATIONS: { className: 'NotificationHub', useSQLite: true } },
        },
      }),
    ],
    test: {
      include: ['test/**/*.test.ts'],
      // Organisation flows register several accounts, each costing a password hash.
      testTimeout: 30_000,
      setupFiles: ['./test/setup.ts'],
    },
  }
})
