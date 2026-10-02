import { applyD1Migrations } from 'cloudflare:test'
import { env } from 'cloudflare:workers'

await applyD1Migrations(env.DB, env.TEST_MIGRATIONS)
await applyD1Migrations(env.DB_PEER, env.TEST_MIGRATIONS)
