import { Hono } from 'hono'
import type { Env } from '../env'

export const config = new Hono<Env>()

/**
 * Version string reported to clients. Current clients compare it against minimum-version gates, so
 * it tracks the newest client release line we have verified, not Cloudwarden's own release number.
 * See docs/compatibility.md.
 */
export const SERVER_VERSION = '2026.9.0'

config.get('/api/config', (c) => {
  const base = c.env.DOMAIN.replace(/\/+$/, '')
  return c.json({
    object: 'config',
    version: SERVER_VERSION,
    gitHash: c.env.GIT_HASH || 'unknown',
    server: { name: 'Cloudwarden', url: base },
    environment: {
      cloudRegion: null,
      vault: base,
      api: `${base}/api`,
      identity: `${base}/identity`,
      notifications: `${base}/notifications`,
      sso: `${base}/sso`,
    },
    featureStates: {},
    push: { pushTechnology: 0 },
    settings: { disableUserRegistration: c.env.SIGNUPS_ALLOWED !== 'true' },
  })
})
