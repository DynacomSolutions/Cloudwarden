import { Hono } from 'hono'
import { mailStatus } from '../emailless'
import type { Env } from '../env'
import { advertisedVapidKey } from '../notifications/webpush'

export const config = new Hono<Env>()

/**
 * Version string reported to clients. Current clients compare it against minimum-version gates, so
 * it tracks the newest client release line we have verified, not Cloudwarden's own release number.
 * See docs/compatibility.md.
 */
export const SERVER_VERSION = '2026.9.0'

/**
 * Feature flags sent to clients (`web/libs/common/src/enums/feature-flag.enum.ts`). Flags not listed
 * keep the client default. A flag is only enabled here when Cloudwarden serves every endpoint the
 * gated feature calls (TASKS #231).
 */
export const FEATURE_STATES: Record<string, boolean | number | string> = {
  // Passkey directory report: GET /api/reports/passkey-directory.
  'inno-passkey-directory-report': true,
  // Organisation invite links (accept, confirm and auto-confirm are served, TASKS #231).
  'pm-32497-generate-invite-link': true,
  'pm-34429-invite-link-auto-confirm': true,
  'pm-39601-invite-link-notification': true,
}

config.get('/api/config', async (c) => {
  // Web push (TASKS #342): advertised once the instance has a VAPID key and the admin allows it.
  const vapidPublicKey = await advertisedVapidKey(c.env)
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
    featureStates: FEATURE_STATES,
    push: vapidPublicKey ? { pushTechnology: 1, vapidPublicKey } : { pushTechnology: 0 },
    settings: { disableUserRegistration: c.env.SIGNUPS_ALLOWED !== 'true' },
    // Cloudwarden extension (TASKS #350): whether mail works and what each feature does without it.
    cloudwarden: { email: mailStatus(c.env) },
  })
})
