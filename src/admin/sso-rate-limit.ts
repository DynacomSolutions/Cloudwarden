// Instance admin SSO login rate limit (TASKS #424). Stored in `instance_settings` like the other
// admin settings; unset means the `LOGIN_LIMITER` binding decides, as before.
import type { Bindings } from '../env'
import { ApiError } from '../errors'
import { errorKind, log } from '../log'
import { AdminEventType, type Audit, auditStatement } from './service'

const KEY = 'sso-rate-limit'
const CACHE_MS = 10_000
/** Effective default: the binding's 20 per minute, or the D1 fallback the SSO routes pass without one. */
export const SSO_RATE_LIMIT_DEFAULT = 20
export const SSO_RATE_LIMIT_D1_DEFAULT = 30
export const SSO_RATE_LIMIT_MIN = 5
export const SSO_RATE_LIMIT_MAX = 1000

// Short lived per isolate cache. Writes invalidate it in the isolate that handled them; other
// isolates see a change within CACHE_MS.
let cache: { at: number; value: number | null } | null = null
export const invalidateSsoRateLimit = () => {
  cache = null
}

/** The per minute limit an admin set, or null when unset. */
export async function loadSsoRateLimit(env: Bindings): Promise<number | null> {
  if (cache && Date.now() - cache.at < CACHE_MS) return cache.value
  let row: { config: string } | null
  try {
    row = await env.DB.prepare('SELECT config FROM instance_settings WHERE key = ?1')
      .bind(KEY)
      .first<{ config: string }>()
  } catch (e) {
    // The binding decides while the setting cannot be read; retry after one second.
    log('warn', 'sso.ratelimit.read_failed', { errorKind: errorKind(e) }, env)
    cache = { at: Date.now() - CACHE_MS + 1000, value: null }
    return null
  }
  let value: number | null = null
  try {
    const v = row
      ? (JSON.parse(row.config) as { ssoRateLimitPerMinute?: unknown }).ssoRateLimitPerMinute
      : null
    if (
      Number.isInteger(v) &&
      (v as number) >= SSO_RATE_LIMIT_MIN &&
      (v as number) <= SSO_RATE_LIMIT_MAX
    ) {
      value = v as number
    }
  } catch {
    // Unreadable config reads as unset.
  }
  cache = { at: Date.now(), value }
  return value
}

export async function ssoRateLimitView(env: Bindings) {
  const v = await loadSsoRateLimit(env)
  return {
    ssoRateLimitPerMinute:
      v ?? (env.LOGIN_LIMITER ? SSO_RATE_LIMIT_DEFAULT : SSO_RATE_LIMIT_D1_DEFAULT),
    custom: v !== null,
  }
}

export async function saveSsoRateLimit(env: Bindings, raw: unknown, audit: Audit) {
  const b = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  const v = b.ssoRateLimitPerMinute
  if (
    typeof v !== 'number' ||
    !Number.isInteger(v) ||
    v < SSO_RATE_LIMIT_MIN ||
    v > SSO_RATE_LIMIT_MAX
  ) {
    const message = `Enter a whole number from ${SSO_RATE_LIMIT_MIN} to ${SSO_RATE_LIMIT_MAX}.`
    throw new ApiError(400, message, { ssoRateLimitPerMinute: [message] })
  }
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO instance_settings (key, config, updated_at, updated_by) VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT (key) DO UPDATE SET config = ?2, updated_at = ?3, updated_by = ?4`,
    ).bind(KEY, JSON.stringify({ ssoRateLimitPerMinute: v }), audit.now ?? Date.now(), audit.actor),
    auditStatement(env.DB, audit, AdminEventType.SsoRateLimitUpdated),
  ])
  invalidateSsoRateLimit()
  return ssoRateLimitView(env)
}

export async function deleteSsoRateLimit(env: Bindings, audit: Audit) {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM instance_settings WHERE key = ?1').bind(KEY),
    auditStatement(env.DB, audit, AdminEventType.SsoRateLimitUpdated),
  ])
  invalidateSsoRateLimit()
  return ssoRateLimitView(env)
}
