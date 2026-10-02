import { and, asc, eq, gt, inArray } from 'drizzle-orm'
import { createDb, schema } from '../db'
import type { Bindings } from '../env'
import { errorKind, log } from '../log'
import { loadStoredPush, pushKeyUnreadable } from './push-config'

/**
 * Mobile push through the Bitwarden push relay (TASKS #103, #262).
 *
 * A self-hosted server does not hold Apple or Google credentials. The Bitwarden relay does: this
 * server proves who it is with an installation id and key (from the host registration page),
 * registers each mobile device's push token with the relay and asks the relay to deliver pushes.
 * The relay then wakes the official apps, which sync. Everything here is optional and silent when
 * the credentials are absent, and no failure ever reaches the request that caused the push.
 */

export const DEFAULT_RELAY_URI = 'https://push.bitwarden.com'
export const DEFAULT_IDENTITY_URI = 'https://identity.bitwarden.com'

/** Device types that register with the relay: Android, iOS and Android (Amazon). */
const MOBILE_TYPES = new Set([0, 1, 15])

export interface RelayConfig {
  installationId: string
  installationKey: string
  relayUri: string
  identityUri: string
}

const trimUri = (s: string) => s.replace(/\/+$/, '')

/** Config from the Worker secrets alone. Null when either credential is missing. */
export function relayConfig(env: Bindings): RelayConfig | null {
  const installationId = env.PUSH_INSTALLATION_ID?.trim()
  const installationKey = env.PUSH_INSTALLATION_KEY?.trim()
  if (!installationId || !installationKey) return null
  return {
    installationId,
    installationKey,
    relayUri: trimUri(env.PUSH_RELAY_URI?.trim() || DEFAULT_RELAY_URI),
    identityUri: trimUri(env.PUSH_IDENTITY_URI?.trim() || DEFAULT_IDENTITY_URI),
  }
}

export type RelaySource = 'env' | 'settings'

/** Effective config: Worker secrets override the instance admin settings stored in the database. */
export async function resolveRelay(
  env: Bindings,
): Promise<{ cfg: RelayConfig; source: RelaySource } | null> {
  const fromEnv = relayConfig(env)
  if (fromEnv) return { cfg: fromEnv, source: 'env' }
  const stored = await loadStoredPush(env)
  if (!stored) return null
  const { installationId, installationKey, relayUri, identityUri } = stored
  return { cfg: { installationId, installationKey, relayUri, identityUri }, source: 'settings' }
}

/** Status for diagnostics. Never includes the key. */
export async function relayStatus(env: Bindings) {
  const r = await resolveRelay(env)
  const unreadable = !r && (await pushKeyUnreadable(env))
  const partial =
    Boolean(env.PUSH_INSTALLATION_ID?.trim()) !== Boolean(env.PUSH_INSTALLATION_KEY?.trim())
  return {
    configured: r !== null,
    state: r
      ? 'configured'
      : partial
        ? 'incomplete'
        : unreadable
          ? 'key unreadable'
          : 'not configured',
    source: r?.source ?? null,
    envOverride: relayConfig(env) !== null,
    relayHost: r ? new URL(r.cfg.relayUri).host : null,
    identityHost: r ? new URL(r.cfg.identityUri).host : null,
    lastResult: last,
  }
}

interface Outcome {
  at: string
  ok: boolean
  status: number | null
}
let last: Outcome | null = null
const record = (ok: boolean, status: number | null) => {
  last = { at: new Date().toISOString(), ok, status }
}

// Access token for the relay, cached per isolate until shortly before it expires.
let cached: { key: string; token: string; expires: number } | null = null

const tokenKey = (cfg: RelayConfig) =>
  `${cfg.identityUri}|${cfg.installationId}|${cfg.installationKey}`

async function accessToken(cfg: RelayConfig, force = false): Promise<string> {
  const key = tokenKey(cfg)
  if (!force && cached && cached.key === key && cached.expires > Date.now() + 60_000) {
    return cached.token
  }
  const res = await fetch(`${cfg.identityUri}/connect/token`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'api.push',
      client_id: `installation.${cfg.installationId}`,
      client_secret: cfg.installationKey,
    }),
  })
  if (!res.ok) {
    record(false, res.status)
    throw new Error(`relay token ${res.status}`)
  }
  const body = (await res.json()) as { access_token?: string; expires_in?: number }
  if (!body.access_token) throw new Error('relay token missing')
  cached = {
    key,
    token: body.access_token,
    expires: Date.now() + (body.expires_in ?? 3600) * 1000,
  }
  return body.access_token
}

async function call(
  cfg: RelayConfig,
  method: string,
  path: string,
  body?: unknown,
): Promise<Response> {
  const send = async (force: boolean) =>
    fetch(`${cfg.relayUri}${path}`, {
      method,
      redirect: 'manual',
      headers: {
        Authorization: `Bearer ${await accessToken(cfg, force)}`,
        'Content-Type': 'application/json',
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
  let res = await send(false)
  // The token may have been revoked or rotated early: fetch a new one once.
  if (res.status === 401) res = await send(true)
  record(res.ok, res.status)
  return res
}

/** Runs a relay call, swallowing every failure into a log line without payloads. */
async function guarded(env: Bindings, event: string, work: (cfg: RelayConfig) => Promise<void>) {
  const resolved = await resolveRelay(env).catch(() => null)
  if (!resolved) return
  try {
    await work(resolved.cfg)
  } catch (err) {
    log('warn', event, { errorKind: errorKind(err) }, env)
  }
}

export interface RelayDevice {
  uuid: string
  identifier: string
  type: number
  pushToken: string | null
  userUuid: string
}

/** Ids of the confirmed organisations of a user: the relay uses them for organisation pushes. */
async function confirmedOrgIds(env: Bindings, userUuid: string): Promise<string[]> {
  const rows = await createDb(env.DB)
    .select({ id: schema.usersOrganizations.organizationUuid })
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.userUuid, userUuid),
        eq(schema.usersOrganizations.status, 2),
      ),
    )
  return rows.map((r) => r.id)
}

/** Registers a mobile device (push token present) with the relay, or removes it when cleared. */
export async function relayRegisterDevice(env: Bindings, device: RelayDevice): Promise<void> {
  if (!MOBILE_TYPES.has(device.type)) return
  await guarded(env, 'push.register_failed', async (cfg) => {
    if (!device.pushToken) {
      await call(cfg, 'DELETE', `/push/${encodeURIComponent(device.uuid)}`)
      return
    }
    const res = await call(cfg, 'POST', '/push/register', {
      deviceId: device.uuid,
      pushToken: device.pushToken,
      userId: device.userUuid,
      type: device.type,
      identifier: device.identifier,
      organizationIds: await confirmedOrgIds(env, device.userUuid),
      installationId: cfg.installationId,
    })
    if (!res.ok) log('warn', 'push.register_rejected', { status: res.status }, env)
  })
}

export async function relayDeleteDevice(env: Bindings, device: RelayDevice): Promise<void> {
  if (!MOBILE_TYPES.has(device.type) || !device.pushToken) return
  await guarded(env, 'push.delete_failed', async (cfg) => {
    await call(cfg, 'DELETE', `/push/${encodeURIComponent(device.uuid)}`)
  })
}

/** Registers every mobile device of a user again, for example after their organisations changed. */
export async function relayRefreshUser(env: Bindings, userUuid: string): Promise<void> {
  if (!(await resolveRelay(env).catch(() => null))) return
  try {
    const rows = await createDb(env.DB)
      .select()
      .from(schema.devices)
      .where(
        and(eq(schema.devices.userUuid, userUuid), inArray(schema.devices.type, [...MOBILE_TYPES])),
      )
    for (const d of rows) {
      if (d.pushToken) {
        await relayRegisterDevice(env, {
          uuid: d.uuid,
          identifier: d.identifier,
          type: d.type,
          pushToken: d.pushToken,
          userUuid,
        })
      }
    }
  } catch (err) {
    log('warn', 'push.refresh_failed', { errorKind: errorKind(err) }, env)
  }
}

export interface RelayPush {
  type: number
  payload: unknown
  /** Target one user's devices. */
  userId?: string
  /** Target every registered device of an organisation's members. */
  organizationId?: string
  /** Device identifier that made the change, which the relay skips. */
  excludeIdentifier?: string | null
}

/** Asks the relay to push to the targeted devices. No-op when not configured. */
export async function relaySend(env: Bindings, push: RelayPush): Promise<void> {
  await guarded(env, 'push.send_failed', async (cfg) => {
    if (!push.userId && !push.organizationId) return
    const res = await call(cfg, 'POST', '/push/send', {
      userId: push.userId ?? null,
      organizationId: push.organizationId ?? null,
      deviceId: null,
      identifier: push.excludeIdentifier ?? null,
      type: push.type,
      payload: push.payload,
      clientType: null,
      installationId: cfg.installationId,
    })
    if (!res.ok) log('warn', 'push.send_rejected', { status: res.status }, env)
  })
}

/** Most devices registered again per run: keeps within the Worker subrequest limit of a paid plan. */
const REREGISTER_MAX = 800
const PAGE = 100
let reregistering = false
let reregisterAgain = false

/**
 * Registers every mobile device with a push token again, after the credentials changed. Pages
 * through devices by id, never overlaps another run (a change during a run schedules one more
 * pass) and logs when more than REREGISTER_MAX devices were left for the next change or app start.
 */
export async function relayReregisterAll(env: Bindings): Promise<number> {
  if (reregistering) {
    reregisterAgain = true
    return 0
  }
  reregistering = true
  let total = 0
  try {
    do {
      reregisterAgain = false
      total += await reregisterPass(env)
    } while (reregisterAgain)
  } finally {
    reregistering = false
  }
  return total
}

async function reregisterPass(env: Bindings): Promise<number> {
  if (!(await resolveRelay(env).catch(() => null))) return 0
  let count = 0
  let after = ''
  try {
    for (;;) {
      const rows = await createDb(env.DB)
        .select()
        .from(schema.devices)
        .where(and(inArray(schema.devices.type, [...MOBILE_TYPES]), gt(schema.devices.uuid, after)))
        .orderBy(asc(schema.devices.uuid))
        .limit(PAGE)
      if (rows.length === 0) break
      after = rows[rows.length - 1]?.uuid ?? ''
      const withToken = rows.filter((d) => d.pushToken)
      for (let i = 0; i < withToken.length; i += 10) {
        await Promise.all(
          withToken.slice(i, i + 10).map((d) =>
            relayRegisterDevice(env, {
              uuid: d.uuid,
              identifier: d.identifier,
              type: d.type,
              pushToken: d.pushToken,
              userUuid: d.userUuid,
            }),
          ),
        )
      }
      count += withToken.length
      if (count >= REREGISTER_MAX) {
        log('warn', 'push.reregister_truncated', { registered: count }, env)
        break
      }
      if (rows.length < PAGE) break
    }
  } catch (err) {
    log('warn', 'push.reregister_failed', { errorKind: errorKind(err) }, env)
  }
  return count
}

export type TestClass = 'ok' | 'not_configured' | 'rejected' | 'unreachable' | 'bad_response'

/** Asks the identity server for a relay token with the effective config. Returns a class only. */
export async function relayTestConnection(env: Bindings): Promise<TestClass> {
  const r = await resolveRelay(env).catch(() => null)
  if (!r) return 'not_configured'
  try {
    const res = await fetch(`${r.cfg.identityUri}/connect/token`, {
      method: 'POST',
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'api.push',
        client_id: `installation.${r.cfg.installationId}`,
        client_secret: r.cfg.installationKey,
      }),
    })
    record(res.ok, res.status)
    if (!res.ok) return 'rejected'
    const body = (await res.json().catch(() => null)) as { access_token?: string } | null
    return body?.access_token ? 'ok' : 'bad_response'
  } catch {
    record(false, null)
    return 'unreachable'
  }
}
