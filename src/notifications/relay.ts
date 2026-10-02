import { and, eq, inArray } from 'drizzle-orm'
import { createDb, schema } from '../db'
import type { Bindings } from '../env'
import { errorKind, log } from '../log'

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

/** Null when push is not configured (either credential missing). */
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

/** Status for diagnostics. Never includes the key. */
export function relayStatus(env: Bindings) {
  const cfg = relayConfig(env)
  const partial =
    Boolean(env.PUSH_INSTALLATION_ID?.trim()) !== Boolean(env.PUSH_INSTALLATION_KEY?.trim())
  return {
    configured: cfg !== null,
    state: cfg ? 'configured' : partial ? 'incomplete' : 'not configured',
    relayHost: cfg ? new URL(cfg.relayUri).host : null,
    identityHost: cfg ? new URL(cfg.identityUri).host : null,
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

async function accessToken(cfg: RelayConfig, force = false): Promise<string> {
  const key = `${cfg.identityUri}|${cfg.installationId}|${cfg.installationKey}`
  if (!force && cached && cached.key === key && cached.expires > Date.now() + 60_000) {
    return cached.token
  }
  const res = await fetch(`${cfg.identityUri}/connect/token`, {
    method: 'POST',
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
  const cfg = relayConfig(env)
  if (!cfg) return
  try {
    await work(cfg)
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
  if (!relayConfig(env)) return
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
