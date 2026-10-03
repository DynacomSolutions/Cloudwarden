// Instance admin managed mobile push settings (TASKS #277). The installation key is write only:
// it is sealed at rest and no response ever contains it, only a `keySet` flag and a masked tail.
import type { Bindings } from '../env'
import { ApiError } from '../errors'
import {
  deletePushStatement,
  deriveUris,
  invalidatePushConfig,
  loadStoredPush,
  pushKeyUnreadable,
  type Region,
  savePushStatements,
} from '../notifications/push-config'
import { relayReregisterAll, relayStatus } from '../notifications/relay'
import { loadWebPush, setWebPushEnabled } from '../notifications/webpush'
import { AdminEventType, type Audit, auditStatement } from './service'

const REGIONS = ['us', 'eu', 'custom']

export async function pushSettingsView(env: Bindings) {
  const s = await loadStoredPush(env)
  return {
    installationId: s?.installationId ?? '',
    keySet: s !== null,
    // A key is stored but cannot be opened (the encryption key changed): it must be entered again.
    keyUnreadable: s === null && (await pushKeyUnreadable(env)),
    region: s?.region ?? 'us',
    relayUri: s?.relayUri ?? null,
    identityUri: s?.identityUri ?? null,
    updatedAt: s ? new Date(s.updatedAt).toISOString() : null,
    status: await relayStatus(env),
  }
}

const fieldError = (field: string, message: string) =>
  new ApiError(400, message, { [field]: [message] })

export async function savePushSettings(
  env: Bindings,
  raw: unknown,
  audit: Audit,
  later: (work: Promise<unknown>) => void,
) {
  const b = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  const installationId = typeof b.installationId === 'string' ? b.installationId.trim() : ''
  if (!/^[A-Za-z0-9-]{8,64}$/.test(installationId)) {
    throw fieldError('installationId', 'Enter the installation ID from bitwarden.com/host.')
  }
  const key = typeof b.installationKey === 'string' ? b.installationKey.trim() : ''
  if (key && (key.length > 256 || /\s/.test(key))) {
    throw fieldError('installationKey', 'The installation key is not valid.')
  }
  const region = b.region as Region
  if (!REGIONS.includes(region)) throw fieldError('region', 'Choose us, eu or custom.')
  const uris = deriveUris(region, b)
  if (!uris) {
    throw fieldError('relayUri', 'Custom relay and identity addresses must be public https URLs.')
  }
  const before = await loadStoredPush(env)
  if (!key && !before) throw fieldError('installationKey', 'Enter the installation key.')
  // A stored key is never sent to a new destination: changing a relay address needs the key again.
  if (
    !key &&
    before &&
    (before.relayUri !== uris.relayUri || before.identityUri !== uris.identityUri)
  ) {
    throw fieldError(
      'installationKey',
      'Enter the installation key again when the region or addresses change.',
    )
  }

  const now = audit.now ?? Date.now()
  const upsert = await savePushStatements(
    env,
    { installationId, installationKey: key || null, region, ...uris },
    audit.actor,
    now,
  )
  await env.DB.batch([upsert, auditStatement(env.DB, audit, AdminEventType.PushSettingsUpdated)])
  invalidatePushConfig()

  const changed =
    !before ||
    before.installationId !== installationId ||
    (key !== '' && key !== before.installationKey) ||
    before.relayUri !== uris.relayUri ||
    before.identityUri !== uris.identityUri
  // Phones registered under the old credentials must be registered again (best effort).
  if (changed) later(relayReregisterAll(env))
  return pushSettingsView(env)
}

export async function deletePushSettings(env: Bindings, audit: Audit) {
  await env.DB.batch([
    deletePushStatement(env),
    auditStatement(env.DB, audit, AdminEventType.PushSettingsRemoved),
  ])
  invalidatePushConfig()
  return pushSettingsView(env)
}

// ----- Browser web push (TASKS #342) -----

/** Web push state for the instance admin: the switch, whether the key opened, and subscribers. */
export async function webPushView(env: Bindings) {
  const state = await loadWebPush(env, { create: true })
  const row = await env.DB.prepare(
    'SELECT COUNT(*) AS n FROM devices WHERE web_push_endpoint IS NOT NULL',
  ).first<{ n: number }>()
  return {
    // Off by default only when an admin turned it off; a key that cannot be opened reads as off.
    enabled: state?.enabled ?? false,
    // False when the stored key cannot be opened (the encryption key changed).
    available: state !== null,
    publicKey: state?.publicKey ?? null,
    subscriptions: row?.n ?? 0,
  }
}

export async function saveWebPush(env: Bindings, raw: unknown, audit: Audit) {
  const b = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  if (typeof b.enabled !== 'boolean') throw fieldError('enabled', 'Enabled must be true or false.')
  if (!(await setWebPushEnabled(env, b.enabled))) {
    throw new ApiError(409, 'The stored web push key cannot be opened.')
  }
  await env.DB.batch([auditStatement(env.DB, audit, AdminEventType.WebPushSettingsUpdated)])
  return webPushView(env)
}
