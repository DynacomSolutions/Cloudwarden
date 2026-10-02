import { eq } from 'drizzle-orm'
import { createDb, schema } from '../db'
import type { Bindings } from '../env'
import { errorKind, log } from '../log'
import { seal, unseal } from '../orgs/sealed'

/**
 * Push relay settings kept in the database by an instance admin (TASKS #277). The installation key
 * is sealed under DATA_ENCRYPTION_KEY (or the JWT_SECRET derived fallback) and is never returned by
 * any API. Worker secrets override these values (see `resolveRelay` in relay.ts).
 */

export type Region = 'us' | 'eu' | 'custom'

export const REGION_URIS = {
  us: { relayUri: 'https://push.bitwarden.com', identityUri: 'https://identity.bitwarden.com' },
  eu: { relayUri: 'https://push.bitwarden.eu', identityUri: 'https://identity.bitwarden.eu' },
} as const

export const SETTINGS_KEY = 'push'
const KEY_PURPOSE = 'instance-setting:push:installation-key'
const CACHE_MS = 10_000

export interface StoredPush {
  installationId: string
  installationKey: string
  region: Region
  relayUri: string
  identityUri: string
  updatedAt: number
}

/** Validates an https base URI for a custom relay. Returns the normalised URI or null. */
export function validateRelayUri(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length > 300) return null
  let url: URL
  try {
    url = new URL(raw.trim())
  } catch {
    return null
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    return null
  }
  const host = url.hostname
  if (!host.includes('.') || host === 'localhost' || /^[\d.]+$/.test(host) || host.includes(':')) {
    return null
  }
  return url.toString().replace(/\/+$/, '')
}

/** The relay and identity URIs for a region. Custom needs both URIs; null when they are invalid. */
export function deriveUris(
  region: Region,
  custom?: { relayUri?: unknown; identityUri?: unknown },
): { relayUri: string; identityUri: string } | null {
  if (region !== 'custom') return { ...REGION_URIS[region] }
  const relayUri = validateRelayUri(custom?.relayUri)
  const identityUri = validateRelayUri(custom?.identityUri)
  return relayUri && identityUri ? { relayUri, identityUri } : null
}

// Short lived per isolate cache. Writes invalidate it in the isolate that handled them; other
// isolates pick the change up when their entry expires.
let cache: { at: number; value: StoredPush | null } | null = null
export const invalidatePushConfig = () => {
  cache = null
}

/** The stored settings, or null when none are saved (or the key cannot be opened). */
export async function loadStoredPush(env: Bindings): Promise<StoredPush | null> {
  if (cache && Date.now() - cache.at < CACHE_MS) return cache.value
  let value: StoredPush | null = null
  try {
    const [row] = await createDb(env.DB)
      .select()
      .from(schema.instanceSettings)
      .where(eq(schema.instanceSettings.key, SETTINGS_KEY))
      .limit(1)
    if (row?.sealedSecrets) {
      const c = JSON.parse(row.config) as Partial<StoredPush>
      if (c.installationId && c.region && c.relayUri && c.identityUri) {
        value = {
          installationId: c.installationId,
          installationKey: await unseal(env, KEY_PURPOSE, row.sealedSecrets),
          region: c.region,
          relayUri: c.relayUri,
          identityUri: c.identityUri,
          updatedAt: row.updatedAt,
        }
      }
    }
  } catch (err) {
    log('warn', 'push.settings_read_failed', { errorKind: errorKind(err) }, env)
  }
  cache = { at: Date.now(), value }
  return value
}

export interface PushSettingsWrite {
  installationId: string
  /** Null keeps the stored key. */
  installationKey: string | null
  region: Region
  relayUri: string
  identityUri: string
}

/** Statement-level helpers so the caller can add the audit insert to the same batch. */
export async function savePushStatements(
  env: Bindings,
  input: PushSettingsWrite,
  actor: string | null,
  now: number,
): Promise<D1PreparedStatement> {
  const sealed = input.installationKey
    ? await seal(env, KEY_PURPOSE, input.installationKey)
    : await readSealed(env)
  if (!sealed) throw new Error('missing key')
  const config = JSON.stringify({
    installationId: input.installationId,
    region: input.region,
    relayUri: input.relayUri,
    identityUri: input.identityUri,
  })
  return env.DB.prepare(
    `INSERT INTO instance_settings (key, config, sealed_secrets, updated_at, updated_by)
     VALUES (?1, ?2, ?3, ?4, ?5)
     ON CONFLICT (key) DO UPDATE SET config = ?2, sealed_secrets = ?3, updated_at = ?4, updated_by = ?5`,
  ).bind(SETTINGS_KEY, config, sealed, now, actor)
}

export const deletePushStatement = (env: Bindings) =>
  env.DB.prepare('DELETE FROM instance_settings WHERE key = ?1').bind(SETTINGS_KEY)

async function readSealed(env: Bindings): Promise<string | null> {
  const row = await env.DB.prepare('SELECT sealed_secrets FROM instance_settings WHERE key = ?1')
    .bind(SETTINGS_KEY)
    .first<{ sealed_secrets: string | null }>()
  return row?.sealed_secrets ?? null
}
