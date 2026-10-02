// Event delivery (TASKS #264). Every minute the cron reads, per enabled integration, the
// organisation's events written after its cursor (the events table `rowid`, so delivery follows
// insertion order) and sends them. Success moves the cursor; failure keeps it, records the error
// and backs off exponentially (30 s doubling to 6 h), so every event is delivered at least once,
// in order, once the destination recovers. A short lease stops overlapping runs sending twice.
import { and, eq, lte, sql } from 'drizzle-orm'
import { createDb, type Db, schema } from '../db'
import type { Bindings } from '../env'
import { errorKind, log } from '../log'
import { eventJson } from '../orgs/events'
import { unseal } from '../orgs/sealed'
import {
  DESTINATIONS,
  DeliveryError,
  type EventPayload,
  type Fetcher,
  type IntegrationType,
} from './destinations'

export const DELIVERY_CRON = '* * * * *'
const LEASE_MS = 5 * 60_000
const MAX_INTEGRATIONS_PER_RUN = 50
const MAX_BATCHES_PER_RUN = 5
const BACKOFF_BASE_MS = 30_000
const BACKOFF_MAX_MS = 6 * 3600_000

export type IntegrationRow = typeof schema.orgIntegrations.$inferSelect
type EventRow = typeof schema.events.$inferSelect

export const secretsPurpose = (uuid: string) => `integration:${uuid}`

export const backoffMs = (failures: number) =>
  Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** Math.max(0, failures - 1))

export const eventPayload = (e: EventRow): EventPayload => ({ id: e.uuid, ...eventJson(e) })

/** The highest event `rowid` of the organisation: where a new integration starts. */
export async function latestEventCursor(db: Db, orgUuid: string): Promise<number> {
  const [row] = await db.all<{ c: number | null }>(
    sql`select max(rowid) as c from events where organization_uuid = ${orgUuid}`,
  )
  return row?.c ?? 0
}

async function eventsAfter(db: Db, orgUuid: string, cursor: number, limit: number) {
  return db.all<EventRow & { rid: number }>(
    sql`select rowid as rid, uuid, event_type as eventType, user_uuid as userUuid,
      organization_uuid as organizationUuid, cipher_uuid as cipherUuid,
      collection_uuid as collectionUuid, group_uuid as groupUuid, policy_uuid as policyUuid,
      organization_user_uuid as organizationUserUuid, acting_user_uuid as actingUserUuid,
      secret_uuid as secretUuid, project_uuid as projectUuid,
      service_account_uuid as serviceAccountUuid,
      granted_service_account_uuid as grantedServiceAccountUuid, system_user as systemUser,
      device_type as deviceType, ip_address as ipAddress, event_date as eventDate
      from events where organization_uuid = ${orgUuid} and rowid > ${cursor}
      order by rowid limit ${limit}`,
  )
}

export async function openSecrets(env: Bindings, row: IntegrationRow) {
  return JSON.parse(await unseal(env, secretsPurpose(row.uuid), row.sealedSecrets)) as Record<
    string,
    unknown
  >
}

/** Sends events through one integration. Throws `DeliveryError` (or a fetch error) on failure. */
export async function sendEvents(
  env: Bindings,
  row: IntegrationRow,
  events: EventPayload[],
  fetcher: Fetcher,
  now = Date.now(),
) {
  const dest = DESTINATIONS[row.atype as IntegrationType]
  if (!dest) throw new DeliveryError(`Unknown integration type ${row.atype}.`)
  const cfg = dest.config.parse(JSON.parse(row.config))
  const secrets = dest.secrets.parse(await openSecrets(env, row))
  await dest.send(fetcher, cfg, secrets, events, { host: new URL(env.DOMAIN).hostname, now })
}

const describe = (err: unknown) =>
  err instanceof DeliveryError
    ? err.message
    : err instanceof TypeError
      ? 'The destination could not be reached.'
      : 'Delivery failed.'

/** Delivers pending events for one integration; returns the number of events sent. */
async function deliverOne(
  env: Bindings,
  db: Db,
  row: IntegrationRow,
  fetcher: Fetcher,
  now: number,
): Promise<number> {
  // Take the lease; a concurrent run that read the same row loses here.
  const lease = await db
    .update(schema.orgIntegrations)
    .set({ nextAttemptAt: now + LEASE_MS })
    .where(
      and(
        eq(schema.orgIntegrations.uuid, row.uuid),
        eq(schema.orgIntegrations.nextAttemptAt, row.nextAttemptAt),
      ),
    )
  if (lease.meta.changes === 0) return 0

  const dest = DESTINATIONS[row.atype as IntegrationType]
  const wanted = row.eventTypes ? new Set(JSON.parse(row.eventTypes) as number[]) : null
  let cursor = row.cursor
  let sent = 0
  try {
    for (let i = 0; i < MAX_BATCHES_PER_RUN; i++) {
      const batch = await eventsAfter(db, row.organizationUuid, cursor, dest?.batchSize ?? 100)
      if (batch.length === 0) break
      const chosen = batch.filter((e) => !wanted || wanted.has(e.eventType)).map(eventPayload)
      if (chosen.length) await sendEvents(env, row, chosen, fetcher, now)
      cursor = (batch[batch.length - 1] as { rid: number }).rid
      sent += chosen.length
      await db
        .update(schema.orgIntegrations)
        .set({ cursor })
        .where(eq(schema.orgIntegrations.uuid, row.uuid))
    }
    await db
      .update(schema.orgIntegrations)
      .set({
        failureCount: 0,
        nextAttemptAt: 0,
        lastError: null,
        ...(sent > 0 ? { lastSuccessAt: now } : {}),
      })
      .where(eq(schema.orgIntegrations.uuid, row.uuid))
  } catch (err) {
    const failures = row.failureCount + 1
    await db
      .update(schema.orgIntegrations)
      .set({
        failureCount: failures,
        nextAttemptAt: now + backoffMs(failures),
        lastError: describe(err),
      })
      .where(eq(schema.orgIntegrations.uuid, row.uuid))
    log(
      'warn',
      'integration.delivery_failed',
      { integration: row.uuid, type: row.atype, failures, errorKind: errorKind(err) },
      env,
    )
  }
  return sent
}

/** Cron entry: delivers pending events for every due integration. */
export async function deliverIntegrations(
  env: Bindings,
  options: { fetcher?: Fetcher; now?: number } = {},
): Promise<number> {
  const fetcher = options.fetcher ?? ((input, init) => fetch(input, init))
  const now = options.now ?? Date.now()
  const db = createDb(env.DB)
  const due = await db
    .select()
    .from(schema.orgIntegrations)
    .where(
      and(eq(schema.orgIntegrations.enabled, true), lte(schema.orgIntegrations.nextAttemptAt, now)),
    )
    .orderBy(schema.orgIntegrations.nextAttemptAt)
    .limit(MAX_INTEGRATIONS_PER_RUN)
  let total = 0
  for (const row of due) total += await deliverOne(env, db, row, fetcher, now)
  return total
}
