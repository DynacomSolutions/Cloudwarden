// Privileged access administration: access connectors, target systems and rotation configurations
// (docs/privileged-access.md). Owners and admins only. Sealed and wrapped values are client
// ciphertext; the server stores and returns them without reading them.
import { and, desc, eq, inArray, sql } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { sha256B64u } from '../auth/crypto'
import { changes, createDb, type Db, runBatch, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { isAdminRole, requireMember } from '../orgs/access'
import { authOnce } from '../orgs/util'
import { auditStatement } from '../pam/audit'
import {
  ConnectorStatus,
  JobStatus,
  ON_DEMAND_COOLDOWN_MS,
  RotationSource,
  TargetMethod,
  TargetStatus,
} from '../pam/constants'
import { parseCron } from '../pam/cron'
import {
  nextScheduled,
  queueJob,
  releaseByConnector,
  releaseByConnectorAndTarget,
  releaseStatements,
} from '../pam/rotation'
import {
  type ConfigRow,
  configJson,
  connectorJson,
  iso,
  jobJson,
  list,
  targetJson,
} from '../pam/views'
import { newClientSecret } from '../sm/auth'
import { parseBody } from '../validation'
import { chunk } from '../vault/ciphers'

export const pamAdmin = new Hono<Env>()

type Ctx = Context<Env>

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
const ID = `:id{${UUID}}`
const BASE = '/api/organizations/:orgId/access-connectors'

for (const path of [BASE, `${BASE}/*`]) pamAdmin.use(path, authOnce)

/** Owners and admins of the organisation; others get 404 (outsiders) or 403 (members). */
async function admin(c: Ctx, db: Db) {
  const orgUuid = c.req.param('orgId') ?? ''
  const m = await requireMember(db, c.var.user.uuid, orgUuid)
  if (!isAdminRole(m)) throw new ApiError(403, 'You do not have permission to do this.')
  return orgUuid
}

const nonEmpty = z.string().min(1).max(10_000)
const name = z.string().trim().min(1).max(100)
const notFound = (what: string) => new ApiError(404, `${what} not found.`)
const empty = (c: Ctx) => c.body(null, 200)

const lastJobsOf = async (db: Db, where: ReturnType<typeof sql>, limit = 20) => {
  const jobs = await db
    .select()
    .from(schema.pamRotationJobs)
    .where(where)
    .orderBy(desc(schema.pamRotationJobs.createdAt))
    .limit(limit)
  const attempts = jobs.length
    ? await db
        .select()
        .from(schema.pamRotationAttempts)
        .where(
          inArray(
            schema.pamRotationAttempts.jobUuid,
            jobs.map((j) => j.uuid),
          ),
        )
        .orderBy(desc(schema.pamRotationAttempts.createdAt))
    : []
  return jobs.map((j) =>
    jobJson(
      j,
      attempts.filter((a) => a.jobUuid === j.uuid),
    ),
  )
}

// ----- Target systems (literal `rotation` paths first, so they are not read as connector ids) -----

const targetOf = async (db: Db, orgUuid: string, id: string) => {
  const [t] = await db
    .select()
    .from(schema.pamTargetSystems)
    .where(
      and(
        eq(schema.pamTargetSystems.uuid, id),
        eq(schema.pamTargetSystems.organizationUuid, orgUuid),
      ),
    )
    .limit(1)
  if (!t) throw notFound('Target system')
  return t
}

pamAdmin.get(`${BASE}/rotation/target-systems`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const rows = await db
    .select()
    .from(schema.pamTargetSystems)
    .where(eq(schema.pamTargetSystems.organizationUuid, orgUuid))
    .orderBy(schema.pamTargetSystems.name)
  return c.json(list(rows.map(targetJson)))
})

pamAdmin.post(`${BASE}/rotation/target-systems`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const body = await parseBody(
    c,
    z.object({
      name,
      method: z.union([z.literal(TargetMethod.Automatic), z.literal(TargetMethod.Manual)]),
    }),
  )
  const now = Date.now()
  const row = {
    uuid: crypto.randomUUID(),
    organizationUuid: orgUuid,
    name: body.name,
    method: body.method,
    status: TargetStatus.PendingSeal,
    sealedData: null,
    wrappedKey: null,
    createdAt: now,
    updatedAt: now,
  }
  await runBatch(db, [
    db.insert(schema.pamTargetSystems).values(row),
    auditStatement(db, orgUuid, 'target_system_registered', c.var.user.uuid, row.uuid, null, now),
  ])
  return c.json(targetJson(row))
})

pamAdmin.put(`${BASE}/rotation/target-systems/${ID}`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const t = await targetOf(db, orgUuid, c.req.param('id'))
  const body = await parseBody(c, z.object({ name, sealedData: nonEmpty, wrappedKey: nonEmpty }))
  const now = Date.now()
  await runBatch(db, [
    db
      .update(schema.pamTargetSystems)
      .set({
        name: body.name,
        sealedData: body.sealedData,
        wrappedKey: body.wrappedKey,
        // Sealing completes registration; a disabled target stays disabled.
        status: t.status === TargetStatus.Disabled ? TargetStatus.Disabled : TargetStatus.Active,
        updatedAt: now,
      })
      .where(eq(schema.pamTargetSystems.uuid, t.uuid)),
    auditStatement(db, orgUuid, 'target_system_updated', c.var.user.uuid, t.uuid, null, now),
  ])
  return empty(c)
})

const setTargetStatus = (enable: boolean) => async (c: Ctx) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const t = await targetOf(db, orgUuid, c.req.param('id') ?? '')
  if (enable && !t.sealedData) {
    throw new ApiError(400, 'The target system must be sealed before it can be enabled.')
  }
  const now = Date.now()
  await runBatch(db, [
    // Disabling a target system takes its running jobs back at once.
    ...(enable ? [] : releaseStatements(db, sql`target_system_uuid = ${t.uuid}`, now)),
    db
      .update(schema.pamTargetSystems)
      .set({ status: enable ? TargetStatus.Active : TargetStatus.Disabled, updatedAt: now })
      .where(eq(schema.pamTargetSystems.uuid, t.uuid)),
    auditStatement(
      db,
      orgUuid,
      enable ? 'target_system_enabled' : 'target_system_disabled',
      c.var.user.uuid,
      t.uuid,
      null,
      now,
    ),
  ])
  return empty(c)
}
pamAdmin.post(`${BASE}/rotation/target-systems/${ID}/enable`, setTargetStatus(true))
pamAdmin.post(`${BASE}/rotation/target-systems/${ID}/disable`, setTargetStatus(false))

pamAdmin.delete(`${BASE}/rotation/target-systems/${ID}`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const t = await targetOf(db, orgUuid, c.req.param('id'))
  const [used] = await db
    .select({ id: schema.pamRotationConfigs.uuid })
    .from(schema.pamRotationConfigs)
    .where(eq(schema.pamRotationConfigs.targetSystemUuid, t.uuid))
    .limit(1)
  if (used) throw new ApiError(409, 'Rotation configurations still use this target system.')
  await runBatch(db, [
    db.delete(schema.pamTargetSystems).where(eq(schema.pamTargetSystems.uuid, t.uuid)),
    auditStatement(db, orgUuid, 'target_system_deleted', c.var.user.uuid, t.uuid),
  ])
  return empty(c)
})

// ----- Rotation configurations -----

const configOf = async (db: Db, orgUuid: string, id: string) => {
  const [row] = await db
    .select({ config: schema.pamRotationConfigs, target: schema.pamTargetSystems })
    .from(schema.pamRotationConfigs)
    .innerJoin(
      schema.pamTargetSystems,
      eq(schema.pamTargetSystems.uuid, schema.pamRotationConfigs.targetSystemUuid),
    )
    .where(
      and(
        eq(schema.pamRotationConfigs.uuid, id),
        eq(schema.pamRotationConfigs.organizationUuid, orgUuid),
      ),
    )
    .limit(1)
  if (!row) throw notFound('Rotation configuration')
  return row
}

const hasOpenJob = async (db: Db, configUuid: string) => {
  const [j] = await db
    .select({ id: schema.pamRotationJobs.uuid })
    .from(schema.pamRotationJobs)
    .where(
      and(
        eq(schema.pamRotationJobs.configUuid, configUuid),
        inArray(schema.pamRotationJobs.status, [JobStatus.Pending, JobStatus.Claimed]),
      ),
    )
    .limit(1)
  return Boolean(j)
}

async function detail(db: Db, config: ConfigRow, target: { name: string; method: number }) {
  return {
    ...configJson(config, target, await hasOpenJob(db, config.uuid)),
    jobs: await lastJobsOf(db, sql`config_uuid = ${config.uuid}`),
  }
}

const cron = z
  .string()
  .max(100)
  .nullish()
  .refine((v) => v == null || v === '' || parseCron(v) !== null, {
    message: 'Invalid cron expression.',
  })

pamAdmin.get(`${BASE}/rotation/configs`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const rows = await db
    .select({ config: schema.pamRotationConfigs, target: schema.pamTargetSystems })
    .from(schema.pamRotationConfigs)
    .innerJoin(
      schema.pamTargetSystems,
      eq(schema.pamTargetSystems.uuid, schema.pamRotationConfigs.targetSystemUuid),
    )
    .where(eq(schema.pamRotationConfigs.organizationUuid, orgUuid))
    .orderBy(desc(schema.pamRotationConfigs.createdAt))
  const open = rows.length
    ? await db
        .select({ id: schema.pamRotationJobs.configUuid })
        .from(schema.pamRotationJobs)
        .where(
          and(
            eq(schema.pamRotationJobs.organizationUuid, orgUuid),
            inArray(schema.pamRotationJobs.status, [JobStatus.Pending, JobStatus.Claimed]),
          ),
        )
    : []
  const busy = new Set(open.map((o) => o.id))
  return c.json(list(rows.map((r) => configJson(r.config, r.target, busy.has(r.config.uuid)))))
})

pamAdmin.post(`${BASE}/rotation/configs`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const body = await parseBody(
    c,
    z.object({
      cipherId: z.string().uuid(),
      targetSystemId: z.string().uuid(),
      sealedData: nonEmpty,
      wrappedKey: nonEmpty,
      scheduleCron: cron,
      rotateOnAccessEnd: z.boolean().nullish(),
    }),
  )
  const [cipher] = await db
    .select({ id: schema.ciphers.uuid, type: schema.ciphers.atype })
    .from(schema.ciphers)
    .where(
      and(eq(schema.ciphers.uuid, body.cipherId), eq(schema.ciphers.organizationUuid, orgUuid)),
    )
    .limit(1)
  if (!cipher) throw notFound('Item')
  if (cipher.type !== 1) throw new ApiError(400, 'Only login items can be rotated.')
  const target = await targetOf(db, orgUuid, body.targetSystemId)
  if (target.status === TargetStatus.PendingSeal) {
    throw new ApiError(400, 'The target system must be sealed before it can be used.')
  }
  const [taken] = await db
    .select({ id: schema.pamRotationConfigs.uuid })
    .from(schema.pamRotationConfigs)
    .where(eq(schema.pamRotationConfigs.cipherUuid, body.cipherId))
    .limit(1)
  if (taken) throw new ApiError(409, 'This item already has a rotation configuration.')
  const now = Date.now()
  const scheduleCron = body.scheduleCron || null
  const row: ConfigRow = {
    uuid: crypto.randomUUID(),
    organizationUuid: orgUuid,
    cipherUuid: body.cipherId,
    targetSystemUuid: target.uuid,
    sealedData: body.sealedData,
    wrappedKey: body.wrappedKey,
    scheduleCron,
    rotateOnAccessEnd: body.rotateOnAccessEnd ?? false,
    nextRotationAt: nextScheduled(scheduleCron, now),
    enabled: true,
    lastRotationAt: null,
    awaitingManualRotation: false,
    lastOnDemandAt: null,
    createdAt: now,
    updatedAt: now,
  }
  await runBatch(db, [
    db.insert(schema.pamRotationConfigs).values(row),
    auditStatement(db, orgUuid, 'rotation_config_created', c.var.user.uuid, row.uuid, null, now),
  ])
  return c.json(await detail(db, row, target))
})

pamAdmin.get(`${BASE}/rotation/configs/${ID}`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const { config, target } = await configOf(db, orgUuid, c.req.param('id'))
  return c.json(await detail(db, config, target))
})

pamAdmin.put(`${BASE}/rotation/configs/${ID}`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const { config, target } = await configOf(db, orgUuid, c.req.param('id'))
  const body = await parseBody(
    c,
    z.object({
      sealedData: nonEmpty,
      wrappedKey: nonEmpty,
      scheduleCron: cron,
      rotateOnAccessEnd: z.boolean().nullish(),
    }),
  )
  const now = Date.now()
  const scheduleCron = body.scheduleCron || null
  const next = { ...config, sealedData: body.sealedData, wrappedKey: body.wrappedKey, scheduleCron }
  const patch = {
    sealedData: body.sealedData,
    wrappedKey: body.wrappedKey,
    scheduleCron,
    rotateOnAccessEnd: body.rotateOnAccessEnd ?? config.rotateOnAccessEnd,
    nextRotationAt:
      scheduleCron === config.scheduleCron && config.nextRotationAt !== null
        ? config.nextRotationAt
        : config.enabled
          ? nextScheduled(scheduleCron, now)
          : null,
    updatedAt: now,
  }
  await runBatch(db, [
    db
      .update(schema.pamRotationConfigs)
      .set(patch)
      .where(eq(schema.pamRotationConfigs.uuid, config.uuid)),
    auditStatement(db, orgUuid, 'rotation_config_updated', c.var.user.uuid, config.uuid, null, now),
  ])
  return c.json(await detail(db, { ...next, ...patch }, target))
})

pamAdmin.delete(`${BASE}/rotation/configs/${ID}`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const { config } = await configOf(db, orgUuid, c.req.param('id'))
  const [claimed] = await db
    .select({ id: schema.pamRotationJobs.uuid })
    .from(schema.pamRotationJobs)
    .where(
      and(
        eq(schema.pamRotationJobs.configUuid, config.uuid),
        eq(schema.pamRotationJobs.status, JobStatus.Claimed),
      ),
    )
    .limit(1)
  if (claimed) throw new ApiError(409, 'A connector is rotating this item now.')
  await runBatch(db, [
    db.delete(schema.pamRotationConfigs).where(eq(schema.pamRotationConfigs.uuid, config.uuid)),
    auditStatement(db, orgUuid, 'rotation_config_deleted', c.var.user.uuid, config.uuid),
  ])
  return empty(c)
})

const setEnabled = (enabled: boolean) => async (c: Ctx) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const { config } = await configOf(db, orgUuid, c.req.param('id') ?? '')
  const now = Date.now()
  await runBatch(db, [
    // Pausing a configuration takes its running job back at once.
    ...(enabled ? [] : releaseStatements(db, sql`config_uuid = ${config.uuid}`, now)),
    db
      .update(schema.pamRotationConfigs)
      .set({
        enabled,
        nextRotationAt: enabled ? nextScheduled(config.scheduleCron, now) : null,
        updatedAt: now,
      })
      .where(eq(schema.pamRotationConfigs.uuid, config.uuid)),
    auditStatement(
      db,
      orgUuid,
      enabled ? 'rotation_config_resumed' : 'rotation_config_paused',
      c.var.user.uuid,
      config.uuid,
      null,
      now,
    ),
  ])
  return empty(c)
}
pamAdmin.post(`${BASE}/rotation/configs/${ID}/pause`, setEnabled(false))
pamAdmin.post(`${BASE}/rotation/configs/${ID}/resume`, setEnabled(true))

pamAdmin.post(`${BASE}/rotation/configs/${ID}/rotate`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const { config, target } = await configOf(db, orgUuid, c.req.param('id'))
  if (!config.enabled) throw new ApiError(400, 'The rotation configuration is paused.')
  if (target.status !== TargetStatus.Active)
    throw new ApiError(400, 'The target system is disabled.')
  const now = Date.now()
  // The cooldown stamp is taken first with a guarded update, so two requests cannot both pass.
  const stamped = await runBatch(db, [
    db
      .update(schema.pamRotationConfigs)
      .set({ lastOnDemandAt: now })
      .where(
        and(
          eq(schema.pamRotationConfigs.uuid, config.uuid),
          sql`(${schema.pamRotationConfigs.lastOnDemandAt} is null or ${schema.pamRotationConfigs.lastOnDemandAt} <= ${now - ON_DEMAND_COOLDOWN_MS})`,
        ),
      ),
  ])
  if (changes(stamped[0]) === 0) {
    throw new ApiError(429, 'This item was rotated on demand a moment ago. Try again shortly.')
  }
  const queued = await queueJob(db, config.uuid, RotationSource.OnDemand, now)
  if (queued.reason === 'busy') throw new ApiError(409, 'A rotation is already queued or running.')
  await auditStatement(
    db,
    orgUuid,
    'rotation_requested',
    c.var.user.uuid,
    config.uuid,
    queued.reason,
    now,
  )
  return empty(c)
})

pamAdmin.post(`${BASE}/rotation/configs/${ID}/record-manual`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const { config, target } = await configOf(db, orgUuid, c.req.param('id'))
  if (target.method !== TargetMethod.Manual) {
    throw new ApiError(400, 'Only manual target systems record a manual rotation.')
  }
  const now = Date.now()
  await runBatch(db, [
    db
      .update(schema.pamRotationConfigs)
      .set({
        awaitingManualRotation: false,
        lastRotationAt: now,
        nextRotationAt: config.enabled ? nextScheduled(config.scheduleCron, now) : null,
        updatedAt: now,
      })
      .where(eq(schema.pamRotationConfigs.uuid, config.uuid)),
    auditStatement(
      db,
      orgUuid,
      'rotation_recorded_manual',
      c.var.user.uuid,
      config.uuid,
      null,
      now,
    ),
  ])
  return empty(c)
})

// ----- Access connectors -----

const connectorOf = async (db: Db, orgUuid: string, id: string) => {
  const [row] = await db
    .select()
    .from(schema.pamAccessConnectors)
    .where(
      and(
        eq(schema.pamAccessConnectors.uuid, id),
        eq(schema.pamAccessConnectors.organizationUuid, orgUuid),
      ),
    )
    .limit(1)
  if (!row) throw notFound('Access connector')
  return row
}

const assignedTargets = async (db: Db, connectorUuids: string[]) => {
  const map = new Map<string, string[]>()
  if (connectorUuids.length === 0) return map
  for (const part of chunk(connectorUuids)) {
    const rows = await db
      .select()
      .from(schema.pamConnectorAssignments)
      .where(inArray(schema.pamConnectorAssignments.connectorUuid, part))
    for (const r of rows)
      map.set(r.connectorUuid, [...(map.get(r.connectorUuid) ?? []), r.targetSystemUuid])
  }
  return map
}

pamAdmin.get(BASE, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const rows = await db
    .select()
    .from(schema.pamAccessConnectors)
    .where(eq(schema.pamAccessConnectors.organizationUuid, orgUuid))
    .orderBy(schema.pamAccessConnectors.name)
  const assigned = await assignedTargets(
    db,
    rows.map((r) => r.uuid),
  )
  return c.json(list(rows.map((r) => connectorJson(r, assigned.get(r.uuid) ?? []))))
})

pamAdmin.post(BASE, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const body = await parseBody(c, z.object({ name, encryptedPayload: nonEmpty, key: nonEmpty }))
  const now = Date.now()
  const secret = newClientSecret(40)
  const row = {
    uuid: crypto.randomUUID(),
    organizationUuid: orgUuid,
    name: body.name,
    status: ConnectorStatus.Enabled,
    apiKeyId: crypto.randomUUID(),
    clientSecretHash: await sha256B64u(secret),
    encryptedPayload: body.encryptedPayload,
    key: body.key,
    lastHeartbeatAt: null,
    createdAt: now,
    updatedAt: now,
  }
  await runBatch(db, [
    db.insert(schema.pamAccessConnectors).values(row),
    auditStatement(db, orgUuid, 'connector_registered', c.var.user.uuid, row.uuid, null, now),
  ])
  // The secret is shown once; only its hash is stored.
  return c.json({
    object: 'registerAccessConnector',
    id: row.uuid,
    organizationId: orgUuid,
    name: row.name,
    status: row.status,
    creationDate: iso(now),
    apiKeyId: row.apiKeyId,
    clientSecret: secret,
  })
})

pamAdmin.get(`${BASE}/${ID}`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const row = await connectorOf(db, orgUuid, c.req.param('id'))
  const assigned = await assignedTargets(db, [row.uuid])
  return c.json({
    ...connectorJson(row, assigned.get(row.uuid) ?? []),
    object: 'pamAccessConnectorDetail',
    jobs: await lastJobsOf(
      db,
      sql`claimed_by_connector_uuid = ${row.uuid} or uuid in (select job_uuid from pam_rotation_attempts where connector_uuid = ${row.uuid})`,
    ),
  })
})

pamAdmin.delete(`${BASE}/${ID}`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const row = await connectorOf(db, orgUuid, c.req.param('id'))
  const now = Date.now()
  await runBatch(db, [
    ...releaseByConnector(db, row.uuid, now),
    db.delete(schema.pamAccessConnectors).where(eq(schema.pamAccessConnectors.uuid, row.uuid)),
    auditStatement(db, orgUuid, 'connector_deleted', c.var.user.uuid, row.uuid, null, now),
  ])
  return empty(c)
})

const setConnectorStatus = (enable: boolean) => async (c: Ctx) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const row = await connectorOf(db, orgUuid, c.req.param('id') ?? '')
  const now = Date.now()
  await runBatch(db, [
    // A disabled connector loses its running jobs at once, so another connector can take them.
    ...(enable ? [] : releaseByConnector(db, row.uuid, now)),
    db
      .update(schema.pamAccessConnectors)
      .set({ status: enable ? ConnectorStatus.Enabled : ConnectorStatus.Disabled, updatedAt: now })
      .where(eq(schema.pamAccessConnectors.uuid, row.uuid)),
    auditStatement(
      db,
      orgUuid,
      enable ? 'connector_enabled' : 'connector_disabled',
      c.var.user.uuid,
      row.uuid,
      null,
      now,
    ),
  ])
  return empty(c)
}
pamAdmin.post(`${BASE}/${ID}/enable`, setConnectorStatus(true))
pamAdmin.post(`${BASE}/${ID}/disable`, setConnectorStatus(false))

pamAdmin.post(`${BASE}/${ID}/assignments`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const row = await connectorOf(db, orgUuid, c.req.param('id'))
  const body = await parseBody(c, z.object({ targetSystemId: z.string().uuid() }))
  const target = await targetOf(db, orgUuid, body.targetSystemId)
  const now = Date.now()
  await runBatch(db, [
    db
      .insert(schema.pamConnectorAssignments)
      .values({ connectorUuid: row.uuid, targetSystemUuid: target.uuid, createdAt: now })
      .onConflictDoNothing(),
    auditStatement(
      db,
      orgUuid,
      'connector_target_assigned',
      c.var.user.uuid,
      row.uuid,
      target.uuid,
      now,
    ),
  ])
  return empty(c)
})

pamAdmin.delete(`${BASE}/${ID}/assignments/:targetId{${UUID}}`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const row = await connectorOf(db, orgUuid, c.req.param('id'))
  const targetUuid = c.req.param('targetId')
  const [assigned] = await db
    .select({ id: schema.pamConnectorAssignments.targetSystemUuid })
    .from(schema.pamConnectorAssignments)
    .where(
      and(
        eq(schema.pamConnectorAssignments.connectorUuid, row.uuid),
        eq(schema.pamConnectorAssignments.targetSystemUuid, targetUuid),
      ),
    )
    .limit(1)
  if (!assigned) throw notFound('Assignment')
  const now = Date.now()
  await runBatch(db, [
    db
      .delete(schema.pamConnectorAssignments)
      .where(
        and(
          eq(schema.pamConnectorAssignments.connectorUuid, row.uuid),
          eq(schema.pamConnectorAssignments.targetSystemUuid, targetUuid),
        ),
      ),
    ...releaseByConnectorAndTarget(db, row.uuid, targetUuid, now),
    auditStatement(
      db,
      orgUuid,
      'connector_target_unassigned',
      c.var.user.uuid,
      row.uuid,
      targetUuid,
      now,
    ),
  ])
  return empty(c)
})
