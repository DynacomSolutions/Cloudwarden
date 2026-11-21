// Connector-facing rotation API (docs/privileged-access.md). An access connector signs in with its
// client credentials (src/pam/connector-auth.ts), polls for jobs, claims one, reads the item,
// writes the rotated item and reports the outcome. Ciphers stay client-encrypted: the server stores
// what the connector sends and never reads it. Every state change is one guarded write.
import { and, eq, sql } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { changes, createDb, type Db, runBatch, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { PushType, pushUserUpdate } from '../notifications/publish'
import { bumpOrgRevision } from '../orgs/access'
import { activeMemberIds, defer } from '../orgs/notify'
import { auditStatement } from '../pam/audit'
import { requireConnectorAuth } from '../pam/connector-auth'
import {
  AttemptStatus,
  CLAIM_LEASE_MS,
  JobStatus,
  MAX_ERROR_CODE,
  MAX_ERROR_DETAIL,
  MAX_FAILURE_REASON,
  SessionTermination,
  SyncState,
  TargetStatus,
} from '../pam/constants'
import { iso, list } from '../pam/views'
import { parseBody } from '../validation'
import { cipherJson, cipherSchema, packPayload } from '../vault/ciphers'

export const pamRotation = new Hono<Env>()

type Ctx = Context<Env>

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
const BASE = '/api/access-connectors/rotation'
pamRotation.use(BASE, requireConnectorAuth)
pamRotation.use(`${BASE}/*`, requireConnectorAuth)

const me = (c: Ctx) => c.var.connector as { uuid: string; organizationUuid: string }
const empty = (c: Ctx) => c.body(null, 200)

pamRotation.get(`${BASE}/jobs`, async (c) => {
  const { uuid, organizationUuid } = me(c)
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const now = Date.now()
  const rows = await db
    .select({ job: schema.pamRotationJobs })
    .from(schema.pamRotationJobs)
    .innerJoin(
      schema.pamConnectorAssignments,
      and(
        eq(
          schema.pamConnectorAssignments.targetSystemUuid,
          schema.pamRotationJobs.targetSystemUuid,
        ),
        eq(schema.pamConnectorAssignments.connectorUuid, uuid),
      ),
    )
    .innerJoin(
      schema.pamTargetSystems,
      eq(schema.pamTargetSystems.uuid, schema.pamRotationJobs.targetSystemUuid),
    )
    .innerJoin(
      schema.pamRotationConfigs,
      eq(schema.pamRotationConfigs.uuid, schema.pamRotationJobs.configUuid),
    )
    .where(
      and(
        eq(schema.pamRotationJobs.organizationUuid, organizationUuid),
        eq(schema.pamRotationJobs.status, JobStatus.Pending),
        sql`${schema.pamRotationJobs.nextClaimableAt} <= ${now}`,
        sql`${schema.pamRotationJobs.expiresAt} > ${now}`,
        eq(schema.pamTargetSystems.status, TargetStatus.Active),
        eq(schema.pamRotationConfigs.enabled, true),
      ),
    )
    .orderBy(schema.pamRotationJobs.nextClaimableAt)
    .limit(100)
  return c.json(
    list(
      rows.map(({ job }) => ({
        object: 'claimableRotationJob',
        jobId: job.uuid,
        source: job.source,
        nextClaimableAt: iso(job.nextClaimableAt),
        expiresAt: iso(job.expiresAt),
        targetSystemId: job.targetSystemUuid,
      })),
    ),
  )
})

pamRotation.post(`${BASE}/jobs/:id{${UUID}}/claim`, async (c) => {
  const { uuid: connectorUuid, organizationUuid } = me(c)
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const jobId = c.req.param('id')
  const [row] = await db
    .select({
      job: schema.pamRotationJobs,
      config: schema.pamRotationConfigs,
      target: schema.pamTargetSystems,
    })
    .from(schema.pamRotationJobs)
    .innerJoin(
      schema.pamRotationConfigs,
      eq(schema.pamRotationConfigs.uuid, schema.pamRotationJobs.configUuid),
    )
    .innerJoin(
      schema.pamTargetSystems,
      eq(schema.pamTargetSystems.uuid, schema.pamRotationJobs.targetSystemUuid),
    )
    .innerJoin(
      schema.pamConnectorAssignments,
      and(
        eq(
          schema.pamConnectorAssignments.targetSystemUuid,
          schema.pamRotationJobs.targetSystemUuid,
        ),
        eq(schema.pamConnectorAssignments.connectorUuid, connectorUuid),
      ),
    )
    .where(
      and(
        eq(schema.pamRotationJobs.uuid, jobId),
        eq(schema.pamRotationJobs.organizationUuid, organizationUuid),
      ),
    )
    .limit(1)
  // Never eligible: no assignment, another organisation, or a disabled target or configuration.
  if (!row || row.target.status !== TargetStatus.Active || !row.config.enabled) {
    throw new ApiError(404, 'Rotation job not found.')
  }
  const now = Date.now()
  const attemptId = crypto.randomUUID()
  const res = await runBatch(db, [
    db
      .update(schema.pamRotationJobs)
      .set({ status: JobStatus.Claimed, claimedByConnectorUuid: connectorUuid, claimedAt: now })
      .where(
        and(
          eq(schema.pamRotationJobs.uuid, jobId),
          eq(schema.pamRotationJobs.status, JobStatus.Pending),
          sql`${schema.pamRotationJobs.nextClaimableAt} <= ${now}`,
          sql`${schema.pamRotationJobs.expiresAt} > ${now}`,
        ),
      ),
    // Only the winner of the guarded update above gets an attempt.
    db.insert(schema.pamRotationAttempts).select(
      db
        .select({
          uuid: sql<string>`${attemptId}`.as('uuid'),
          jobUuid: sql<string>`${jobId}`.as('job_uuid'),
          connectorUuid: sql<string>`${connectorUuid}`.as('connector_uuid'),
          cipherUpdated: sql<number>`0`.as('cipher_updated'),
          status: sql<number>`${AttemptStatus.Executing}`.as('status'),
          failureReason: sql<string | null>`null`.as('failure_reason'),
          syncState: sql<number | null>`null`.as('sync_state'),
          sessionTermination: sql<number | null>`null`.as('session_termination'),
          createdAt: sql<number>`${now}`.as('created_at'),
          resolvedAt: sql<number | null>`null`.as('resolved_at'),
        })
        .from(schema.pamRotationJobs)
        .where(
          and(
            eq(schema.pamRotationJobs.uuid, jobId),
            eq(schema.pamRotationJobs.status, JobStatus.Claimed),
            eq(schema.pamRotationJobs.claimedByConnectorUuid, connectorUuid),
            eq(schema.pamRotationJobs.claimedAt, now),
          ),
        ),
    ),
  ])
  // Another connector won the race (or the job left the queue): claim a different job.
  if (changes(res[0]) === 0) throw new ApiError(409, 'The job was claimed by another connector.')
  await auditStatement(
    db,
    organizationUuid,
    'rotation_claimed',
    connectorUuid,
    jobId,
    attemptId,
    now,
  )
  return c.json({
    attemptId,
    jobId,
    source: row.job.source,
    targetSystemId: row.target.uuid,
    targetSystemName: row.target.name,
    targetSystemSealedData: row.target.sealedData,
    targetSystemWrappedKey: row.target.wrappedKey,
    cipherId: row.config.cipherUuid,
    rotationConfigSealedData: row.config.sealedData,
    rotationConfigWrappedKey: row.config.wrappedKey,
    executeBy: iso(now + CLAIM_LEASE_MS),
  })
})

/** The caller's own executing attempt with its claimed job, config and cipher; 404 or 409 otherwise. */
async function ownAttempt(c: Ctx, db: Db, id: string) {
  const { uuid: connectorUuid, organizationUuid } = me(c)
  const [row] = await db
    .select({
      attempt: schema.pamRotationAttempts,
      job: schema.pamRotationJobs,
      config: schema.pamRotationConfigs,
      targetStatus: schema.pamTargetSystems.status,
    })
    .from(schema.pamRotationAttempts)
    .innerJoin(
      schema.pamRotationJobs,
      eq(schema.pamRotationJobs.uuid, schema.pamRotationAttempts.jobUuid),
    )
    .innerJoin(
      schema.pamRotationConfigs,
      eq(schema.pamRotationConfigs.uuid, schema.pamRotationJobs.configUuid),
    )
    .innerJoin(
      schema.pamTargetSystems,
      eq(schema.pamTargetSystems.uuid, schema.pamRotationJobs.targetSystemUuid),
    )
    .where(
      and(
        eq(schema.pamRotationAttempts.uuid, id),
        eq(schema.pamRotationAttempts.connectorUuid, connectorUuid),
        eq(schema.pamRotationJobs.organizationUuid, organizationUuid),
      ),
    )
    .limit(1)
  if (!row) throw new ApiError(404, 'Rotation attempt not found.')
  // A claim holds while the attempt runs, the job is still claimed by this connector within its
  // lease, and neither the target system nor the configuration was disabled meanwhile.
  const holds =
    row.attempt.status === AttemptStatus.Executing &&
    row.job.status === JobStatus.Claimed &&
    row.job.claimedByConnectorUuid === connectorUuid &&
    row.job.claimedAt !== null &&
    row.job.claimedAt + CLAIM_LEASE_MS > Date.now() &&
    row.targetStatus === TargetStatus.Active &&
    row.config.enabled
  return { ...row, holds }
}

const reject = async (c: Ctx, db: Db, kind: string, jobId: string, attemptId: string) => {
  const { uuid, organizationUuid } = me(c)
  await auditStatement(db, organizationUuid, kind, uuid, jobId, attemptId)
  throw new ApiError(409, 'The claim or attempt no longer holds.')
}

pamRotation.get(`${BASE}/attempts/:id{${UUID}}/cipher`, async (c) => {
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const a = await ownAttempt(c, db, c.req.param('id'))
  if (!a.holds) throw new ApiError(409, 'The claim or attempt no longer holds.')
  const [cipher] = await db
    .select()
    .from(schema.ciphers)
    .where(eq(schema.ciphers.uuid, a.config.cipherUuid))
    .limit(1)
  if (!cipher) throw new ApiError(404, 'Item not found.')
  return c.json({
    ...cipherJson({ cipher, folderId: null }),
    object: 'cipherMini',
    organizationId: cipher.organizationUuid,
    organizationUseTotp: true,
    partialData: null,
  })
})

pamRotation.put(`${BASE}/attempts/:id{${UUID}}/cipher`, async (c) => {
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const a = await ownAttempt(c, db, c.req.param('id'))
  const { uuid: connectorUuid, organizationUuid } = me(c)
  const body = await parseBody(c, cipherSchema)
  if (!a.holds) return reject(c, db, 'write_rejected', a.job.uuid, a.attempt.uuid)
  const known = Date.parse(body.lastKnownRevisionDate ?? '')
  if (Number.isNaN(known)) {
    throw new ApiError(400, 'The request is invalid.', { lastKnownRevisionDate: ['Required.'] })
  }
  const [cipher] = await db
    .select()
    .from(schema.ciphers)
    .where(eq(schema.ciphers.uuid, a.config.cipherUuid))
    .limit(1)
  if (!cipher) throw new ApiError(404, 'Item not found.')
  if (body.type !== 1 || cipher.atype !== 1) {
    throw new ApiError(400, 'Only login items can be rotated.')
  }
  if ((body.key ?? null) !== (cipher.key ?? null)) {
    throw new ApiError(400, 'The item key must not change.')
  }
  if (body.organizationId && body.organizationId !== cipher.organizationUuid) {
    throw new ApiError(400, 'The organization must not change.')
  }
  const now = Math.max(Date.now(), cipher.updatedAt + 1)
  const holds = sql`exists (select 1 from pam_rotation_attempts a join pam_rotation_jobs j on j.uuid = a.job_uuid join pam_target_systems t on t.uuid = j.target_system_uuid join pam_rotation_configs g on g.uuid = j.config_uuid where a.uuid = ${a.attempt.uuid} and a.status = ${AttemptStatus.Executing} and j.status = ${JobStatus.Claimed} and j.claimed_by_connector_uuid = ${connectorUuid} and j.claimed_at > ${now - CLAIM_LEASE_MS} and t.status = ${TargetStatus.Active} and g.enabled = 1)`
  const res = await runBatch(db, [
    db
      .update(schema.ciphers)
      .set({
        name: body.name,
        notes: body.notes ?? null,
        fields: body.fields == null ? null : JSON.stringify(body.fields),
        data: packPayload(body, 1),
        passwordHistory: body.passwordHistory == null ? null : JSON.stringify(body.passwordHistory),
        updatedAt: now,
      })
      .where(
        and(
          eq(schema.ciphers.uuid, cipher.uuid),
          eq(schema.ciphers.updatedAt, known),
          eq(schema.ciphers.updatedAt, cipher.updatedAt),
          holds,
        ),
      ),
    db
      .update(schema.pamRotationAttempts)
      .set({ cipherUpdated: true })
      .where(
        and(
          eq(schema.pamRotationAttempts.uuid, a.attempt.uuid),
          sql`exists (select 1 from ciphers where uuid = ${cipher.uuid} and updated_at = ${now})`,
        ),
      ),
    bumpOrgRevision(db, organizationUuid, now),
  ])
  if (changes(res[0]) === 0) return reject(c, db, 'write_rejected', a.job.uuid, a.attempt.uuid)
  await auditStatement(
    db,
    organizationUuid,
    'rotation_cipher_written',
    connectorUuid,
    a.job.uuid,
    a.attempt.uuid,
    now,
  )
  defer(
    c,
    (async () => {
      const members = await activeMemberIds(createDb(c.env.DB), organizationUuid)
      await Promise.all(
        members.map((userId) =>
          pushUserUpdate(
            c.env,
            userId,
            PushType.SyncCiphers,
            { UserId: userId, Date: iso(now) },
            null,
          ),
        ),
      )
    })(),
  )
  return empty(c)
})

pamRotation.post(`${BASE}/attempts/:id{${UUID}}/success`, async (c) => {
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const a = await ownAttempt(c, db, c.req.param('id'))
  const { uuid: connectorUuid, organizationUuid } = me(c)
  const body = await parseBody(
    c,
    z.object({
      sessionTermination: z.union([
        z.literal(SessionTermination.NotRequested),
        z.literal(SessionTermination.Terminated),
        z.literal(SessionTermination.TermFailed),
      ]),
    }),
  )
  // A success needs a written cipher first (the verified-before-success backstop).
  if (!a.holds || !a.attempt.cipherUpdated) {
    return reject(c, db, 'report_rejected', a.job.uuid, a.attempt.uuid)
  }
  const now = Date.now()
  const res = await runBatch(db, [
    db
      .update(schema.pamRotationAttempts)
      .set({
        status: AttemptStatus.Rotated,
        syncState: SyncState.TargetUpdated,
        sessionTermination: body.sessionTermination,
        resolvedAt: now,
      })
      .where(
        and(
          eq(schema.pamRotationAttempts.uuid, a.attempt.uuid),
          eq(schema.pamRotationAttempts.status, AttemptStatus.Executing),
          eq(schema.pamRotationAttempts.cipherUpdated, true),
          sql`exists (select 1 from pam_rotation_jobs where uuid = ${a.job.uuid} and status = ${JobStatus.Claimed} and claimed_by_connector_uuid = ${connectorUuid})`,
        ),
      ),
    db
      .update(schema.pamRotationJobs)
      .set({ status: JobStatus.Succeeded })
      .where(
        and(
          eq(schema.pamRotationJobs.uuid, a.job.uuid),
          eq(schema.pamRotationJobs.status, JobStatus.Claimed),
          sql`exists (select 1 from pam_rotation_attempts where uuid = ${a.attempt.uuid} and status = ${AttemptStatus.Rotated})`,
        ),
      ),
    db
      .update(schema.pamRotationConfigs)
      .set({
        lastRotationAt: now,
        awaitingManualRotation: false,
        updatedAt: now,
      })
      .where(
        and(
          eq(schema.pamRotationConfigs.uuid, a.config.uuid),
          sql`exists (select 1 from pam_rotation_jobs where uuid = ${a.job.uuid} and status = ${JobStatus.Succeeded})`,
        ),
      ),
  ])
  if (changes(res[0]) === 0) return reject(c, db, 'report_rejected', a.job.uuid, a.attempt.uuid)
  await auditStatement(
    db,
    organizationUuid,
    'rotation_succeeded',
    connectorUuid,
    a.job.uuid,
    a.attempt.uuid,
    now,
  )
  return empty(c)
})

const clean = (s: string) => s.replace(/\s+/g, ' ').trim()

pamRotation.post(`${BASE}/attempts/:id{${UUID}}/failure`, async (c) => {
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const a = await ownAttempt(c, db, c.req.param('id'))
  const { uuid: connectorUuid, organizationUuid } = me(c)
  const body = await parseBody(
    c,
    z.object({
      syncState: z.union([
        z.literal(SyncState.TargetUnchanged),
        z.literal(SyncState.TargetUpdated),
        z.literal(SyncState.Indeterminate),
      ]),
      errorCode: z.string().min(1).max(MAX_ERROR_CODE),
      detail: z.string().max(MAX_ERROR_DETAIL).nullish(),
    }),
  )
  if (!a.holds) return reject(c, db, 'report_rejected', a.job.uuid, a.attempt.uuid)
  const reason = clean(body.detail ? `${body.errorCode}: ${body.detail}` : body.errorCode).slice(
    0,
    MAX_FAILURE_REASON,
  )
  const now = Date.now()
  const res = await runBatch(db, [
    db
      .update(schema.pamRotationAttempts)
      .set({
        status: AttemptStatus.Errored,
        failureReason: reason,
        syncState: body.syncState,
        resolvedAt: now,
      })
      .where(
        and(
          eq(schema.pamRotationAttempts.uuid, a.attempt.uuid),
          eq(schema.pamRotationAttempts.status, AttemptStatus.Executing),
          sql`exists (select 1 from pam_rotation_jobs where uuid = ${a.job.uuid} and status = ${JobStatus.Claimed} and claimed_by_connector_uuid = ${connectorUuid})`,
        ),
      ),
    db
      .update(schema.pamRotationJobs)
      .set({ status: JobStatus.Failed })
      .where(
        and(
          eq(schema.pamRotationJobs.uuid, a.job.uuid),
          eq(schema.pamRotationJobs.status, JobStatus.Claimed),
          sql`exists (select 1 from pam_rotation_attempts where uuid = ${a.attempt.uuid} and status = ${AttemptStatus.Errored})`,
        ),
      ),
  ])
  if (changes(res[0]) === 0) return reject(c, db, 'report_rejected', a.job.uuid, a.attempt.uuid)
  await auditStatement(
    db,
    organizationUuid,
    'rotation_failed',
    connectorUuid,
    a.job.uuid,
    a.attempt.uuid,
    now,
  )
  return empty(c)
})
