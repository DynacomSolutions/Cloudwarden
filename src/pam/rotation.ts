// Rotation jobs: queueing, releasing and the scheduled sweep (docs/privileged-access.md).
//
// A job moves Pending -> Claimed -> Succeeded or Failed, or ends TimedOut. Every transition is one
// guarded UPDATE (the guard names the status it expects), so two connectors, a report and a sweep
// can race and exactly one wins. The partial unique index `pam_rotation_jobs_open_unique` allows
// one open job per configuration.
import { and, eq, inArray, lte, sql } from 'drizzle-orm'
import { createDb, type Db, runBatch, schema } from '../db'
import type { Bindings } from '../env'
import {
  AttemptStatus,
  CLAIM_LEASE_MS,
  CONNECTOR_OFFLINE_AFTER_MS,
  JOB_LIFETIME_MS,
  JobStatus,
  RotationSource,
  TargetMethod,
  TargetStatus,
} from './constants'
import { nextRun } from './cron'

const SWEEP_BATCH = 100

type Source = (typeof RotationSource)[keyof typeof RotationSource]

/**
 * Queues a rotation job for a configuration. Returns the new job id, or null when the
 * configuration is disabled, its target is not usable, or an open job exists already.
 * A manual target gets an "awaiting manual rotation" flag instead of a job.
 */
export async function queueJob(
  db: Db,
  configUuid: string,
  source: Source,
  now: number,
): Promise<{ jobId: string | null; reason: 'queued' | 'manual' | 'busy' | 'unusable' }> {
  const [row] = await db
    .select({ config: schema.pamRotationConfigs, target: schema.pamTargetSystems })
    .from(schema.pamRotationConfigs)
    .innerJoin(
      schema.pamTargetSystems,
      eq(schema.pamTargetSystems.uuid, schema.pamRotationConfigs.targetSystemUuid),
    )
    .where(eq(schema.pamRotationConfigs.uuid, configUuid))
    .limit(1)
  if (!row?.config.enabled || row.target.status !== TargetStatus.Active) {
    return { jobId: null, reason: 'unusable' }
  }
  if (row.target.method === TargetMethod.Manual) {
    await db
      .update(schema.pamRotationConfigs)
      .set({ awaitingManualRotation: true, updatedAt: now })
      .where(eq(schema.pamRotationConfigs.uuid, configUuid))
    return { jobId: null, reason: 'manual' }
  }
  const uuid = crypto.randomUUID()
  const inserted = await db
    .insert(schema.pamRotationJobs)
    .values({
      uuid,
      configUuid,
      organizationUuid: row.config.organizationUuid,
      targetSystemUuid: row.target.uuid,
      source,
      status: JobStatus.Pending,
      nextClaimableAt: now,
      expiresAt: now + JOB_LIFETIME_MS,
      createdAt: now,
    })
    .onConflictDoNothing()
    .returning({ id: schema.pamRotationJobs.uuid })
  return inserted.length > 0 ? { jobId: uuid, reason: 'queued' } : { jobId: null, reason: 'busy' }
}

/**
 * Statements that put the claimed jobs matching `jobFilter` back to Pending and mark their open
 * attempts Abandoned. Used when a connector is disabled, deleted or loses a target.
 */
export function releaseStatements(db: Db, jobFilter: ReturnType<typeof sql>, now: number) {
  return [
    db
      .update(schema.pamRotationAttempts)
      .set({ status: AttemptStatus.Abandoned, resolvedAt: now })
      .where(
        and(
          eq(schema.pamRotationAttempts.status, AttemptStatus.Executing),
          sql`${schema.pamRotationAttempts.jobUuid} in (select uuid from pam_rotation_jobs where status = ${JobStatus.Claimed} and ${jobFilter})`,
        ),
      ),
    db
      .update(schema.pamRotationJobs)
      .set({ status: JobStatus.Pending, claimedByConnectorUuid: null, claimedAt: null })
      .where(sql`${schema.pamRotationJobs.status} = ${JobStatus.Claimed} and ${jobFilter}`),
  ]
}

export const releaseByConnector = (db: Db, connectorUuid: string, now: number) =>
  releaseStatements(db, sql`claimed_by_connector_uuid = ${connectorUuid}`, now)

export const releaseByConnectorAndTarget = (
  db: Db,
  connectorUuid: string,
  targetUuid: string,
  now: number,
) =>
  releaseStatements(
    db,
    sql`claimed_by_connector_uuid = ${connectorUuid} and target_system_uuid = ${targetUuid}`,
    now,
  )

/** The next scheduled time of a configuration, or null when it has no schedule. */
export const nextScheduled = (cron: string | null, after: number): number | null =>
  cron ? nextRun(cron, after) : null

/**
 * One pass of the rotation sweep: releases abandoned claims, times out old jobs, and queues the
 * scheduled rotations that are due. Idempotent and safe to run twice at once.
 */
export async function sweepRotation(env: Bindings, now = Date.now()): Promise<void> {
  const db = createDb(env.DB)

  // 1. Claims whose lease ended while the connector went quiet go back to the queue.
  const stale = await db
    .select({ id: schema.pamRotationJobs.uuid })
    .from(schema.pamRotationJobs)
    .leftJoin(
      schema.pamAccessConnectors,
      eq(schema.pamAccessConnectors.uuid, schema.pamRotationJobs.claimedByConnectorUuid),
    )
    .where(
      and(
        eq(schema.pamRotationJobs.status, JobStatus.Claimed),
        sql`${schema.pamRotationJobs.expiresAt} > ${now}`,
        sql`(${schema.pamRotationJobs.claimedAt} is null or ${schema.pamRotationJobs.claimedAt} <= ${now - CLAIM_LEASE_MS})`,
        sql`(${schema.pamAccessConnectors.uuid} is null or ${schema.pamAccessConnectors.status} != 0 or ${schema.pamAccessConnectors.lastHeartbeatAt} is null or ${schema.pamAccessConnectors.lastHeartbeatAt} <= ${now - CONNECTOR_OFFLINE_AFTER_MS})`,
      ),
    )
    .limit(SWEEP_BATCH)
  for (const { id } of stale) {
    await runBatch(db, releaseStatements(db, sql`uuid = ${id}`, now))
  }

  // 2. Jobs past their lifetime time out; their open attempts are abandoned.
  const expired = await db
    .select({ id: schema.pamRotationJobs.uuid })
    .from(schema.pamRotationJobs)
    .where(
      and(
        inArray(schema.pamRotationJobs.status, [JobStatus.Pending, JobStatus.Claimed]),
        lte(schema.pamRotationJobs.expiresAt, now),
      ),
    )
    .limit(SWEEP_BATCH)
  for (const { id } of expired) {
    await runBatch(db, [
      db
        .update(schema.pamRotationAttempts)
        .set({ status: AttemptStatus.Abandoned, resolvedAt: now })
        .where(
          and(
            eq(schema.pamRotationAttempts.jobUuid, id),
            eq(schema.pamRotationAttempts.status, AttemptStatus.Executing),
          ),
        ),
      db
        .update(schema.pamRotationJobs)
        .set({ status: JobStatus.TimedOut })
        .where(
          and(
            eq(schema.pamRotationJobs.uuid, id),
            inArray(schema.pamRotationJobs.status, [JobStatus.Pending, JobStatus.Claimed]),
          ),
        ),
    ])
  }

  // 3. Scheduled rotations that are due.
  const due = await db
    .select()
    .from(schema.pamRotationConfigs)
    .where(
      and(
        eq(schema.pamRotationConfigs.enabled, true),
        sql`${schema.pamRotationConfigs.nextRotationAt} is not null and ${schema.pamRotationConfigs.nextRotationAt} <= ${now}`,
      ),
    )
    .limit(SWEEP_BATCH)
  for (const config of due) {
    await queueJob(db, config.uuid, RotationSource.Scheduled, now)
    // Move the schedule on, so a busy or unusable target is not retried every minute.
    await db
      .update(schema.pamRotationConfigs)
      .set({ nextRotationAt: nextScheduled(config.scheduleCron, now), updatedAt: now })
      .where(
        and(
          eq(schema.pamRotationConfigs.uuid, config.uuid),
          eq(schema.pamRotationConfigs.nextRotationAt, config.nextRotationAt as number),
        ),
      )
  }
}
