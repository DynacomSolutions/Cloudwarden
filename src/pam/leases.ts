// Access requests and leases: the state machine (docs/privileged-access.md).
//
//   request:  Pending -> Approved | Denied | Cancelled | Expired;  Approved -> Cancelled | Expired
//   lease:    Active -> Expired (time) | Revoked (by an approver) | Cancelled (by the requester)
//
// Every transition is one guarded write naming the state it expects, and the lease insert carries
// the single-active-lease guard in its own statement, so two activations or two approvals race to
// one winner. D1 runs a batch as one transaction.
import { and, eq, inArray, sql } from 'drizzle-orm'
import { createDb, type Db, schema } from '../db'
import type { Bindings } from '../env'
import { ApprovalMode, LeaseStatus, RequestStatus, RotationSource } from './constants'
import { queueJob } from './rotation'
import { iso } from './views'

export type RuleRow = typeof schema.pamAccessRules.$inferSelect
export type RequestRow = typeof schema.pamAccessRequests.$inferSelect
export type LeaseRow = typeof schema.pamLeases.$inferSelect
export type DecisionRow = typeof schema.pamAccessDecisions.$inferSelect

/** The approval mode a rule asks for: `conditions.approvalMode`, defaulting to human approval. */
export function approvalModeOf(rule: Pick<RuleRow, 'conditions'>): number {
  try {
    const c = JSON.parse(rule.conditions ?? 'null') as { approvalMode?: unknown } | null
    const m = c?.approvalMode
    if (m === ApprovalMode.Automatic || m === 'Automatic') return ApprovalMode.Automatic
  } catch {
    // Unreadable conditions fall back to the safe default.
  }
  return ApprovalMode.Human
}

/** Lease status as shown: a stored Active lease past `notAfter` reads as Expired. */
export const leaseStatusAt = (l: Pick<LeaseRow, 'status' | 'notAfter'>, now: number) =>
  l.status === LeaseStatus.Active && l.notAfter <= now ? LeaseStatus.Expired : l.status

/** SQL: no other live lease exists on the item (the single-active-lease guard). */
export const noLiveLease = (cipherUuid: string, now: number) =>
  sql`not exists (select 1 from pam_leases where cipher_uuid = ${cipherUuid} and status = ${LeaseStatus.Active} and not_after > ${now})`

export function leaseJson(l: LeaseRow, now: number) {
  return {
    object: 'accessLease',
    id: l.uuid,
    requestId: l.requestUuid,
    cipherId: l.cipherUuid,
    collectionId: l.collectionUuid,
    // Leases do not record their rule.
    ruleId: null,
    organizationId: l.organizationUuid,
    requesterId: l.requesterUuid,
    status: leaseStatusAt(l, now),
    notBefore: iso(l.notBefore),
    notAfter: iso(l.notAfter),
    revokedAt: iso(l.revokedAt),
    revokedByUserId: l.revokedByUserUuid,
    revocationReason: l.revocationReason,
  }
}

export interface RequestContext {
  decisions: DecisionRow[]
  lease: LeaseRow | undefined
  requester: { name: string; email: string } | undefined
}

/** Request status as shown: pending or approved requests past their deadline read as Expired. */
export const requestStatusAt = (
  r: Pick<RequestRow, 'status' | 'expiresAt' | 'extensionOfLeaseUuid'>,
  hasLease: boolean,
  now: number,
) => {
  if (r.expiresAt > now) return r.status
  if (r.status === RequestStatus.Pending) return RequestStatus.Expired
  // An approved request that produced a lease, or an applied extension, stays approved.
  if (r.status === RequestStatus.Approved && !hasLease && r.extensionOfLeaseUuid == null) {
    return RequestStatus.Expired
  }
  return r.status
}

export function requestJson(r: RequestRow, ctx: RequestContext, now: number) {
  const first = r.windowStart ?? r.submittedAt
  return {
    object: 'accessRequestDetails',
    id: r.uuid,
    cipherId: r.cipherUuid,
    collectionId: r.collectionUuid,
    organizationId: r.organizationUuid,
    requesterId: r.requesterUuid,
    ruleId: r.ruleUuid,
    status: requestStatusAt(r, ctx.lease !== undefined, now),
    leaseNotBefore: iso(r.windowStart ?? (ctx.lease ? ctx.lease.notBefore : null)),
    leaseNotAfter: iso(
      r.windowEnd ?? (ctx.lease ? ctx.lease.notAfter : first + r.durationSeconds * 1000),
    ),
    reason: r.reason,
    submittedAt: iso(r.submittedAt),
    resolvedAt: iso(r.resolvedAt),
    decisions: ctx.decisions.map((d) => ({
      deciderKind: d.deciderKind,
      id: d.deciderUserUuid,
      name: null,
      email: null,
      comment: d.comment,
      verdict: d.verdict,
      decidedAt: iso(d.decidedAt),
    })),
    producedLeaseId: ctx.lease?.uuid ?? null,
    producedLeaseStatus: ctx.lease ? leaseStatusAt(ctx.lease, now) : null,
    producedLeaseNotAfter: iso(ctx.lease?.notAfter),
    extensionOfLeaseId: r.extensionOfLeaseUuid,
    requesterName: ctx.requester?.name ?? null,
    requesterEmail: ctx.requester?.email ?? null,
  }
}

/** Loads decisions, produced leases and requester names for many requests in a few queries. */
export async function requestViews(db: Db, rows: RequestRow[], now = Date.now()) {
  if (rows.length === 0) return []
  const ids = rows.map((r) => r.uuid)
  const users = [...new Set(rows.map((r) => r.requesterUuid))]
  const [decisions, leases, people] = await Promise.all([
    db
      .select()
      .from(schema.pamAccessDecisions)
      .where(inArray(schema.pamAccessDecisions.requestUuid, ids)),
    db.select().from(schema.pamLeases).where(inArray(schema.pamLeases.requestUuid, ids)),
    db
      .select({ id: schema.users.uuid, name: schema.users.name, email: schema.users.email })
      .from(schema.users)
      .where(inArray(schema.users.uuid, users)),
  ])
  return rows.map((r) =>
    requestJson(
      r,
      {
        decisions: decisions.filter((d) => d.requestUuid === r.uuid),
        lease: leases.find((l) => l.requestUuid === r.uuid),
        requester: people.find((p) => p.id === r.requesterUuid),
      },
      now,
    ),
  )
}

export const requestView = async (db: Db, row: RequestRow, now = Date.now()) =>
  (await requestViews(db, [row], now))[0]

/**
 * After a lease ended for any reason, queue an access-end rotation when the item has a rotation
 * configuration that asks for one. Safe to call twice: the partial unique index keeps one open job.
 */
export async function rotateAfterAccess(db: Db, lease: Pick<LeaseRow, 'cipherUuid'>, now: number) {
  const [config] = await db
    .select({ id: schema.pamRotationConfigs.uuid, on: schema.pamRotationConfigs.rotateOnAccessEnd })
    .from(schema.pamRotationConfigs)
    .where(eq(schema.pamRotationConfigs.cipherUuid, lease.cipherUuid))
    .limit(1)
  if (config?.on) await queueJob(db, config.id, RotationSource.AccessEnd, now)
}

/**
 * One pass of the access sweep: expires requests nobody decided or activated in time, marks leases
 * whose time ran out as Expired, and queues access-end rotations. Idempotent.
 */
export async function sweepAccess(env: Bindings, now = Date.now()): Promise<void> {
  const db = createDb(env.DB)
  await db
    .update(schema.pamAccessRequests)
    .set({ status: RequestStatus.Expired, resolvedAt: now, updatedAt: now })
    .where(
      and(
        inArray(schema.pamAccessRequests.status, [RequestStatus.Pending, RequestStatus.Approved]),
        sql`${schema.pamAccessRequests.expiresAt} <= ${now}`,
        // An approved request that produced a lease, or an applied extension, is finished business.
        sql`not exists (select 1 from pam_leases where request_uuid = pam_access_requests.uuid)`,
        sql`not (${schema.pamAccessRequests.status} = ${RequestStatus.Approved} and ${schema.pamAccessRequests.extensionOfLeaseUuid} is not null)`,
      ),
    )
  const ended = await db
    .select()
    .from(schema.pamLeases)
    .where(
      and(
        eq(schema.pamLeases.status, LeaseStatus.Active),
        sql`${schema.pamLeases.notAfter} <= ${now}`,
      ),
    )
    .limit(200)
  for (const lease of ended) {
    const res = await db
      .update(schema.pamLeases)
      .set({ status: LeaseStatus.Expired })
      .where(
        and(
          eq(schema.pamLeases.uuid, lease.uuid),
          eq(schema.pamLeases.status, LeaseStatus.Active),
          sql`${schema.pamLeases.notAfter} <= ${now}`,
        ),
      )
      .returning({ id: schema.pamLeases.uuid })
    if (res.length > 0) await rotateAfterAccess(db, lease, now)
  }
}
