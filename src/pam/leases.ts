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
import { PushType, pushUserUpdate } from '../notifications/publish'
import { chunk } from '../vault/ciphers'
import {
  APPROVAL_TTL_MS,
  ApprovalMode,
  LeaseStatus,
  RequestStatus,
  RotationSource,
} from './constants'
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

/**
 * SQL: no other lease on the item overlaps the window `[from, to)` (the single-active-lease guard).
 * A lease counts only between its `notBefore` and `notAfter`, so a lease that starts after the new
 * one ends does not block it. Without `to`, the guard asks about the instant `from`.
 */
export const noLiveLease = (cipherUuid: string, from: number, to = from + 1) =>
  sql`not exists (select 1 from pam_leases where cipher_uuid = ${cipherUuid} and status = ${LeaseStatus.Active} and not_after > ${from} and not_before < ${to})`

/**
 * SQL, for a statement on `pam_leases`: no other lease on the item overlaps the stretch that an
 * extension of `extendMs` adds to this lease. Extensions need it under a single-lease rule, or an
 * extension would cover a lease that another member scheduled right after this one.
 */
export const noExtensionOverlap = (extendMs: number, lease = sql`pam_leases`) =>
  sql`not exists (select 1 from pam_leases o where o.cipher_uuid = ${lease}.cipher_uuid and o.uuid != ${lease}.uuid and o.status = ${LeaseStatus.Active} and o.not_after > ${lease}.not_after and o.not_before < ${lease}.not_after + ${extendMs})`

/** SQL: the requester holds no lease on the item that has not ended yet, scheduled ones included. */
export const noOpenLeaseOf = (cipherUuid: string, requesterUuid: string, now: number) =>
  sql`not exists (select 1 from pam_leases where cipher_uuid = ${cipherUuid} and requester_uuid = ${requesterUuid} and status = ${LeaseStatus.Active} and not_after > ${now})`

/** Expiry of an approval: a day, or until the window ends. A window that starts later gets its own day. */
export const approvalExpiry = (windowStart: number | null, windowEnd: number | null, now: number) =>
  Math.min(
    windowEnd ?? Number.POSITIVE_INFINITY,
    Math.max(windowStart ?? now, now) + APPROVAL_TTL_MS,
  )

/** Statement: moves the member's revision date forward, so their clients sync after a lease change. */
export const bumpMemberRevision = (db: Db, userUuid: string, now: number) =>
  db
    .update(schema.users)
    .set({ updatedAt: sql`max(${schema.users.updatedAt} + 1, ${now})` })
    .where(eq(schema.users.uuid, userUuid))

/** Tells the member's devices to sync: a lease changes which items they receive in full. */
export const pushLeaseChange = (env: Bindings, userUuid: string, now: number) =>
  pushUserUpdate(
    env,
    userUuid,
    PushType.SyncVault,
    { UserId: userUuid, Date: new Date(now).toISOString() },
    null,
  )

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
  // At most ID_CHUNK ids per statement (D1 allows 100 bound parameters).
  const [decisions, leases, people] = await Promise.all([
    Promise.all(
      chunk(ids).map((part) =>
        db
          .select()
          .from(schema.pamAccessDecisions)
          .where(inArray(schema.pamAccessDecisions.requestUuid, part)),
      ),
    ).then((r) => r.flat()),
    Promise.all(
      chunk(ids).map((part) =>
        db.select().from(schema.pamLeases).where(inArray(schema.pamLeases.requestUuid, part)),
      ),
    ).then((r) => r.flat()),
    Promise.all(
      chunk(users).map((part) =>
        db
          .select({ id: schema.users.uuid, name: schema.users.name, email: schema.users.email })
          .from(schema.users)
          .where(inArray(schema.users.uuid, part)),
      ),
    ).then((r) => r.flat()),
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

/** A windowed lease that started within this time before a sweep still gets its sync push (once). */
const START_LOOKBACK_MS = 10 * 60_000

/**
 * One pass of the access sweep: expires requests nobody decided or activated in time, marks leases
 * whose time ran out as Expired, queues access-end rotations, and tells the members whose windowed
 * lease has just started to sync (a lease that starts later changes nothing at the moment of
 * approval). Idempotent: the start push is recorded on the lease, so it happens once.
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
    if (res.length > 0) {
      await rotateAfterAccess(db, lease, now)
      // The item goes back to its reduced row at the member's next sync.
      await bumpMemberRevision(db, lease.requesterUuid, now)
      await pushLeaseChange(env, lease.requesterUuid, now).catch(() => undefined)
    }
  }
  const started = await db
    .select({ uuid: schema.pamLeases.uuid, userUuid: schema.pamLeases.requesterUuid })
    .from(schema.pamLeases)
    .where(
      and(
        eq(schema.pamLeases.status, LeaseStatus.Active),
        sql`${schema.pamLeases.notBefore} <= ${now} and ${schema.pamLeases.notBefore} > ${now - START_LOOKBACK_MS}`,
        // Only a lease scheduled for later starts at a time of its own.
        sql`${schema.pamLeases.notBefore} > ${schema.pamLeases.createdAt}`,
        sql`${schema.pamLeases.notAfter} > ${now}`,
        sql`${schema.pamLeases.startNotifiedAt} is null`,
      ),
    )
    .limit(200)
  const told = new Set<string>()
  for (const { uuid, userUuid } of started) {
    // Record the push first: a sweep that runs twice at once still pushes once.
    const claimed = await db
      .update(schema.pamLeases)
      .set({ startNotifiedAt: now })
      .where(and(eq(schema.pamLeases.uuid, uuid), sql`${schema.pamLeases.startNotifiedAt} is null`))
      .returning({ id: schema.pamLeases.uuid })
    if (claimed.length === 0 || told.has(userUuid)) continue
    told.add(userUuid)
    await bumpMemberRevision(db, userUuid, now)
    await pushLeaseChange(env, userUuid, now).catch(() => undefined)
  }
}
