// Access requests and leases (docs/privileged-access.md): a member asks for time-boxed access to an
// item in a collection that an access rule covers; an approver decides (or the rule approves
// automatically); the member activates the approval into a lease; leases can be extended and revoked.
// The state machine is in src/pam/leases.ts. Items stay client-encrypted: this module never reads them.
import { and, desc, eq, inArray, or, type SQL, sql } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { changes, createDb, type Db, runBatch, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { collectionAccess, isAdminRole, loadUserAccess, type UserAccess } from '../orgs/access'
import { accessToCipher, linkedCollections } from '../orgs/ciphers'
import { authOnce } from '../orgs/util'
import { auditStatement } from '../pam/audit'
import {
  APPROVAL_TTL_MS,
  ApprovalMode,
  DeciderKind,
  LeaseStatus,
  LIST_LIMIT,
  MAX_LEASE_SECONDS,
  PENDING_TTL_MS,
  RequestStatus,
  Verdict,
} from '../pam/constants'
import {
  approvalModeOf,
  type LeaseRow,
  leaseJson,
  noLiveLease,
  type RequestRow,
  requestView,
  requestViews,
  rotateAfterAccess,
} from '../pam/leases'
import { iso, list } from '../pam/views'
import { parseBody } from '../validation'
import { chunk } from '../vault/ciphers'

export const pamLeases = new Hono<Env>()

type Ctx = Context<Env>

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
const ID = `:id{${UUID}}`
for (const path of [
  '/api/access-requests',
  '/api/access-requests/*',
  '/api/leases',
  '/api/leases/*',
]) {
  pamLeases.use(path, authOnce)
}

const MIN_SECONDS = 60
const MAX_AHEAD_MS = 30 * 24 * 3600 * 1000
const seconds = z.number().int().min(MIN_SECONDS).max(MAX_LEASE_SECONDS)
const dateText = z
  .string()
  .max(40)
  .refine((v) => !Number.isNaN(Date.parse(v)), { message: 'Invalid date.' })

const notFound = (what: string) => new ApiError(404, `${what} not found.`)
const conflict = (message: string) => new ApiError(409, message)
const live = (l: Pick<LeaseRow, 'status' | 'notAfter'>, now: number) =>
  l.status === LeaseStatus.Active && l.notAfter > now

// ----- Who may decide -----

/** Organisations where the caller may decide everything, and collections where they hold Manage. */
function approverScope(ua: UserAccess) {
  const orgs = new Set<string>(ua.accessAllOrgs)
  for (const m of ua.members) if (isAdminRole(m)) orgs.add(m.organizationUuid)
  const collections = [...ua.grants].filter(([, a]) => a.manage).map(([id]) => id)
  return { orgs, collections }
}

const canDecide = (ua: UserAccess, orgUuid: string, collectionUuid: string) =>
  approverScope(ua).orgs.has(orgUuid) ||
  collectionAccess(ua, orgUuid, collectionUuid)?.manage === true

/** SQL for rows (with `organization_uuid` and `collection_uuid`) the caller may decide. */
function approvableSql(ua: UserAccess, orgCol: SQL, collCol: SQL): SQL {
  const scope = approverScope(ua)
  const parts: SQL[] = []
  for (const part of chunk([...scope.orgs])) {
    parts.push(
      sql`${orgCol} in (${sql.join(
        part.map((x) => sql`${x}`),
        sql`, `,
      )})`,
    )
  }
  for (const part of chunk(scope.collections)) {
    parts.push(
      sql`${collCol} in (${sql.join(
        part.map((x) => sql`${x}`),
        sql`, `,
      )})`,
    )
  }
  return parts.length ? sql`(${sql.join(parts, sql` or `)})` : sql`0`
}

// ----- Rules, items, requests -----

/** The enabled rule that covers the item through a collection the caller can reach. */
async function ruleForCipher(db: Db, ua: UserAccess, userUuid: string, cipherUuid: string) {
  const [cipher] = await db
    .select()
    .from(schema.ciphers)
    .where(eq(schema.ciphers.uuid, cipherUuid))
    .limit(1)
  if (!cipher?.organizationUuid || cipher.deletedAt !== null) throw notFound('Item')
  const access = await accessToCipher(db, userUuid, cipher, ua)
  if (!access) throw notFound('Item')
  // Members need privileged access enabled (`users/enable-pam`); owners and admins always have it.
  const member = ua.members.find((m) => m.organizationUuid === cipher.organizationUuid)
  if (!member || !(member.accessPam || isAdminRole(member))) {
    throw new ApiError(403, 'Privileged access is not enabled for you.')
  }
  const linked = await linkedCollections(db, cipher.uuid)
  const reachable = linked.filter((id) =>
    collectionAccess(ua, cipher.organizationUuid as string, id),
  )
  const rows = reachable.length
    ? await db
        .select({
          rule: schema.pamAccessRules,
          collectionUuid: schema.pamRuleCollections.collectionUuid,
        })
        .from(schema.pamRuleCollections)
        .innerJoin(
          schema.pamAccessRules,
          eq(schema.pamAccessRules.uuid, schema.pamRuleCollections.ruleUuid),
        )
        .where(
          and(
            inArray(schema.pamRuleCollections.collectionUuid, reachable),
            eq(schema.pamAccessRules.enabled, true),
          ),
        )
    : []
  const hit = rows[0]
  return { cipher, rule: hit?.rule, collectionUuid: hit?.collectionUuid }
}

const liveLeaseOn = async (db: Db, cipherUuid: string, now: number, requester?: string) => {
  const [l] = await db
    .select()
    .from(schema.pamLeases)
    .where(
      and(
        eq(schema.pamLeases.cipherUuid, cipherUuid),
        eq(schema.pamLeases.status, LeaseStatus.Active),
        sql`${schema.pamLeases.notAfter} > ${now}`,
        requester ? eq(schema.pamLeases.requesterUuid, requester) : undefined,
      ),
    )
    .orderBy(desc(schema.pamLeases.notAfter))
    .limit(1)
  return l
}

const myOpenRequests = (db: Db, userUuid: string, cipherUuid: string, now: number) =>
  db
    .select()
    .from(schema.pamAccessRequests)
    .where(
      and(
        eq(schema.pamAccessRequests.requesterUuid, userUuid),
        eq(schema.pamAccessRequests.cipherUuid, cipherUuid),
        sql`${schema.pamAccessRequests.extensionOfLeaseUuid} is null`,
        or(
          eq(schema.pamAccessRequests.status, RequestStatus.Pending),
          eq(schema.pamAccessRequests.status, RequestStatus.Approved),
        ),
        sql`${schema.pamAccessRequests.expiresAt} > ${now}`,
        sql`not exists (select 1 from pam_leases where request_uuid = pam_access_requests.uuid)`,
      ),
    )
    .orderBy(desc(schema.pamAccessRequests.submittedAt))

pamLeases.get(`/api/leases/ciphers/:id{${UUID}}/pre-check`, async (c) => {
  const db = createDb(c.env.DB)
  const user = c.var.user.uuid
  const ua = await loadUserAccess(db, user)
  const { cipher, rule } = await ruleForCipher(db, ua, user, c.req.param('id') ?? '')
  if (!rule) throw notFound('Access rule')
  const now = Date.now()
  const holder = await liveLeaseOn(db, cipher.uuid, now)
  const mine =
    holder?.requesterUuid === user ? holder : await liveLeaseOn(db, cipher.uuid, now, user)
  const open = await myOpenRequests(db, user, cipher.uuid, now)
  const blocked = rule.singleActiveLease && holder !== undefined
  return c.json({
    object: 'accessPreCheck',
    cipherId: cipher.uuid,
    approvalMode: approvalModeOf(rule),
    hasActiveLease: mine !== undefined,
    defaultDurationSeconds: rule.defaultLeaseSeconds,
    maxDurationSeconds: rule.maxLeaseSeconds,
    canStartLease: !blocked && mine === undefined && open.length === 0,
    slotFreesAt: blocked ? iso(holder.notAfter) : null,
  })
})

pamLeases.get(`/api/leases/ciphers/:id{${UUID}}/state`, async (c) => {
  const db = createDb(c.env.DB)
  const user = c.var.user.uuid
  const ua = await loadUserAccess(db, user)
  const { cipher, rule } = await ruleForCipher(db, ua, user, c.req.param('id') ?? '')
  const now = Date.now()
  const mine = await liveLeaseOn(db, cipher.uuid, now, user)
  const open = await myOpenRequests(db, user, cipher.uuid, now)
  const pending = open.find((r) => r.status === RequestStatus.Pending)
  const approved = open.find((r) => r.status === RequestStatus.Approved)
  const holder = rule?.singleActiveLease ? await liveLeaseOn(db, cipher.uuid, now) : undefined
  const [pendingView, approvedView] = await Promise.all([
    pending ? requestView(db, pending, now) : null,
    approved ? requestView(db, approved, now) : null,
  ])
  return c.json({
    object: 'cipherAccessState',
    cipherId: cipher.uuid,
    activeLease: mine ? leaseJson(mine, now) : null,
    pendingRequest: pendingView,
    approvedRequest: approvedView,
    extensionsAllowed: rule?.allowsExtensions ?? false,
    maxExtensionDurationSeconds: rule?.maxExtensionSeconds ?? null,
    canRequest: Boolean(rule) && !mine && open.length === 0 && !holder,
  })
})

const createSchema = z.object({
  durationSeconds: seconds.nullish(),
  start: dateText.nullish(),
  end: dateText.nullish(),
  reason: z.string().max(1000).nullish(),
})

/** Statement: insert a lease for `request` when the guards still hold. Zero rows when they do not. */
function insertLeaseIf(
  db: Db,
  lease: Omit<
    LeaseRow,
    'revokedAt' | 'revokedByUserUuid' | 'revocationReason' | 'lastExtensionRequestUuid'
  >,
  guard: SQL,
) {
  const c = (v: string | number, name: string) => sql<typeof v>`${v}`.as(name)
  return db.insert(schema.pamLeases).select(
    db
      .select({
        uuid: c(lease.uuid, 'uuid'),
        requestUuid: c(lease.requestUuid, 'request_uuid'),
        organizationUuid: c(lease.organizationUuid, 'organization_uuid'),
        cipherUuid: c(lease.cipherUuid, 'cipher_uuid'),
        collectionUuid: c(lease.collectionUuid, 'collection_uuid'),
        requesterUuid: c(lease.requesterUuid, 'requester_uuid'),
        status: c(lease.status, 'status'),
        notBefore: c(lease.notBefore, 'not_before'),
        notAfter: c(lease.notAfter, 'not_after'),
        revokedAt: sql<number | null>`null`.as('revoked_at'),
        revokedByUserUuid: sql<string | null>`null`.as('revoked_by_user_uuid'),
        revocationReason: sql<string | null>`null`.as('revocation_reason'),
        lastExtensionRequestUuid: sql<string | null>`null`.as('last_extension_request_uuid'),
        createdAt: c(lease.createdAt, 'created_at'),
      })
      .from(schema.pamAccessRequests)
      .where(and(eq(schema.pamAccessRequests.uuid, lease.requestUuid), guard)),
  )
}

const unique = (err: unknown) => /UNIQUE|constraint/i.test(String((err as Error)?.message ?? err))

pamLeases.post(`/api/leases/ciphers/:id{${UUID}}`, async (c) => {
  const db = createDb(c.env.DB)
  const user = c.var.user.uuid
  const body = await parseBody(c, createSchema)
  const ua = await loadUserAccess(db, user)
  const { cipher, rule, collectionUuid } = await ruleForCipher(
    db,
    ua,
    user,
    c.req.param('id') ?? '',
  )
  if (!rule || !collectionUuid) throw new ApiError(400, 'No access rule applies to this item.')
  const now = Date.now()

  // The window: an explicit start and end, or a duration from the moment of activation.
  if ((body.start == null) !== (body.end == null)) {
    throw new ApiError(400, 'The request is invalid.', {
      start: ['Give both start and end, or neither.'],
    })
  }
  let start: number | null = null
  let end: number | null = null
  let duration = body.durationSeconds ?? rule.defaultLeaseSeconds
  if (body.start != null && body.end != null) {
    start = Date.parse(body.start)
    end = Date.parse(body.end)
    if (end <= start || end <= now || start > now + MAX_AHEAD_MS) {
      throw new ApiError(400, 'The request is invalid.', { end: ['Invalid window.'] })
    }
    duration = Math.floor((end - Math.max(start, now)) / 1000)
    if (duration < MIN_SECONDS) throw new ApiError(400, 'The window is too short.')
  }
  if (duration > rule.maxLeaseSeconds) {
    throw new ApiError(400, 'The request is invalid.', {
      durationSeconds: ['The duration exceeds the maximum of the access rule.'],
    })
  }

  if (await liveLeaseOn(db, cipher.uuid, now, user))
    throw conflict('You already hold a lease on this item.')
  if ((await myOpenRequests(db, user, cipher.uuid, now)).length > 0) {
    throw conflict('You already have an open request for this item.')
  }
  const holder = rule.singleActiveLease ? await liveLeaseOn(db, cipher.uuid, now) : undefined
  if (holder) throw conflict(`The item is leased to another member until ${iso(holder.notAfter)}.`)

  const mode = approvalModeOf(rule)
  const auto = mode === ApprovalMode.Automatic
  const id = crypto.randomUUID()
  const request: RequestRow = {
    uuid: id,
    organizationUuid: cipher.organizationUuid as string,
    cipherUuid: cipher.uuid,
    collectionUuid,
    ruleUuid: rule.uuid,
    requesterUuid: user,
    status: auto ? RequestStatus.Approved : RequestStatus.Pending,
    reason: body.reason ?? null,
    windowStart: start,
    windowEnd: end,
    durationSeconds: duration,
    submittedAt: now,
    expiresAt: auto
      ? Math.min(end ?? Number.POSITIVE_INFINITY, now + APPROVAL_TTL_MS)
      : now + PENDING_TTL_MS,
    resolvedAt: auto ? now : null,
    extensionOfLeaseUuid: null,
    createdAt: now,
    updatedAt: now,
  }
  const statements: unknown[] = [
    db.insert(schema.pamAccessRequests).values(request),
    auditStatement(db, request.organizationUuid, 'access_requested', user, id, null, now),
  ]
  if (auto) {
    statements.push(
      db.insert(schema.pamAccessDecisions).values({
        uuid: crypto.randomUUID(),
        requestUuid: id,
        deciderKind: DeciderKind.Automatic,
        deciderUserUuid: null,
        verdict: Verdict.Approve,
        comment: null,
        decidedAt: now,
      }),
      insertLeaseIf(
        db,
        {
          uuid: crypto.randomUUID(),
          requestUuid: id,
          organizationUuid: request.organizationUuid,
          cipherUuid: cipher.uuid,
          collectionUuid,
          requesterUuid: user,
          status: LeaseStatus.Active,
          notBefore: Math.max(start ?? now, now),
          notAfter: end ?? now + duration * 1000,
          createdAt: now,
        },
        rule.singleActiveLease
          ? (and(
              noLiveLease(cipher.uuid, now),
              eq(schema.pamAccessRequests.status, RequestStatus.Approved),
            ) as SQL)
          : eq(schema.pamAccessRequests.status, RequestStatus.Approved),
      ),
    )
  }
  let res: D1Result[]
  try {
    res = await runBatch(db, statements as never)
  } catch (err) {
    if (unique(err)) throw conflict('You already have an open request for this item.')
    throw err
  }
  if (auto && changes(res[3]) === 0) {
    // Another lease took the slot between the check and the write: leave no half-made request.
    await db
      .update(schema.pamAccessRequests)
      .set({ status: RequestStatus.Cancelled, updatedAt: now })
      .where(eq(schema.pamAccessRequests.uuid, id))
    throw conflict('The item was leased to another member a moment ago.')
  }
  const [row] = await db
    .select()
    .from(schema.pamAccessRequests)
    .where(eq(schema.pamAccessRequests.uuid, id))
    .limit(1)
  return c.json({
    object: 'accessRequestResult',
    approvalMode: mode,
    request: await requestView(db, row as RequestRow, now),
  })
})

// ----- Access requests -----

async function loadRequest(db: Db, id: string) {
  const [row] = await db
    .select()
    .from(schema.pamAccessRequests)
    .where(eq(schema.pamAccessRequests.uuid, id))
    .limit(1)
  if (!row) throw notFound('Access request')
  return row
}

/** Own requests, and others' requests the caller may decide; everything else is "not found". */
async function visibleRequest(db: Db, ua: UserAccess, userUuid: string, id: string) {
  const row = await loadRequest(db, id)
  if (row.requesterUuid !== userUuid && !canDecide(ua, row.organizationUuid, row.collectionUuid)) {
    throw notFound('Access request')
  }
  return row
}

const openSql = (now: number) =>
  sql`((${schema.pamAccessRequests.status} = ${RequestStatus.Pending} or (${schema.pamAccessRequests.status} = ${RequestStatus.Approved} and ${schema.pamAccessRequests.extensionOfLeaseUuid} is null and not exists (select 1 from pam_leases where request_uuid = pam_access_requests.uuid))) and ${schema.pamAccessRequests.expiresAt} > ${now})`

const requestList = async (c: Ctx, where: (ua: UserAccess, now: number) => SQL) => {
  const db = createDb(c.env.DB)
  const ua = await loadUserAccess(db, c.var.user.uuid)
  const now = Date.now()
  const rows = await db
    .select()
    .from(schema.pamAccessRequests)
    .where(where(ua, now))
    .orderBy(desc(schema.pamAccessRequests.submittedAt))
    .limit(LIST_LIMIT)
  return c.json(list(await requestViews(db, rows, now)))
}

pamLeases.get('/api/access-requests/inbox', (c) =>
  requestList(
    c,
    (ua, now) =>
      sql`${schema.pamAccessRequests.status} = ${RequestStatus.Pending} and ${schema.pamAccessRequests.expiresAt} > ${now} and ${schema.pamAccessRequests.requesterUuid} != ${c.var.user.uuid} and ${approvableSql(ua, sql`${schema.pamAccessRequests.organizationUuid}`, sql`${schema.pamAccessRequests.collectionUuid}`)}`,
  ),
)
pamLeases.get('/api/access-requests/mine', (c) =>
  requestList(
    c,
    (_ua, now) =>
      sql`${schema.pamAccessRequests.requesterUuid} = ${c.var.user.uuid} and ${openSql(now)}`,
  ),
)
pamLeases.get('/api/access-requests/history', (c) =>
  requestList(
    c,
    (ua, now) =>
      sql`(${schema.pamAccessRequests.requesterUuid} = ${c.var.user.uuid} or ${approvableSql(ua, sql`${schema.pamAccessRequests.organizationUuid}`, sql`${schema.pamAccessRequests.collectionUuid}`)}) and not ${openSql(now)}`,
  ),
)

pamLeases.get(`/api/access-requests/${ID}`, async (c) => {
  const db = createDb(c.env.DB)
  const ua = await loadUserAccess(db, c.var.user.uuid)
  const row = await visibleRequest(db, ua, c.var.user.uuid, c.req.param('id') ?? '')
  return c.json(await requestView(db, row))
})

pamLeases.post(`/api/access-requests/${ID}/decision`, async (c) => {
  const db = createDb(c.env.DB)
  const user = c.var.user.uuid
  const ua = await loadUserAccess(db, user)
  const row = await visibleRequest(db, ua, user, c.req.param('id') ?? '')
  const body = await parseBody(
    c,
    z.object({
      verdict: z.union([z.literal(Verdict.Deny), z.literal(Verdict.Approve)]),
      comment: z.string().max(1000).nullish(),
    }),
  )
  if (!canDecide(ua, row.organizationUuid, row.collectionUuid)) {
    throw new ApiError(403, 'You do not have permission to decide this request.')
  }
  if (row.requesterUuid === user) throw new ApiError(403, 'You cannot decide your own request.')
  const now = Date.now()
  if (row.status !== RequestStatus.Pending || row.expiresAt <= now) {
    throw conflict('The request is no longer pending.')
  }
  const approve = body.verdict === Verdict.Approve
  const status = approve ? RequestStatus.Approved : RequestStatus.Denied
  const isExtension = row.extensionOfLeaseUuid !== null
  const decided = sql`exists (select 1 from pam_access_requests where uuid = ${row.uuid} and status = ${status} and resolved_at = ${now})`
  const statements: unknown[] = [
    db
      .update(schema.pamAccessRequests)
      .set({
        status,
        resolvedAt: now,
        updatedAt: now,
        // An approval is valid for a day, or until the requested window ends.
        expiresAt:
          approve && !isExtension
            ? Math.min(row.windowEnd ?? Number.POSITIVE_INFINITY, now + APPROVAL_TTL_MS)
            : row.expiresAt,
      })
      .where(
        and(
          eq(schema.pamAccessRequests.uuid, row.uuid),
          eq(schema.pamAccessRequests.status, RequestStatus.Pending),
          sql`${schema.pamAccessRequests.expiresAt} > ${now}`,
        ),
      ),
    db.insert(schema.pamAccessDecisions).select(
      db
        .select({
          uuid: sql<string>`${crypto.randomUUID()}`.as('uuid'),
          requestUuid: sql<string>`${row.uuid}`.as('request_uuid'),
          deciderKind: sql<number>`${DeciderKind.Human}`.as('decider_kind'),
          deciderUserUuid: sql<string>`${user}`.as('decider_user_uuid'),
          verdict: sql<number>`${body.verdict}`.as('verdict'),
          comment: sql<string | null>`${body.comment ?? null}`.as('comment'),
          decidedAt: sql<number>`${now}`.as('decided_at'),
        })
        .from(schema.pamAccessRequests)
        .where(and(eq(schema.pamAccessRequests.uuid, row.uuid), decided)),
    ),
    auditStatement(
      db,
      row.organizationUuid,
      approve ? 'access_approved' : 'access_denied',
      user,
      row.uuid,
      null,
      now,
    ),
  ]
  if (approve && isExtension) {
    // The extension applies in the same batch, and only while its lease is still live.
    statements.push(
      db
        .update(schema.pamLeases)
        .set({
          notAfter: sql`${schema.pamLeases.notAfter} + ${row.durationSeconds * 1000}`,
          lastExtensionRequestUuid: row.uuid,
        })
        .where(
          and(
            eq(schema.pamLeases.uuid, row.extensionOfLeaseUuid as string),
            eq(schema.pamLeases.status, LeaseStatus.Active),
            sql`${schema.pamLeases.notAfter} > ${now}`,
            decided,
          ),
        ),
    )
  }
  const res = await runBatch(db, statements as never)
  if (changes(res[0]) === 0) throw conflict('The request is no longer pending.')
  if (approve && isExtension && changes(res[3]) === 0) {
    await db
      .update(schema.pamAccessRequests)
      .set({ status: RequestStatus.Cancelled, updatedAt: now })
      .where(eq(schema.pamAccessRequests.uuid, row.uuid))
    throw conflict('The lease ended before the extension was approved.')
  }
  return c.json(await requestView(db, await loadRequest(db, row.uuid), now))
})

pamLeases.post(`/api/access-requests/${ID}/activate`, async (c) => {
  const db = createDb(c.env.DB)
  const user = c.var.user.uuid
  const row = await loadRequest(db, c.req.param('id') ?? '')
  if (row.requesterUuid !== user) throw notFound('Access request')
  const now = Date.now()
  if (row.extensionOfLeaseUuid !== null)
    throw new ApiError(400, 'Extensions apply when they are approved.')
  if (row.status !== RequestStatus.Approved || row.expiresAt <= now) {
    throw conflict('The request is not approved, or the approval has expired.')
  }
  if (row.windowStart !== null && row.windowStart > now)
    throw conflict('The requested window has not started.')
  const [rule] = await db
    .select()
    .from(schema.pamAccessRules)
    .where(eq(schema.pamAccessRules.uuid, row.ruleUuid))
    .limit(1)
  if (!rule?.enabled) throw conflict('The access rule no longer applies.')
  if (rule.singleActiveLease && (await liveLeaseOn(db, row.cipherUuid, now))) {
    throw conflict('The item is leased to another member.')
  }
  const leaseId = crypto.randomUUID()
  const guard = and(
    eq(schema.pamAccessRequests.status, RequestStatus.Approved),
    sql`${schema.pamAccessRequests.expiresAt} > ${now}`,
    sql`not exists (select 1 from pam_leases where request_uuid = ${row.uuid})`,
    rule.singleActiveLease ? noLiveLease(row.cipherUuid, now) : undefined,
    sql`not exists (select 1 from pam_leases where cipher_uuid = ${row.cipherUuid} and requester_uuid = ${user} and status = ${LeaseStatus.Active} and not_after > ${now})`,
  ) as SQL
  let res: D1Result[]
  try {
    res = await runBatch(db, [
      insertLeaseIf(
        db,
        {
          uuid: leaseId,
          requestUuid: row.uuid,
          organizationUuid: row.organizationUuid,
          cipherUuid: row.cipherUuid,
          collectionUuid: row.collectionUuid,
          requesterUuid: user,
          status: LeaseStatus.Active,
          notBefore: now,
          notAfter: row.windowEnd ?? now + row.durationSeconds * 1000,
          createdAt: now,
        },
        guard,
      ),
      auditStatement(db, row.organizationUuid, 'lease_activated', user, leaseId, row.uuid, now),
    ] as never)
  } catch (err) {
    if (unique(err)) throw conflict('The request was already activated.')
    throw err
  }
  if (changes(res[0]) === 0) throw conflict('The request cannot be activated now.')
  const [lease] = await db
    .select()
    .from(schema.pamLeases)
    .where(eq(schema.pamLeases.uuid, leaseId))
    .limit(1)
  return c.json(leaseJson(lease as LeaseRow, now))
})

const reasonBody = z.object({ reason: z.string().max(1000).nullish() }).nullish()
const readReason = async (c: Ctx) => {
  const raw = await c.req.json().catch(() => null)
  const parsed = reasonBody.safeParse(raw)
  if (!parsed.success)
    throw new ApiError(400, 'The request is invalid.', { reason: ['Invalid reason.'] })
  return parsed.data?.reason ?? null
}

/** Ends a lease early. The requester cancels it; an approver revokes it. */
async function endLease(c: Ctx, db: Db, lease: LeaseRow, ua: UserAccess, reason: string | null) {
  const user = c.var.user.uuid
  const now = Date.now()
  const own = lease.requesterUuid === user
  if (!own && !canDecide(ua, lease.organizationUuid, lease.collectionUuid)) throw notFound('Lease')
  if (!live(lease, now)) throw conflict('The lease is not active.')
  const res = await runBatch(db, [
    db
      .update(schema.pamLeases)
      .set({
        status: own ? LeaseStatus.Cancelled : LeaseStatus.Revoked,
        revokedAt: now,
        revokedByUserUuid: user,
        revocationReason: reason,
      })
      .where(
        and(
          eq(schema.pamLeases.uuid, lease.uuid),
          eq(schema.pamLeases.status, LeaseStatus.Active),
          sql`${schema.pamLeases.notAfter} > ${now}`,
        ),
      ),
    auditStatement(
      db,
      lease.organizationUuid,
      own ? 'lease_cancelled' : 'lease_revoked',
      user,
      lease.uuid,
      reason,
      now,
    ),
  ])
  if (changes(res[0]) === 0) throw conflict('The lease is not active.')
  await rotateAfterAccess(db, lease, now)
}

const loadLease = async (db: Db, id: string) => {
  const [l] = await db.select().from(schema.pamLeases).where(eq(schema.pamLeases.uuid, id)).limit(1)
  if (!l) throw notFound('Lease')
  return l
}

pamLeases.post(`/api/access-requests/${ID}/revoke`, async (c) => {
  const db = createDb(c.env.DB)
  const user = c.var.user.uuid
  const ua = await loadUserAccess(db, user)
  const row = await visibleRequest(db, ua, user, c.req.param('id') ?? '')
  const reason = await readReason(c)
  const now = Date.now()
  const [lease] = await db
    .select()
    .from(schema.pamLeases)
    .where(eq(schema.pamLeases.requestUuid, row.uuid))
    .limit(1)
  if (lease) {
    await endLease(c, db, lease, ua, reason)
    return c.body(null, 200)
  }
  // No lease yet: a pending or approved request is withdrawn (by its owner) or cancelled (by an approver).
  const res = await runBatch(db, [
    db
      .update(schema.pamAccessRequests)
      .set({ status: RequestStatus.Cancelled, resolvedAt: now, updatedAt: now })
      .where(
        and(
          eq(schema.pamAccessRequests.uuid, row.uuid),
          inArray(schema.pamAccessRequests.status, [RequestStatus.Pending, RequestStatus.Approved]),
          sql`${schema.pamAccessRequests.expiresAt} > ${now}`,
          sql`not exists (select 1 from pam_leases where request_uuid = ${row.uuid})`,
        ),
      ),
    auditStatement(
      db,
      row.organizationUuid,
      'access_request_cancelled',
      user,
      row.uuid,
      reason,
      now,
    ),
  ])
  if (changes(res[0]) === 0) throw conflict('The request cannot be revoked now.')
  return c.body(null, 200)
})

// ----- Leases -----

const leaseList = async (c: Ctx, where: (ua: UserAccess, now: number) => SQL) => {
  const db = createDb(c.env.DB)
  const ua = await loadUserAccess(db, c.var.user.uuid)
  const now = Date.now()
  const rows = await db
    .select()
    .from(schema.pamLeases)
    .where(where(ua, now))
    .orderBy(desc(schema.pamLeases.createdAt))
    .limit(LIST_LIMIT)
  return c.json(list(rows.map((l) => leaseJson(l, now))))
}
const liveSql = (now: number) =>
  sql`(${schema.pamLeases.status} = ${LeaseStatus.Active} and ${schema.pamLeases.notAfter} > ${now})`
const visibleLeases = (c: Ctx, ua: UserAccess) =>
  sql`(${schema.pamLeases.requesterUuid} = ${c.var.user.uuid} or ${approvableSql(ua, sql`${schema.pamLeases.organizationUuid}`, sql`${schema.pamLeases.collectionUuid}`)})`

pamLeases.get('/api/leases/active', (c) =>
  leaseList(c, (ua, now) => sql`${visibleLeases(c, ua)} and ${liveSql(now)}`),
)
pamLeases.get('/api/leases/mine', (c) =>
  leaseList(
    c,
    (_ua, now) => sql`${schema.pamLeases.requesterUuid} = ${c.var.user.uuid} and ${liveSql(now)}`,
  ),
)
pamLeases.get('/api/leases/history', (c) =>
  leaseList(c, (ua, now) => sql`${visibleLeases(c, ua)} and not ${liveSql(now)}`),
)

pamLeases.post(`/api/leases/${ID}/revoke`, async (c) => {
  const db = createDb(c.env.DB)
  const ua = await loadUserAccess(db, c.var.user.uuid)
  const lease = await loadLease(db, c.req.param('id') ?? '')
  await endLease(c, db, lease, ua, await readReason(c))
  return c.body(null, 200)
})

pamLeases.post(`/api/leases/${ID}/extend`, async (c) => {
  const db = createDb(c.env.DB)
  const user = c.var.user.uuid
  const lease = await loadLease(db, c.req.param('id') ?? '')
  if (lease.requesterUuid !== user) throw notFound('Lease')
  const body = await parseBody(
    c,
    z.object({ durationSeconds: seconds.nullish(), reason: z.string().min(1).max(1000) }),
  )
  const now = Date.now()
  if (!live(lease, now)) throw conflict('The lease is not active.')
  const [original] = await db
    .select()
    .from(schema.pamAccessRequests)
    .where(eq(schema.pamAccessRequests.uuid, lease.requestUuid))
    .limit(1)
  const [rule] = original
    ? await db
        .select()
        .from(schema.pamAccessRules)
        .where(eq(schema.pamAccessRules.uuid, original.ruleUuid))
        .limit(1)
    : []
  if (!rule?.enabled || !rule.allowsExtensions)
    throw new ApiError(400, 'This lease cannot be extended.')
  const max = rule.maxExtensionSeconds ?? rule.defaultLeaseSeconds
  const duration = body.durationSeconds ?? max
  if (duration > max) {
    throw new ApiError(400, 'The request is invalid.', {
      durationSeconds: ['The duration exceeds the maximum extension of the access rule.'],
    })
  }
  const auto = approvalModeOf(rule) === ApprovalMode.Automatic
  const id = crypto.randomUUID()
  const request: RequestRow = {
    uuid: id,
    organizationUuid: lease.organizationUuid,
    cipherUuid: lease.cipherUuid,
    collectionUuid: lease.collectionUuid,
    ruleUuid: rule.uuid,
    requesterUuid: user,
    status: auto ? RequestStatus.Approved : RequestStatus.Pending,
    reason: body.reason,
    windowStart: null,
    windowEnd: null,
    durationSeconds: duration,
    submittedAt: now,
    expiresAt: now + PENDING_TTL_MS,
    resolvedAt: auto ? now : null,
    extensionOfLeaseUuid: lease.uuid,
    createdAt: now,
    updatedAt: now,
  }
  const statements: unknown[] = [
    db.insert(schema.pamAccessRequests).values(request),
    auditStatement(
      db,
      lease.organizationUuid,
      'lease_extension_requested',
      user,
      lease.uuid,
      id,
      now,
    ),
  ]
  if (auto) {
    statements.push(
      db.insert(schema.pamAccessDecisions).values({
        uuid: crypto.randomUUID(),
        requestUuid: id,
        deciderKind: DeciderKind.Automatic,
        deciderUserUuid: null,
        verdict: Verdict.Approve,
        comment: null,
        decidedAt: now,
      }),
      db
        .update(schema.pamLeases)
        .set({
          notAfter: sql`${schema.pamLeases.notAfter} + ${duration * 1000}`,
          lastExtensionRequestUuid: id,
        })
        .where(
          and(
            eq(schema.pamLeases.uuid, lease.uuid),
            eq(schema.pamLeases.status, LeaseStatus.Active),
            sql`${schema.pamLeases.notAfter} > ${now}`,
          ),
        ),
    )
  }
  let res: D1Result[]
  try {
    res = await runBatch(db, statements as never)
  } catch (err) {
    if (unique(err)) throw conflict('This lease already has a pending extension request.')
    throw err
  }
  if (auto && changes(res[3]) === 0) {
    await db
      .update(schema.pamAccessRequests)
      .set({ status: RequestStatus.Cancelled, updatedAt: now })
      .where(eq(schema.pamAccessRequests.uuid, id))
    throw conflict('The lease ended before it could be extended.')
  }
  return c.json(await requestView(db, await loadRequest(db, id), now))
})
