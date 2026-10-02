// Notification centre (TASKS #231): end user notifications with per user read and deleted state.
// Wire shapes follow `NotificationViewResponse` in the web client
// (libs/common/src/vault/notifications/models/notification-view.response.ts).
import { and, desc, eq, inArray, isNull, or } from 'drizzle-orm'
import type { Context } from 'hono'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { Status } from '../orgs/constants'
import { activeMemberIds, defer } from '../orgs/notify'
import { PushType, pushUserUpdate } from './publish'

type Notification = typeof schema.notifications.$inferSelect
type NotificationState = { readAt: number | null; deletedAt: number | null } | null

const iso = (ms: number | null | undefined) => (ms == null ? null : new Date(ms).toISOString())

export function notificationJson(n: Notification, s: NotificationState) {
  return {
    object: 'notificationStatusDetails',
    id: n.uuid,
    priority: n.priority,
    global: n.userUuid === null && n.organizationUuid === null,
    title: n.title,
    body: n.body,
    date: iso(n.createdAt),
    taskId: n.taskUuid,
    readDate: iso(s?.readAt),
    deletedDate: iso(s?.deletedAt),
  }
}

/** The PascalCase push payload of the `Notification` and `NotificationStatus` push types. */
const pushPayload = (n: Notification, s: NotificationState) => {
  const j = notificationJson(n, s)
  return {
    Id: j.id,
    Priority: j.priority,
    Global: j.global,
    Title: j.title,
    Body: j.body,
    Date: j.date,
    TaskId: j.taskId,
    ReadDate: j.readDate,
    DeletedDate: j.deletedDate,
  }
}

/** Organisations where the user is a confirmed member. */
async function confirmedOrgs(db: Db, userUuid: string) {
  const uo = schema.usersOrganizations
  const rows = await db
    .select({ id: uo.organizationUuid })
    .from(uo)
    .where(and(eq(uo.userUuid, userUuid), eq(uo.status, Status.Confirmed)))
  return rows.map((r) => r.id)
}

/** Condition for the notifications addressed to a user: their own, their organisations', global. */
async function visibleTo(db: Db, userUuid: string) {
  const n = schema.notifications
  const orgs = await confirmedOrgs(db, userUuid)
  return or(
    eq(n.userUuid, userUuid),
    and(
      isNull(n.userUuid),
      orgs.length ? or(isNull(n.organizationUuid), inArray(n.organizationUuid, orgs)) : undefined,
      orgs.length ? undefined : isNull(n.organizationUuid),
    ),
  )
}

export interface ListOptions {
  read?: boolean
  deleted?: boolean
  page: number
  pageSize: number
}

/** One page of the user's notifications, highest priority and newest first. */
export async function listNotifications(db: Db, userUuid: string, o: ListOptions) {
  const n = schema.notifications
  const s = schema.notificationStatus
  const rows = await db
    .select({ n, readAt: s.readAt, deletedAt: s.deletedAt })
    .from(n)
    .leftJoin(s, and(eq(s.notificationUuid, n.uuid), eq(s.userUuid, userUuid)))
    .where(await visibleTo(db, userUuid))
    .orderBy(desc(n.priority), desc(n.createdAt), desc(n.uuid))
  const filtered = rows.filter(
    (r) =>
      (o.read === undefined || (r.readAt != null) === o.read) &&
      (r.deletedAt != null) === (o.deleted ?? false),
  )
  const start = (o.page - 1) * o.pageSize
  const page = filtered.slice(start, start + o.pageSize)
  return {
    object: 'list',
    data: page.map((r) => notificationJson(r.n, r)),
    continuationToken: filtered.length > start + o.pageSize ? String(o.page + 1) : null,
  }
}

/** Loads a notification addressed to the user, with their state; undefined when not visible. */
export async function findNotification(db: Db, userUuid: string, id: string) {
  const n = schema.notifications
  const s = schema.notificationStatus
  const [row] = await db
    .select({ n, readAt: s.readAt, deletedAt: s.deletedAt })
    .from(n)
    .leftJoin(s, and(eq(s.notificationUuid, n.uuid), eq(s.userUuid, userUuid)))
    .where(and(eq(n.uuid, id), await visibleTo(db, userUuid)))
    .limit(1)
  return row
}

/** Records that the user read or deleted a notification, then pushes the new state. */
export async function setNotificationState(
  c: Context<Env>,
  db: Db,
  userUuid: string,
  id: string,
  change: 'read' | 'deleted',
) {
  const row = await findNotification(db, userUuid, id)
  if (!row) return false
  const now = Date.now()
  const next = {
    readAt: change === 'read' ? (row.readAt ?? now) : row.readAt,
    deletedAt: change === 'deleted' ? (row.deletedAt ?? now) : row.deletedAt,
  }
  await db
    .insert(schema.notificationStatus)
    .values({ notificationUuid: row.n.uuid, userUuid, ...next })
    .onConflictDoUpdate({
      target: [schema.notificationStatus.notificationUuid, schema.notificationStatus.userUuid],
      set: next,
    })
  defer(
    c,
    pushUserUpdate(
      c.env,
      userUuid,
      PushType.NotificationStatus,
      pushPayload(row.n, next),
      c.var.auth?.deviceIdentifier,
    ),
  )
  return true
}

/** Recipients of a new notification. A global one reaches every enabled account. */
async function recipients(db: Db, n: Notification): Promise<string[]> {
  if (n.userUuid) return [n.userUuid]
  if (n.organizationUuid) return activeMemberIds(db, n.organizationUuid)
  const rows = await db
    .select({ id: schema.users.uuid })
    .from(schema.users)
    .where(eq(schema.users.enabled, true))
  return rows.map((r) => r.id)
}

/** Pushes a new notification to everyone it is addressed to, after the response. */
export function pushNewNotification(c: Context<Env>, db: Db, n: Notification) {
  defer(
    c,
    (async () => {
      for (const user of await recipients(db, n)) {
        await pushUserUpdate(c.env, user, PushType.Notification, pushPayload(n, null))
      }
    })(),
  )
}

export interface NewNotification {
  title: string
  body: string
  priority?: number | null
  userId?: string | null
  organizationId?: string | null
}

/**
 * Creates a notification for one user, the members of one organisation, or everyone, and pushes
 * it. Unknown targets are a 404.
 */
export async function createNotification(c: Context<Env>, input: NewNotification) {
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const userUuid = input.userId?.toLowerCase() ?? null
  const orgUuid = input.organizationId?.toLowerCase() ?? null
  if (userUuid && orgUuid) {
    throw new ApiError(400, 'Choose a user or an organization, not both.')
  }
  if (userUuid) {
    const [u] = await db
      .select({ id: schema.users.uuid })
      .from(schema.users)
      .where(eq(schema.users.uuid, userUuid))
    if (!u) throw new ApiError(404, 'User not found')
  }
  if (orgUuid) {
    const [o] = await db
      .select({ id: schema.organizations.uuid })
      .from(schema.organizations)
      .where(eq(schema.organizations.uuid, orgUuid))
    if (!o) throw new ApiError(404, 'Organization not found')
  }
  const now = Date.now()
  const n: Notification = {
    uuid: crypto.randomUUID(),
    userUuid,
    organizationUuid: orgUuid,
    taskUuid: null,
    priority: input.priority ?? 0,
    title: input.title,
    body: input.body,
    createdAt: now,
    updatedAt: now,
  }
  await db.insert(schema.notifications).values(n)
  pushNewNotification(c, db, n)
  return n
}
