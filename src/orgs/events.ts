import { and, desc, eq, gte, lt, lte, or, type SQL } from 'drizzle-orm'
import type { Context } from 'hono'
import { fromB64u, toB64u, utf8 } from '../auth/crypto'
import type { Db } from '../db'
import { schema } from '../db'
import type { Env } from '../env'

export interface EventInput {
  type: number
  organizationUuid?: string | null
  userUuid?: string | null
  cipherUuid?: string | null
  collectionUuid?: string | null
  groupUuid?: string | null
  policyUuid?: string | null
  organizationUserUuid?: string | null
  actingUserUuid?: string | null
  secretUuid?: string | null
  projectUuid?: string | null
  /** Machine account that acted, or that the event is about. */
  serviceAccountUuid?: string | null
  grantedServiceAccountUuid?: string | null
  /** Non-member actor: 1 SCIM, 3 Public API (TASKS #270). */
  systemUser?: number | null
  date?: number
}

/** Device type and client address of the current request. */
export function requestMeta(c: Context<Env>) {
  const type = Number.parseInt(c.req.header('Device-Type') ?? '', 10)
  return {
    deviceType: Number.isFinite(type) ? type : null,
    ipAddress: c.req.header('CF-Connecting-IP') ?? null,
  }
}

/** An insert statement for one event; include it in the batch of the write it records. */
export function eventStatement(
  db: Db,
  c: Context<Env>,
  e: EventInput,
  actor: string | null = c.var.user?.uuid ?? null,
) {
  const meta = requestMeta(c)
  return db.insert(schema.events).values({
    uuid: crypto.randomUUID(),
    eventType: e.type,
    userUuid: e.userUuid ?? null,
    organizationUuid: e.organizationUuid ?? null,
    cipherUuid: e.cipherUuid ?? null,
    collectionUuid: e.collectionUuid ?? null,
    groupUuid: e.groupUuid ?? null,
    policyUuid: e.policyUuid ?? null,
    organizationUserUuid: e.organizationUserUuid ?? null,
    actingUserUuid: e.actingUserUuid ?? actor,
    secretUuid: e.secretUuid ?? null,
    projectUuid: e.projectUuid ?? null,
    serviceAccountUuid: e.serviceAccountUuid ?? null,
    grantedServiceAccountUuid: e.grantedServiceAccountUuid ?? null,
    systemUser: e.systemUser ?? null,
    deviceType: meta.deviceType,
    ipAddress: meta.ipAddress,
    eventDate: e.date ?? Date.now(),
  })
}

const iso = (ms: number) => new Date(ms).toISOString()

export function eventJson(e: typeof schema.events.$inferSelect) {
  return {
    object: 'event',
    type: e.eventType,
    userId: e.userUuid,
    organizationId: e.organizationUuid,
    providerId: null,
    cipherId: e.cipherUuid,
    collectionId: e.collectionUuid,
    groupId: e.groupUuid,
    policyId: e.policyUuid,
    organizationUserId: e.organizationUserUuid,
    providerUserId: null,
    providerOrganizationId: null,
    actingUserId: e.actingUserUuid,
    date: iso(e.eventDate),
    deviceType: e.deviceType,
    ipAddress: e.ipAddress,
    installationId: null,
    systemUser: e.systemUser,
    domainName: null,
    secretId: e.secretUuid,
    projectId: e.projectUuid,
    serviceAccountId: e.serviceAccountUuid,
    grantedServiceAccountId: e.grantedServiceAccountUuid,
  }
}

export const EVENT_PAGE_SIZE = 50

const parseDate = (s: string | undefined): number | null => {
  if (!s) return null
  const t = Date.parse(s)
  return Number.isNaN(t) ? null : t
}

/** Opaque cursor: the date and id of the last row of the previous page. */
const encodeCursor = (e: { eventDate: number; uuid: string }) =>
  toB64u(utf8(`${e.eventDate}.${e.uuid}`))

function decodeCursor(token: string | undefined): { date: number; uuid: string } | null {
  if (!token) return null
  const raw = fromB64u(token)
  if (!raw) return null
  const text = new TextDecoder().decode(raw)
  const dot = text.indexOf('.')
  const date = Number(text.slice(0, dot))
  return dot > 0 && Number.isFinite(date) ? { date, uuid: text.slice(dot + 1) } : null
}

/** One page of events, newest first, filtered by `where` and the request's start, end and cursor. */
export async function listEvents(
  db: Db,
  c: Context<Env>,
  where: SQL | undefined,
  map: (e: typeof schema.events.$inferSelect) => unknown = eventJson,
) {
  const start = parseDate(c.req.query('start'))
  const end = parseDate(c.req.query('end'))
  const cursor = decodeCursor(c.req.query('continuationToken'))
  const e = schema.events
  const conditions = [
    where,
    start === null ? undefined : gte(e.eventDate, start),
    end === null ? undefined : lte(e.eventDate, end),
    cursor
      ? or(lt(e.eventDate, cursor.date), and(eq(e.eventDate, cursor.date), lt(e.uuid, cursor.uuid)))
      : undefined,
  ].filter((x): x is SQL => x !== undefined)
  const rows = await db
    .select()
    .from(e)
    .where(and(...conditions))
    .orderBy(desc(e.eventDate), desc(e.uuid))
    .limit(EVENT_PAGE_SIZE + 1)
  const page = rows.slice(0, EVENT_PAGE_SIZE)
  const last = page[page.length - 1]
  return {
    object: 'list',
    data: page.map(map),
    continuationToken: rows.length > EVENT_PAGE_SIZE && last ? encodeCursor(last) : null,
  }
}
