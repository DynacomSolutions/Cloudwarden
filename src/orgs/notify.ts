import { and, eq, inArray } from 'drizzle-orm'
import type { Context, MiddlewareHandler } from 'hono'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { PushType, pushUserUpdate } from '../notifications/publish'
import { relayRefreshUser } from '../notifications/relay'
import { loadUserAccess } from './access'
import { itemAccess, linkedCollections } from './ciphers'
import { Status } from './constants'

type Ctx = Context<Env>
type CipherRef = { uuid: string; organizationUuid: string | null }

/** Beyond this many members, per-member access is not worth computing: everyone resyncs ciphers. */
const MAX_PRECISE = 100

const iso = (ms: number) => new Date(ms).toISOString()

/** Runs a push after the response; detached when there is no execution context. */
function defer(c: Ctx, work: Promise<void>): void {
  try {
    c.executionCtx.waitUntil(work)
  } catch {
    void work
  }
}

/** Active members of an organisation. Read it before a write that may remove them. */
export async function activeMemberIds(db: Db, orgUuid: string): Promise<string[]> {
  const rows = await db
    .select({ id: schema.usersOrganizations.userUuid })
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
        inArray(schema.usersOrganizations.status, [Status.Accepted, Status.Confirmed]),
      ),
    )
  return rows.flatMap((r) => (r.id ? [r.id] : []))
}

/** Members who can see a cipher right now. */
export async function cipherRecipients(db: Db, cipher: CipherRef): Promise<string[]> {
  if (!cipher.organizationUuid) return []
  const members = await activeMemberIds(db, cipher.organizationUuid)
  if (members.length > MAX_PRECISE) return members
  const linked = await linkedCollections(db, cipher.uuid)
  const out: string[] = []
  for (const userUuid of members) {
    const ua = await loadUserAccess(db, userUuid)
    if (itemAccess(ua, cipher.organizationUuid, linked)) out.push(userUuid)
  }
  return out
}

function actorDevice(c: Ctx): string | null {
  return c.var.auth?.deviceIdentifier ?? null
}

/** Pushes one cipher event to each recipient; the acting device is skipped for the actor only. */
export function notifyOrgCipher(
  c: Ctx,
  type: PushType,
  cipher: CipherRef,
  recipients: string[],
  revision: number,
): void {
  const actor = c.var.user.uuid
  const device = actorDevice(c)
  defer(
    c,
    (async () => {
      const db = createDb(c.env.DB)
      const collections = await linkedCollections(db, cipher.uuid)
      await Promise.all(
        recipients.map((userUuid) =>
          pushUserUpdate(
            c.env,
            userUuid,
            type,
            {
              Id: cipher.uuid,
              UserId: userUuid,
              OrganizationId: cipher.organizationUuid,
              CollectionIds: collections,
              RevisionDate: iso(revision),
            },
            userUuid === actor ? device : null,
          ),
        ),
      )
    })(),
  )
}

function pushMany(c: Ctx, userUuids: string[], type: PushType, revision: number): void {
  const actor = c.var.user.uuid
  const device = actorDevice(c)
  defer(
    c,
    (async () => {
      await Promise.all(
        [...new Set(userUuids)].map((userUuid) =>
          pushUserUpdate(
            c.env,
            userUuid,
            type,
            { UserId: userUuid, Date: iso(revision) },
            userUuid === actor ? device : null,
          ),
        ),
      )
    })(),
  )
}

/** Many items changed: members refetch their ciphers. */
export const notifyCiphersChanged = (c: Ctx, members: string[], revision = Date.now()) =>
  pushMany(c, members, PushType.SyncCiphers, revision)

/** Structure changed (collections, groups, policies, membership): members run a full sync. */
export const notifyVaultChanged = (c: Ctx, members: string[], revision = Date.now()) =>
  pushMany(c, members, PushType.SyncVault, revision)

/** A member was confirmed and now holds the organisation key. */
export const notifyOrgKeys = (c: Ctx, userUuid: string, revision = Date.now()) => {
  pushMany(c, [userUuid], PushType.SyncOrgKeys, revision)
  // The relay targets organisation pushes by the organisation ids stored with each device.
  defer(c, relayRefreshUser(c.env, userUuid))
}

/**
 * Announces any successful organisation write (collections, groups, policies, members, settings)
 * as a full sync to everyone who was a member before it ran, so removed members hear it too.
 */
/**
 * Membership, group and Secrets Manager access changes alter who can reach Secrets Manager data,
 * so they mark it changed for `secrets/sync` (TASKS #220 review).
 */
export const secretsRevisionOnMemberChange: MiddlewareHandler<Env> = async (c, next) => {
  await next()
  const write = c.req.method !== 'GET' && c.req.method !== 'HEAD'
  const orgUuid = c.req.param('orgId') ?? c.req.param('id')
  if (!write || !orgUuid || !c.res.ok) return
  await createDb(c.env.DB)
    .update(schema.organizations)
    .set({ secretsRevisionDate: Date.now() })
    .where(eq(schema.organizations.uuid, orgUuid))
}

export const orgChangeNotifier: MiddlewareHandler<Env> = async (c, next) => {
  const write = c.req.method !== 'GET' && c.req.method !== 'HEAD'
  const orgUuid = c.req.param('orgId') ?? c.req.param('id')
  if (!write || !orgUuid || !c.req.header('Authorization')) return next()
  const members = await activeMemberIds(createDb(c.env.DB), orgUuid).catch(() => [])
  await next()
  if (c.res.ok && members.length > 0) {
    notifyVaultChanged(c, members)
    // Membership changes (remove, revoke, leave, delete) alter relay organisation targeting.
    if (/\/(users|leave|delete)(\/|$)/.test(c.req.path) || c.req.method === 'DELETE') {
      for (const uuid of members.slice(0, 200)) defer(c, relayRefreshUser(c.env, uuid))
    }
  }
}
