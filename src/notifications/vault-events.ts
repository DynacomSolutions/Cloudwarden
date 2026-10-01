import type { Context } from 'hono'
import type { Env } from '../env'
import { PushType, pushUserUpdate } from './publish'

type Ctx = Context<Env>

/** Above this many ids, a bulk change is announced as one SyncCiphers instead of one event each. */
const MAX_INDIVIDUAL_EVENTS = 10

/**
 * Runs a push after the response without delaying it. Falls back to a detached promise
 * when the request has no execution context (direct `app.fetch` calls).
 */
function defer(c: Ctx, work: Promise<void>): void {
  try {
    c.executionCtx.waitUntil(work)
  } catch {
    void work
  }
}

const iso = (ms: number) => new Date(ms).toISOString()

/** Tells the user's other devices about cipher changes. The requesting device is excluded. */
export function notifyCiphers(c: Ctx, type: PushType, ids: string[], revision: number): void {
  const user = c.var.user
  const device = c.var.auth.deviceIdentifier
  if (ids.length > MAX_INDIVIDUAL_EVENTS) {
    defer(
      c,
      pushUserUpdate(
        c.env,
        user.uuid,
        PushType.SyncCiphers,
        { UserId: user.uuid, Date: iso(revision) },
        device,
      ),
    )
    return
  }
  for (const id of ids) {
    defer(
      c,
      pushUserUpdate(
        c.env,
        user.uuid,
        type,
        {
          Id: id,
          UserId: user.uuid,
          OrganizationId: null,
          CollectionIds: null,
          RevisionDate: iso(revision),
        },
        device,
      ),
    )
  }
}

export const notifyCipher = (c: Ctx, type: PushType, id: string, revision: number) =>
  notifyCiphers(c, type, [id], revision)

export function notifyFolder(c: Ctx, type: PushType, id: string, revision: number): void {
  const user = c.var.user
  defer(
    c,
    pushUserUpdate(
      c.env,
      user.uuid,
      type,
      { Id: id, UserId: user.uuid, RevisionDate: iso(revision) },
      c.var.auth.deviceIdentifier,
    ),
  )
}

/** User-level events: SyncVault, SyncCiphers, SyncSettings. */
export function notifyUser(c: Ctx, type: PushType, revision: number): void {
  const user = c.var.user
  defer(
    c,
    pushUserUpdate(
      c.env,
      user.uuid,
      type,
      { UserId: user.uuid, Date: iso(revision) },
      c.var.auth.deviceIdentifier,
    ),
  )
}
