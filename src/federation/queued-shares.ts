// Shares queued behind a workspace that awaits an instance admin's approval (TASKS #382). This
// module holds the data side: counts, cancellation when the request is declined or expires, the
// admin summary and the notices. Sending happens in `sharing.ts` once the workspace is active.
import { and, eq, inArray } from 'drizzle-orm'
import { isAdminUser } from '../admin/security'
import { createDb, schema } from '../db'
import { genericEmail } from '../email'
import { sendNotice, vaultBase } from '../email/send'
import type { Bindings } from '../env'
import { FederationEvent, federationEventStatement } from './events'
import type { Peer } from './peers'

export const QueuedStatus = {
  Queued: 'queued',
  Declined: 'declined',
  Expired: 'expired',
  Dropped: 'dropped',
} as const
export type QueuedStatus = (typeof QueuedStatus)[keyof typeof QueuedStatus]

/** People queued behind one workspace request, and per requesting user. */
export const MAX_QUEUED_PER_PEER = 50
export const MAX_QUEUED_PER_USER = 20

const q = schema.federationQueuedShares

export type QueuedRow = typeof q.$inferSelect

export async function queuedRowsForPeer(env: Bindings, peerUuid: string): Promise<QueuedRow[]> {
  return createDb(env.DB)
    .select()
    .from(q)
    .where(and(eq(q.peerUuid, peerUuid), eq(q.status, QueuedStatus.Queued)))
}

export async function countQueued(
  env: Bindings,
  by: { peerUuid?: string; userUuid?: string },
): Promise<number> {
  const conds = [eq(q.status, QueuedStatus.Queued)]
  if (by.peerUuid) conds.push(eq(q.peerUuid, by.peerUuid))
  if (by.userUuid) conds.push(eq(q.requestedBy, by.userUuid))
  return (
    await createDb(env.DB)
      .select({ id: q.uuid })
      .from(q)
      .where(and(...conds))
  ).length
}

export const queuedJson = (r: QueuedRow, peerState: string | null) => ({
  object: 'queuedExternalGrantee',
  id: r.uuid,
  email: r.email,
  peerId: r.peerUuid,
  peerDomain: r.peerDomain,
  peerState,
  status: r.status,
  note: r.note,
  readOnly: r.readOnly,
  hidePasswords: r.hidePasswords,
  manage: r.manage,
})

/** Instance admins that can be told about a new request (verified, holding an instance role). */
async function instanceAdminEmails(env: Bindings): Promise<string[]> {
  const rows = await createDb(env.DB).select().from(schema.users)
  return rows.filter((u) => isAdminUser(env, u)).map((u) => u.email)
}

/** One email per instance admin when a user asks for a workspace; nothing when mail is off. */
export async function notifyAdminsOfRequest(env: Bindings, peer: Peer, requesterEmail: string) {
  for (const to of await instanceAdminEmails(env)) {
    await sendNotice(
      env,
      to,
      genericEmail(`Workspace request: ${peer.domain}`, [
        `${requesterEmail} asked to share a collection with the workspace ${peer.domain}.`,
        'Compare its fingerprint with its administrator and approve or remove the request under Instance admin, Trusted workspaces.',
        `${vaultBase(env)}/#/instance-admin/federation`,
      ]),
    )
  }
}

/** Tells a requester what happened to what they queued (best effort, silent when mail is off). */
export async function notifyRequester(
  env: Bindings,
  userUuid: string,
  domain: string,
  outcome: { sent: number; dropped: number; cancelled: 'declined' | 'expired' | null },
) {
  const [u] = await createDb(env.DB)
    .select({ email: schema.users.email })
    .from(schema.users)
    .where(eq(schema.users.uuid, userUuid))
    .limit(1)
  if (!u) return
  const lines = outcome.cancelled
    ? [
        outcome.cancelled === 'declined'
          ? `Your instance administrator declined the workspace ${domain}, so nothing you queued was sent.`
          : `The request for the workspace ${domain} expired before an administrator approved it, so nothing you queued was sent.`,
      ]
    : [
        `The workspace ${domain} was approved. ${outcome.sent} invitation(s) were sent${
          outcome.dropped > 0 ? ` and ${outcome.dropped} could not be sent` : ''
        }.`,
        `Review the access list of the collection in the web vault: ${vaultBase(env)}`,
      ]
  await sendNotice(env, u.email, genericEmail('Your external shares', lines))
}

/**
 * Cancels what is queued behind a workspace that will not be approved: its request was declined
 * (removed by an admin) or expired. The rows stay so the requesters can see what happened.
 */
export async function cancelQueuedForPeer(
  env: Bindings,
  peer: Peer,
  status: 'declined' | 'expired',
  actor: string | null,
) {
  const rows = await queuedRowsForPeer(env, peer.uuid)
  if (rows.length === 0) return
  const db = createDb(env.DB)
  const now = Date.now()
  await db
    .update(q)
    .set({ status, updatedAt: now })
    .where(
      inArray(
        q.uuid,
        rows.map((r) => r.uuid),
      ),
    )
  await federationEventStatement(db, {
    type: FederationEvent.QueuedShareCancelled,
    actingUserUuid: actor,
    peerDomain: peer.domain,
  })
  for (const userUuid of new Set(rows.map((r) => r.requestedBy))) {
    await notifyRequester(env, userUuid, peer.domain, { sent: 0, dropped: 0, cancelled: status })
  }
}

/** Per peer, what waits behind it: organisation, collections, people and who asked. */
export async function queuedSummaryByPeer(env: Bindings) {
  const db = createDb(env.DB)
  const rows = await db
    .select({
      r: q,
      orgName: schema.organizations.name,
      requester: schema.users.email,
    })
    .from(q)
    .innerJoin(schema.organizations, eq(schema.organizations.uuid, q.organizationUuid))
    .innerJoin(schema.users, eq(schema.users.uuid, q.requestedBy))
    .where(eq(q.status, QueuedStatus.Queued))
  const by = new Map<
    string,
    Map<
      string,
      {
        organizationId: string
        organizationName: string
        requestedByEmail: string
        collections: Set<string>
        people: Set<string>
      }
    >
  >()
  for (const { r, orgName, requester } of rows) {
    const groups = by.get(r.peerUuid) ?? new Map()
    const key = `${r.organizationUuid}:${r.requestedBy}`
    const g = groups.get(key) ?? {
      organizationId: r.organizationUuid,
      organizationName: orgName,
      requestedByEmail: requester,
      collections: new Set<string>(),
      people: new Set<string>(),
    }
    g.collections.add(r.collectionUuid)
    g.people.add(r.email)
    groups.set(key, g)
    by.set(r.peerUuid, groups)
  }
  const out = new Map<
    string,
    {
      organizationId: string
      organizationName: string
      requestedByEmail: string
      collections: number
      people: number
    }[]
  >()
  for (const [peer, groups] of by) {
    out.set(
      peer,
      [...groups.values()].map((g) => ({
        organizationId: g.organizationId,
        organizationName: g.organizationName,
        requestedByEmail: g.requestedByEmail,
        collections: g.collections.size,
        people: g.people.size,
      })),
    )
  }
  return out
}
