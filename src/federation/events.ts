// Audit events for federation actions (TASKS #306). Codes sit above the admin range (9001 to
// 9008) and below anything the official clients define, which ignore unknown codes.
import { and, desc, gte, lte } from 'drizzle-orm'
import { createDb, type Db, schema } from '../db'
import type { Bindings } from '../env'

export const FederationEvent = {
  PeerAdded: 9101,
  PeerApproved: 9102,
  PeerSuspended: 9103,
  PeerResumed: 9104,
  PeerRemoved: 9105,
  PeerPairRequested: 9106,
  MemberInvited: 9110,
  InvitationReceived: 9111,
  InvitationAccepted: 9112,
  InvitationDeclined: 9113,
  MemberKeyChanged: 9114,
  ReplicaPurged: 9115,
  WriteForwarded: 9116,
  InvitationRevoked: 9117,
  CollectionSharedExternally: 9118,
  CollectionUnsharedExternally: 9119,
  PeerRequested: 9120,
  PeerAutoAccepted: 9121,
  PeerBlocked: 9122,
  PeerUnblocked: 9123,
  IncomingApprovalChanged: 9124,
  ShareQueued: 9125,
  QueuedShareSent: 9126,
  QueuedShareDropped: 9127,
  QueuedShareCancelled: 9128,
  QueuedShareEdited: 9129,
  QueuedShareRetry: 9130,
} as const

export const FEDERATION_EVENT_MIN = 9101
export const FEDERATION_EVENT_MAX = 9199

export interface FederationEventInput {
  type: number
  organizationUuid?: string | null
  userUuid?: string | null
  organizationUserUuid?: string | null
  cipherUuid?: string | null
  actingUserUuid?: string | null
  /** The peer involved, stored in the event's IP column slot as `peer:<domain>` for display. */
  peerDomain?: string | null
}

export function federationEventStatement(db: Db, e: FederationEventInput) {
  return db.insert(schema.events).values({
    uuid: crypto.randomUUID(),
    eventType: e.type,
    userUuid: e.userUuid ?? null,
    organizationUuid: e.organizationUuid ?? null,
    cipherUuid: e.cipherUuid ?? null,
    organizationUserUuid: e.organizationUserUuid ?? null,
    actingUserUuid: e.actingUserUuid ?? null,
    ipAddress: e.peerDomain ? `peer:${e.peerDomain}` : null,
    eventDate: Date.now(),
  })
}

export async function recordFederationEvent(env: Bindings, e: FederationEventInput) {
  await federationEventStatement(createDb(env.DB), e)
}

export async function listFederationEvents(env: Bindings, limit = 100) {
  const rows = await createDb(env.DB)
    .select()
    .from(schema.events)
    .where(
      and(
        gte(schema.events.eventType, FEDERATION_EVENT_MIN),
        lte(schema.events.eventType, FEDERATION_EVENT_MAX),
      ),
    )
    .orderBy(desc(schema.events.eventDate))
    .limit(limit)
  const name = Object.fromEntries(Object.entries(FederationEvent).map(([k, v]) => [v, k]))
  return rows.map((r) => ({
    type: r.eventType,
    name: name[r.eventType] ?? 'Unknown',
    organizationId: r.organizationUuid,
    userId: r.userUuid,
    organizationUserId: r.organizationUserUuid,
    actingUserId: r.actingUserUuid,
    peer: r.ipAddress?.startsWith('peer:') ? r.ipAddress.slice(5) : null,
    date: new Date(r.eventDate).toISOString(),
  }))
}
