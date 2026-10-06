// Peer lifecycle steps shared by the instance admin API and the collection Access dialog
// (TASKS #302, #371). Trust is only ever activated through `approvePeerLocally`, which callers
// reach after checking the instance admin role.
import { and, eq, inArray, lt } from 'drizzle-orm'
import { createDb, runBatch, schema } from '../db'
import type { Bindings } from '../env'
import { ApiError } from '../errors'
import { FederationEvent, federationEventStatement } from './events'
import { normaliseFingerprint, ownDomain } from './identity'
import {
  fetchDescriptor,
  getPeer,
  listPeers,
  normaliseDomainOrThrow,
  type Peer,
  PeerStatus,
  peerByDomain,
  peerJsonCall,
} from './peers'
import { cancelQueuedForPeer } from './queued-shares'
import {
  forgetRemoved,
  INCOMING_TTL_MS,
  isBlocked,
  MAX_AUTO_ACCEPTED_PEERS,
  MAX_INCOMING_PENDING,
} from './trust-settings'

/**
 * Peers waiting for approval that an admin added or that arrived as a signed pairing request;
 * further ones are refused. Requests made by non-admins from the Access dialog have their own,
 * smaller caps below and do not count here.
 */
export const MAX_PENDING_PEERS = 20
/** Open non-admin workspace requests across the instance, and per user. */
export const MAX_USER_REQUESTS = 5
export const MAX_USER_REQUESTS_PER_USER = 2
/** A non-admin request nobody approved is dropped after this long. */
export const REQUEST_TTL_MS = 7 * 24 * 3_600_000

const isOpenRequest = (p: Peer) =>
  p.requestedBy !== null && p.status === PeerStatus.Pending && !p.localApproved

export async function assertPendingRoom(env: Bindings) {
  // Peers an admin added; incoming requests have their own caps (trust-settings.ts).
  const pending = (await listPeers(env)).filter(
    (p) => p.status === PeerStatus.Pending && p.requestedBy === null && !p.incoming,
  )
  if (pending.length >= MAX_PENDING_PEERS) {
    throw new ApiError(429, 'Too many peers are waiting for approval.')
  }
}

/** Drops non-admin requests nobody approved within the time to live. */
export async function expireWorkspaceRequests(env: Bindings, now = Date.now()) {
  const db = createDb(env.DB)
  const stale = (await listPeers(env)).filter(
    (p) =>
      (isOpenRequest(p) && p.createdAt < now - REQUEST_TTL_MS) ||
      // Incoming requests nobody approved are dropped too.
      (p.incoming &&
        p.status === PeerStatus.Pending &&
        !p.localApproved &&
        p.createdAt < now - INCOMING_TTL_MS),
  )
  for (const p of stale) {
    // What was queued behind the request is cancelled and its requesters are told.
    await cancelQueuedForPeer(env, p, 'expired', null)
    await db.delete(schema.federationPeers).where(eq(schema.federationPeers.uuid, p.uuid))
  }
  // Whatever sits in a queue for more than a week is cancelled, whichever peer it waits behind.
  const old = await db
    .select({ uuid: schema.federationQueuedShares.uuid })
    .from(schema.federationQueuedShares)
    .where(
      and(
        inArray(schema.federationQueuedShares.status, ['queued', 'retry']),
        lt(schema.federationQueuedShares.createdAt, now - REQUEST_TTL_MS),
      ),
    )
  if (old.length > 0) {
    await db
      .update(schema.federationQueuedShares)
      .set({ status: 'expired', updatedAt: now })
      .where(
        inArray(
          schema.federationQueuedShares.uuid,
          old.map((r) => r.uuid),
        ),
      )
  }
  // Finished queue entries are kept for a month so requesters can see what happened.
  await db
    .delete(schema.federationQueuedShares)
    .where(
      and(
        inArray(schema.federationQueuedShares.status, ['declined', 'expired', 'dropped']),
        lt(schema.federationQueuedShares.updatedAt, now - 30 * 24 * 3_600_000),
      ),
    )
}

async function assertRequestRoom(env: Bindings, userUuid: string) {
  const open = (await listPeers(env)).filter(isOpenRequest)
  if (open.length >= MAX_USER_REQUESTS) {
    throw new ApiError(429, 'Too many workspace requests are waiting for an administrator.')
  }
  if (open.filter((p) => p.requestedBy === userUuid).length >= MAX_USER_REQUESTS_PER_USER) {
    throw new ApiError(429, 'You already have workspace requests waiting for an administrator.')
  }
}

/** Status after an approval change; suspension is only lifted explicitly. */
export const nextStatus = (p: Pick<Peer, 'status' | 'localApproved' | 'remoteApproved'>) =>
  p.status === PeerStatus.Suspended
    ? PeerStatus.Suspended
    : p.localApproved && p.remoteApproved
      ? PeerStatus.Active
      : PeerStatus.Pending

export async function setPeer(env: Bindings, peer: Peer, patch: Partial<Peer>) {
  const merged = { ...peer, ...patch }
  const status = patch.status ?? nextStatus(merged)
  await createDb(env.DB)
    .update(schema.federationPeers)
    .set({ ...patch, status, updatedAt: Date.now() })
    .where(eq(schema.federationPeers.uuid, peer.uuid))
  return (await getPeer(env, peer.uuid)) as Peer
}

/** Fetches the descriptor of `input` for display; nothing is stored. */
export async function lookupPeerDescriptor(env: Bindings, input: string) {
  const domain = checkedDomain(env, input)
  return { domain, descriptor: await fetchDescriptor(env, domain) }
}

function checkedDomain(env: Bindings, input: string) {
  const domain = normaliseDomainOrThrow(input)
  if (domain === ownDomain(env)) throw new ApiError(400, 'An instance cannot pair with itself.')
  return domain
}

/** Records a pending peer (neither side approved). `requestedBy` is set for non-admin requests. */
export async function addPendingPeer(
  env: Bindings,
  input: string,
  actorUuid: string,
  requestedBy: string | null,
): Promise<Peer> {
  const domain = checkedDomain(env, input)
  if (requestedBy) await assertRequestRoom(env, requestedBy)
  else await assertPendingRoom(env)
  if (await isBlocked(env, { domain })) throw new ApiError(400, 'This domain is blocked.')
  if (await peerByDomain(env, domain)) throw new ApiError(400, 'This peer already exists.')
  const d = await fetchDescriptor(env, domain)
  if (await isBlocked(env, { domain, instanceId: d.instanceId, fingerprint: d.fingerprint })) {
    throw new ApiError(400, 'This workspace is blocked.')
  }
  const db = createDb(env.DB)
  const [byId] = await db
    .select()
    .from(schema.federationPeers)
    .where(eq(schema.federationPeers.instanceId, d.instanceId))
    .limit(1)
  if (byId) throw new ApiError(400, 'This instance is already paired under another domain.')
  const now = Date.now()
  const uuid = crypto.randomUUID()
  await runBatch(db, [
    db.insert(schema.federationPeers).values({
      uuid,
      instanceId: d.instanceId,
      domain,
      publicKey: d.publicKey,
      fingerprint: d.fingerprint,
      protocolVersion: d.version,
      status: PeerStatus.Pending,
      localApproved: false,
      remoteApproved: false,
      requestedBy,
      createdAt: now,
      updatedAt: now,
    }),
    federationEventStatement(db, {
      type: FederationEvent.PeerAdded,
      actingUserUuid: actorUuid,
      peerDomain: domain,
    }),
  ])
  return (await getPeer(env, uuid)) as Peer
}

/**
 * Approves a peer after a fingerprint check, then asks the peer to record our approval. The peer
 * is active once both sides approved. Callers must have established that the actor is an
 * instance admin.
 */
export async function approvePeerLocally(
  env: Bindings,
  peer: Peer,
  fingerprint: string,
  actorUuid: string,
): Promise<Peer> {
  if (normaliseFingerprint(fingerprint) !== normaliseFingerprint(peer.fingerprint)) {
    throw new ApiError(
      400,
      'The fingerprint does not match the peer key. Do not approve this peer.',
    )
  }
  // The key must still be the one the admin checked.
  const d = await fetchDescriptor(env, peer.domain)
  if (d.publicKey !== peer.publicKey) {
    throw new ApiError(409, 'The peer now presents a different key. Remove it and add it again.')
  }
  let next = await setPeer(env, peer, { localApproved: true, approvedBy: actorUuid })
  await forgetRemoved(env, peer.domain)
  await federationEventStatement(createDb(env.DB), {
    type: FederationEvent.PeerApproved,
    actingUserUuid: actorUuid,
    peerDomain: next.domain,
  })
  const res = await peerJsonCall<{ localApproved: boolean }>(env, next, '/federation/v1/pair', {
    body: { domain: ownDomain(env) },
    allowInactive: true,
  })
  if (res?.localApproved) next = await setPeer(env, next, { remoteApproved: true })
  return next
}

/**
 * Records the peer of an incoming signed pairing request. The caps are part of the insert
 * statement, so concurrent requests cannot overshoot them: automatic peers (inbound only) at most
 * `MAX_AUTO_ACCEPTED_PEERS`, waiting incoming requests at most `MAX_INCOMING_PENDING`; peers an
 * admin added are not counted. Returns the new peer's uuid.
 */
export async function insertIncomingPeer(
  env: Bindings,
  p: {
    instanceId: string
    domain: string
    publicKey: string
    fingerprint: string
    protocolVersion: number
    wantAuto: boolean
  },
): Promise<string> {
  const uuid = crypto.randomUUID()
  const now = Date.now()
  const insert = async (auto: boolean) => {
    const cap = auto
      ? '(select count(*) from federation_peers where incoming = 1 and accepted_automatically = 1 and approved_by is null) < ?11'
      : "(select count(*) from federation_peers where incoming = 1 and status = 'pending' and local_approved = 0) < ?11"
    const r = await env.DB.prepare(
      `insert into federation_peers (uuid, instance_id, domain, public_key, fingerprint, protocol_version, status, local_approved, accepted_automatically, incoming, remote_approved, last_seen_at, created_at, updated_at)
       select ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 1, 1, ?9, ?9, ?10 where ${cap}`,
    )
      .bind(
        uuid,
        p.instanceId,
        p.domain,
        p.publicKey,
        p.fingerprint,
        p.protocolVersion,
        auto ? PeerStatus.Active : PeerStatus.Pending,
        auto ? 1 : 0,
        now,
        now,
        auto ? MAX_AUTO_ACCEPTED_PEERS : MAX_INCOMING_PENDING,
      )
      .run()
    return (r.meta?.changes ?? 0) > 0
  }
  let auto = false
  if (p.wantAuto && (await insert(true))) auto = true
  else if (!(await insert(false))) {
    throw new ApiError(429, 'Too many peers are waiting for approval.')
  }
  await federationEventStatement(createDb(env.DB), {
    type: auto ? FederationEvent.PeerAutoAccepted : FederationEvent.PeerPairRequested,
    peerDomain: p.domain,
  })
  return uuid
}
