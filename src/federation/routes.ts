// Federation HTTP surface (TASKS #300 to #306):
// - `/.well-known/cloudwarden-federation`: public instance descriptor;
// - `/federation/v1/*`: signed server-to-server API (docs/federation.md, "Protocol");
// - `/federation/attachments/*`: attachment downloads relayed from a hosting instance;
// - `/api/cloudwarden/federation/*`: the web client's pages (instance admin, org admin, user).
import { eq } from 'drizzle-orm'
import { type Context, Hono } from 'hono'
import { z } from 'zod'
import { isAdminUser, rateLimit } from '../admin/security'
import { requireAuth } from '../auth/middleware'
import { createDb, runBatch, schema } from '../db'
import type { Bindings, Env } from '../env'
import { ApiError } from '../errors'
import { PushType, pushUserUpdate } from '../notifications/publish'
import { requireMember } from '../orgs/access'
import { canListMembers } from '../orgs/members'
import { parseBody } from '../validation'
import { FederationEvent, federationEventStatement, listFederationEvents } from './events'
import {
  acceptFederatedInvite,
  acceptSchema,
  cipherDigest,
  declineFederatedInvite,
  dropHostedForPeer,
  executeForwarded,
  federatedInviteSchema,
  inviteFederated,
  listFederatedMembers,
  memberOrganizations,
  orgView,
  removeFederatedMember,
  requireShadow,
} from './hosting'
import {
  baseUrl,
  descriptor,
  federationEnabled,
  ownDomain,
  requireFederation,
  WELL_KNOWN_PATH,
} from './identity'
import { safeFetch } from './net'
import {
  addPendingPeer,
  approvePeerLocally,
  assertPendingRoom,
  expireWorkspaceRequests,
  nextStatus,
  setPeer,
} from './peer-admin'
import {
  claimNonce,
  fetchDescriptor,
  getPeer,
  isActive,
  listPeers,
  normaliseDomainOrThrow,
  PAIR_RATE_LIMIT,
  type Peer,
  PeerStatus,
  peerByDomain,
  peerFetch,
  peerJson,
  requirePeer,
  verifyInbound,
} from './peers'
import { cancelQueuedForPeer, queuedSummaryByPeer } from './queued-shares'
import {
  dropServedForPeer,
  eventSchema,
  handlePeerEvent,
  incomingInviteSchema,
  listInvitations,
  listMemberships,
  receiveInvitation,
  respondToInvitation,
  revokeInvitation,
} from './replica'
import {
  addWorkspace,
  collectionsByMember,
  externalAccessState,
  flushQueuedShares,
  getInviteSetting,
  lookupWorkspace,
  removeExternalAccess,
  removeQueuedShare,
  setInviteSetting,
  shareCollection,
  shareSchema,
  sharingByPeer,
  updateExternalAccess,
  updateQueuedShare,
  updateSchema,
  workspaceSchema,
} from './sharing'
import { parseSignature } from './signature'
import {
  blockDomain,
  isBlockedDomain,
  listBlockedDomains,
  MAX_AUTO_ACCEPTED_PEERS,
  requireIncomingApproval,
  setRequireIncomingApproval,
  unblockDomain,
} from './trust-settings'

type Ctx = Context<Env>

export const federation = new Hono<Env>()

/** Relayed attachment downloads per client address per minute. */
const ATTACHMENT_RATE_LIMIT = 120
/** Pairing requests per minute across the instance. */
const PAIR_GLOBAL_LIMIT = 30

const fedBody = <S extends z.ZodType>(c: Ctx, s: S): z.infer<S> => {
  let raw: unknown
  try {
    raw = JSON.parse(new TextDecoder().decode(c.var.federation.body) || '{}')
  } catch {
    throw new ApiError(400, 'Invalid JSON.')
  }
  const r = s.safeParse(raw)
  if (!r.success) throw new ApiError(400, 'The request is invalid.')
  return r.data
}

// ----- public descriptor -----

federation.get(WELL_KNOWN_PATH, async (c) => {
  if (!federationEnabled(c.env)) return c.json({ message: 'Not found', object: 'error' }, 404)
  c.header('Cache-Control', 'public, max-age=300')
  return c.json(await descriptor(c.env))
})

// ----- pairing (signed by a peer that may not be known yet) -----

federation.post('/federation/v1/pair', async (c) => {
  requireFederation(c.env)
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown'
  if (!(await rateLimit(c.env.DB, `fedpair:${ip}`, PAIR_RATE_LIMIT, 60_000, Date.now()))) {
    throw new ApiError(429, 'Too many pairing requests.')
  }
  if (!(await rateLimit(c.env.DB, 'fedpair:all', PAIR_GLOBAL_LIMIT, 60_000, Date.now()))) {
    throw new ApiError(429, 'Too many pairing requests.')
  }
  const parsed = parseSignature(c.req.raw.headers)
  if (!parsed) throw new ApiError(401, 'Missing or malformed federation signature.')
  const body = new Uint8Array(await c.req.raw.arrayBuffer())
  let claimed: { domain?: unknown }
  try {
    claimed = JSON.parse(new TextDecoder().decode(body))
  } catch {
    throw new ApiError(400, 'Invalid JSON.')
  }
  const domain = normaliseDomainOrThrow(String(claimed.domain ?? ''))
  // A blocked domain is refused before anything is fetched or stored.
  if (await isBlockedDomain(c.env, domain)) throw new ApiError(403, 'This domain is blocked.')
  // The key is bound to the domain by fetching the caller's descriptor over https.
  const d = await fetchDescriptor(c.env, domain)
  if (d.instanceId !== parsed.params.keyid)
    throw new ApiError(401, 'Key id does not match the peer.')
  const nonce = await verifyInbound(c, d.publicKey, body)
  // The nonce is spent before anything is written, so a replayed pairing request changes nothing.
  // The peer row may not exist yet, so the nonce lives in the rate limit table (limit 1).
  if (
    !(await rateLimit(c.env.DB, `fedpairnonce:${d.instanceId}:${nonce}`, 1, 3_600_000, Date.now()))
  ) {
    throw new ApiError(401, 'Replayed federation request.')
  }
  const db = createDb(c.env.DB)
  const now = Date.now()
  let peer = await peerByDomain(c.env, domain)
  if (peer && (peer.instanceId !== d.instanceId || peer.publicKey !== d.publicKey)) {
    throw new ApiError(
      409,
      'This domain is paired with a different key. An administrator must remove the peer first.',
    )
  }
  if (!peer) {
    const [byId] = await db
      .select()
      .from(schema.federationPeers)
      .where(eq(schema.federationPeers.instanceId, d.instanceId))
      .limit(1)
    if (byId) throw new ApiError(409, 'This instance is already paired under another domain.')
    // The key was bound to the domain by the https descriptor above, so without the admin setting
    // the peer is trusted at once: it can only send invitations that users must accept. A cap
    // keeps the number of automatic peers small; beyond it requests wait for an admin.
    const autoCount = (await listPeers(c.env)).filter((p) => p.acceptedAutomatically).length
    const auto = !(await requireIncomingApproval(c.env)) && autoCount < MAX_AUTO_ACCEPTED_PEERS
    if (!auto) await assertPendingRoom(c.env)
    const uuid = crypto.randomUUID()
    await runBatch(db, [
      db.insert(schema.federationPeers).values({
        uuid,
        instanceId: d.instanceId,
        domain,
        publicKey: d.publicKey,
        fingerprint: d.fingerprint,
        protocolVersion: d.version,
        status: auto ? PeerStatus.Active : PeerStatus.Pending,
        localApproved: auto,
        acceptedAutomatically: auto,
        remoteApproved: true,
        lastSeenAt: now,
        createdAt: now,
        updatedAt: now,
      }),
      federationEventStatement(db, {
        type: auto ? FederationEvent.PeerAutoAccepted : FederationEvent.PeerPairRequested,
        peerDomain: domain,
      }),
    ])
    peer = (await getPeer(c.env, uuid)) as Peer
  } else {
    const status = nextStatus({ ...peer, remoteApproved: true })
    await db
      .update(schema.federationPeers)
      .set({ remoteApproved: true, status, lastSeenAt: now, updatedAt: now })
      .where(eq(schema.federationPeers.uuid, peer.uuid))
  }
  await claimNonce(c.env, peer.uuid, nonce)
  // The peer may now be active (its admin approved while ours had already): send what is queued.
  await flushQueuedShares(c, peer)
  return c.json({
    instanceId: (await descriptor(c.env)).instanceId,
    localApproved: peer.localApproved,
  })
})

// ----- signed API -----

federation.use('/federation/v1/*', async (c, next) => {
  if (c.req.path === '/federation/v1/pair') return next()
  return requirePeer(c, next)
})

federation.post('/federation/v1/ping', (c) =>
  c.json({ ok: true, domain: ownDomain(c.env), time: new Date().toISOString() }),
)

federation.post('/federation/v1/unpair', async (c) => {
  await dropPeer(c.env, c.var.federation.peer, null)
  return c.json({ ok: true })
})

// Serving side: an organisation on the peer invites one of our users.
federation.post('/federation/v1/invitations', async (c) =>
  c.json(await receiveInvitation(c.env, c.var.federation.peer, fedBody(c, incomingInviteSchema))),
)

federation.post('/federation/v1/invitations/:id/revoke', async (c) => {
  await revokeInvitation(c.env, c.var.federation.peer, c.req.param('id'))
  return c.json({ ok: true })
})

// Hosting side: the peer's user answered our invitation.
federation.post('/federation/v1/invitations/:id/accept', async (c) => {
  const body = fedBody(c, acceptSchema)
  if (c.var.federation.user !== body.userId) throw new ApiError(400, 'Federated user mismatch.')
  return c.json(await acceptFederatedInvite(c.env, c.var.federation.peer, c.req.param('id'), body))
})

federation.post('/federation/v1/invitations/:id/decline', async (c) => {
  await declineFederatedInvite(c.env, c.var.federation.peer, c.req.param('id'))
  return c.json({ ok: true })
})

// Serving side: a change on the hosting side.
federation.post('/federation/v1/events', async (c) => {
  const body = fedBody(c, eventSchema)
  if (c.var.federation.user !== body.userId) throw new ApiError(400, 'Federated user mismatch.')
  await handlePeerEvent(c.env, c.var.federation.peer, body)
  return c.json({ ok: true })
})

const shadowFor = async (c: Ctx) => {
  const id = c.req.param('userId') ?? ''
  if (c.var.federation.user !== id) throw new ApiError(400, 'Federated user mismatch.')
  return requireShadow(c.env, c.var.federation.peer, id)
}

// Hosting side: replica pulls.
federation.post('/federation/v1/members/:userId/organizations', async (c) => {
  const user = await shadowFor(c)
  const { publicKey } = fedBody(c, z.object({ publicKey: z.string().max(4096).nullish() }))
  return c.json({
    organizations: await memberOrganizations(c.env, c.var.federation.peer, user, publicKey ?? null),
  })
})

federation.post('/federation/v1/members/:userId/organizations/:orgId/index', async (c) => {
  const user = await shadowFor(c)
  const view = await orgView(c.env, user, c.req.param('orgId'))
  return c.json({
    profile: view.profile,
    collections: view.collections,
    policies: view.policies,
    ciphers: await Promise.all(
      view.ciphers.map(async (j) => ({
        id: j.id,
        digest: await cipherDigest(j as never),
        revisionDate: j.revisionDate,
      })),
    ),
  })
})

federation.post('/federation/v1/members/:userId/organizations/:orgId/ciphers', async (c) => {
  const user = await shadowFor(c)
  const { ids } = fedBody(c, z.object({ ids: z.array(z.string()).max(500) }))
  const want = new Set(ids)
  const view = await orgView(c.env, user, c.req.param('orgId'))
  const picked = view.ciphers.filter((j) => want.has(j.id))
  return c.json({
    ciphers: await Promise.all(
      picked.map(async (j) => ({ id: j.id, digest: await cipherDigest(j as never), json: j })),
    ),
  })
})

// Hosting side: a client request of the peer's user, run as their stand-in account.
federation.all('/federation/v1/members/:userId/proxy/*', async (c) => {
  const user = await shadowFor(c)
  const prefix = `/federation/v1/members/${user.uuid}/proxy/`
  const rest = c.req.path.slice(prefix.length)
  return executeForwarded(c, user, c.var.federation.device, rest)
})

// ----- attachment downloads relayed from a hosting instance -----

federation.get('/federation/attachments/:peerId/:cipherId/:attachmentId', async (c) => {
  requireFederation(c.env)
  const ip = c.req.header('CF-Connecting-IP') ?? 'unknown'
  if (!(await rateLimit(c.env.DB, `fedatt:${ip}`, ATTACHMENT_RATE_LIMIT, 60_000, Date.now()))) {
    throw new ApiError(429, 'Too many requests.')
  }
  const peer = await getPeer(c.env, c.req.param('peerId'))
  if (!peer || !isActive(peer)) throw new ApiError(404, 'Not found')
  const cipherId = c.req.param('cipherId')
  const attachmentId = c.req.param('attachmentId')
  if (!/^[0-9a-f-]{36}$/.test(cipherId) || !/^[A-Za-z0-9_-]+$/.test(attachmentId)) {
    throw new ApiError(404, 'Not found')
  }
  const token = c.req.query('token') ?? ''
  const res = await safeFetch(
    c.env,
    new Request(
      `${baseUrl(peer.domain)}/attachments/${cipherId}/${attachmentId}?token=${encodeURIComponent(token)}`,
    ),
  )
  // Never the peer's own type or disposition: the bytes are encrypted, and a peer must not be
  // able to serve active content from this origin.
  const headers = new Headers({
    'cache-control': 'no-store',
    'content-type': 'application/octet-stream',
    'content-disposition': 'attachment',
    'content-security-policy': "sandbox; default-src 'none'",
    'x-content-type-options': 'nosniff',
  })
  const length = res.headers.get('content-length')
  if (length && /^\d+$/.test(length)) headers.set('content-length', length)
  if (!res.ok) {
    await res.body?.cancel()
    return c.json(
      { message: 'Attachment not available.', object: 'error' },
      res.status === 404 ? 404 : 502,
    )
  }
  return new Response(res.body, { status: 200, headers })
})

// ----- peer lifecycle shared by the admin API and the unpair call -----

/** Users of this instance holding replicas from the peer get a resync so clients add or drop it. */
async function announcePeerUsers(env: Bindings, peer: Peer) {
  const rows = await createDb(env.DB)
    .select({ u: schema.federationReplicaOrgs.userUuid })
    .from(schema.federationReplicaOrgs)
    .where(eq(schema.federationReplicaOrgs.peerUuid, peer.uuid))
  const now = Date.now()
  for (const u of new Set(rows.map((r) => r.u))) {
    await createDb(env.DB)
      .update(schema.users)
      .set({ updatedAt: now })
      .where(eq(schema.users.uuid, u))
    await pushUserUpdate(env, u, PushType.SyncVault, {
      UserId: u,
      Date: new Date(now).toISOString(),
    })
  }
}

/** Removes a peer and everything tied to it on this instance. */
async function dropPeer(env: Bindings, peer: Peer, actor: string | null) {
  // A request that never became active is declined: what was queued behind it is cancelled.
  if (!isActive(peer)) await cancelQueuedForPeer(env, peer, 'declined', actor)
  await dropServedForPeer(env, peer)
  await dropHostedForPeer(env, peer)
  const db = createDb(env.DB)
  await runBatch(db, [
    db.delete(schema.federationPeers).where(eq(schema.federationPeers.uuid, peer.uuid)),
    federationEventStatement(db, {
      type: FederationEvent.PeerRemoved,
      actingUserUuid: actor,
      peerDomain: peer.domain,
    }),
  ])
}

// ----- web client API -----

const UI = '/api/cloudwarden/federation'

federation.use(`${UI}/*`, async (c, next) => {
  c.header('Cache-Control', 'no-store')
  await next()
})
federation.use(`${UI}/*`, async (c, next) => {
  requireFederation(c.env)
  await next()
})
federation.use(`${UI}/*`, requireAuth)

/** Whether federation is on, and the active peers an org admin can invite from. */
federation.get(`${UI}/status`, async (c) => {
  const all = await listPeers(c.env)
  const peers = all.filter(isActive)
  const isAdmin = isAdminUser(c.env, c.var.user)
  return c.json({
    enabled: true,
    domain: ownDomain(c.env),
    isInstanceAdmin: isAdmin,
    // Workspaces waiting for an instance admin's decision (shown as a count in the admin nav).
    pendingRequests: isAdmin
      ? all.filter((p) => p.status === PeerStatus.Pending && !p.localApproved).length
      : 0,
    peers: peers.map((p) => ({ id: p.uuid, domain: p.domain })),
  })
})

const requireInstanceAdmin = async (c: Ctx) => {
  if (!(await rateLimit(c.env.DB, `adminapi:${c.var.user.uuid}`, 120, 60_000, Date.now()))) {
    throw new ApiError(429, 'Too many requests. Try again later.')
  }
  if (!isAdminUser(c.env, c.var.user)) throw new ApiError(403, 'Forbidden')
}

const ADMIN = `${UI}/admin`

federation.get(`${ADMIN}/identity`, async (c) => {
  await requireInstanceAdmin(c)
  return c.json(await descriptor(c.env))
})

federation.get(`${ADMIN}/peers`, async (c) => {
  await requireInstanceAdmin(c)
  await expireWorkspaceRequests(c.env)
  const sharing = await sharingByPeer(c)
  const queued = await queuedSummaryByPeer(c.env)
  const db = createDb(c.env.DB)
  const peers = await listPeers(c.env)
  const data = await Promise.all(
    peers.map(async (p) => {
      let requestedByEmail: string | null = null
      if (p.requestedBy) {
        const [u] = await db
          .select({ email: schema.users.email })
          .from(schema.users)
          .where(eq(schema.users.uuid, p.requestedBy))
          .limit(1)
        requestedByEmail = u?.email ?? null
      }
      let approvedByEmail: string | null = null
      if (p.approvedBy) {
        const [u] = await db
          .select({ email: schema.users.email })
          .from(schema.users)
          .where(eq(schema.users.uuid, p.approvedBy))
          .limit(1)
        approvedByEmail = u?.email ?? null
      }
      return {
        ...(await peerJson(p)),
        requestedByEmail,
        approvedByEmail,
        sharing: sharing.get(p.uuid) ?? [],
        queued: queued.get(p.uuid) ?? [],
      }
    }),
  )
  return c.json({ object: 'list', data })
})

federation.post(`${ADMIN}/peers`, async (c) => {
  await requireInstanceAdmin(c)
  const { domain } = await parseBody(c, z.object({ domain: z.string().min(1).max(260) }))
  return c.json(await peerJson(await addPendingPeer(c.env, domain, c.var.user.uuid, null)))
})

const adminPeer = async (c: Ctx) => {
  await requireInstanceAdmin(c)
  const peer = await getPeer(c.env, c.req.param('id') ?? '')
  if (!peer) throw new ApiError(404, 'Peer not found.')
  return peer
}

/**
 * Approves a peer after the admin compared its fingerprint out of band, then asks the peer to
 * record our approval. The peer is active once both sides approved.
 */
federation.post(`${ADMIN}/peers/:id/approve`, async (c) => {
  const peer = await adminPeer(c)
  const { fingerprint } = await parseBody(c, z.object({ fingerprint: z.string().min(1).max(200) }))
  const approved = await approvePeerLocally(c.env, peer, fingerprint, c.var.user.uuid)
  // Shares queued behind the request are sent now, each checked again.
  if (isActive(approved)) await flushQueuedShares(c, approved)
  return c.json(await peerJson(approved))
})

federation.post(`${ADMIN}/peers/:id/suspend`, async (c) => {
  const peer = await setPeer(c.env, await adminPeer(c), { status: PeerStatus.Suspended })
  await federationEventStatement(createDb(c.env.DB), {
    type: FederationEvent.PeerSuspended,
    actingUserUuid: c.var.user.uuid,
    peerDomain: peer.domain,
  })
  await announcePeerUsers(c.env, peer)
  return c.json(await peerJson(peer))
})

federation.post(`${ADMIN}/peers/:id/resume`, async (c) => {
  const before = await adminPeer(c)
  const peer = await setPeer(c.env, before, {
    status: nextStatus({ ...before, status: PeerStatus.Pending }),
  })
  await federationEventStatement(createDb(c.env.DB), {
    type: FederationEvent.PeerResumed,
    actingUserUuid: c.var.user.uuid,
    peerDomain: peer.domain,
  })
  await announcePeerUsers(c.env, peer)
  return c.json(await peerJson(peer))
})

/** Health: a signed ping for active peers, the public descriptor otherwise. */
federation.post(`${ADMIN}/peers/:id/check`, async (c) => {
  const peer = await adminPeer(c)
  const started = Date.now()
  try {
    if (peer && isActive(peer)) {
      const res = await peerFetch(c.env, peer, '/federation/v1/ping', { body: {} })
      if (!res.ok) throw new ApiError(502, `HTTP ${res.status}`)
    } else {
      const d = await fetchDescriptor(c.env, peer.domain)
      if (d.publicKey !== peer.publicKey) throw new ApiError(409, 'The peer key changed.')
    }
    return c.json({
      ok: true,
      latencyMs: Date.now() - started,
      peer: await peerJson((await getPeer(c.env, peer.uuid)) as Peer),
    })
  } catch (err) {
    return c.json({
      ok: false,
      error: err instanceof ApiError ? err.message : 'unreachable',
      peer: await peerJson((await getPeer(c.env, peer.uuid)) as Peer),
    })
  }
})

federation.delete(`${ADMIN}/peers/:id`, async (c) => {
  const peer = await adminPeer(c)
  if (peer && isActive(peer)) {
    await peerFetch(c.env, peer, '/federation/v1/unpair', { body: {} }).catch(() => {})
  }
  await dropPeer(c.env, peer, c.var.user.uuid)
  // Without a block the removed workspace could pair again at once; "block" refuses its requests.
  if (c.req.query('block') === 'true') await blockWithEvent(c, peer.domain)
  return c.body(null, 200)
})

async function blockWithEvent(c: Ctx, domain: string) {
  await blockDomain(c.env, domain, c.var.user.uuid)
  await federationEventStatement(createDb(c.env.DB), {
    type: FederationEvent.PeerBlocked,
    actingUserUuid: c.var.user.uuid,
    peerDomain: domain,
  })
}

federation.get(`${ADMIN}/settings`, async (c) => {
  await requireInstanceAdmin(c)
  return c.json({
    requireIncomingApproval: await requireIncomingApproval(c.env),
    blockedDomains: await listBlockedDomains(c.env),
  })
})

federation.put(`${ADMIN}/settings`, async (c) => {
  await requireInstanceAdmin(c)
  const { requireIncomingApproval: value } = await parseBody(
    c,
    z.object({ requireIncomingApproval: z.boolean() }),
  )
  await setRequireIncomingApproval(c.env, value, c.var.user.uuid)
  await federationEventStatement(createDb(c.env.DB), {
    type: FederationEvent.IncomingApprovalChanged,
    actingUserUuid: c.var.user.uuid,
  })
  return c.json({ requireIncomingApproval: value })
})

federation.post(`${ADMIN}/blocked`, async (c) => {
  await requireInstanceAdmin(c)
  const { domain } = await parseBody(c, z.object({ domain: z.string().min(1).max(260) }))
  const d = normaliseDomainOrThrow(domain)
  if (d === ownDomain(c.env)) throw new ApiError(400, 'This instance cannot block itself.')
  await blockWithEvent(c, d)
  // A blocked domain that is still a peer is removed.
  const peer = await peerByDomain(c.env, d)
  if (peer) await dropPeer(c.env, peer, c.var.user.uuid)
  return c.json({ blockedDomains: await listBlockedDomains(c.env) })
})

federation.delete(`${ADMIN}/blocked/:domain`, async (c) => {
  await requireInstanceAdmin(c)
  const d = normaliseDomainOrThrow(c.req.param('domain') ?? '')
  await unblockDomain(c.env, d)
  await federationEventStatement(createDb(c.env.DB), {
    type: FederationEvent.PeerUnblocked,
    actingUserUuid: c.var.user.uuid,
    peerDomain: d,
  })
  return c.json({ blockedDomains: await listBlockedDomains(c.env) })
})

federation.get(`${ADMIN}/events`, async (c) => {
  await requireInstanceAdmin(c)
  return c.json({ object: 'list', data: await listFederationEvents(c.env) })
})

// Organisation admins on the hosting side.

federation.get(`${UI}/organizations/:orgId/members`, async (c) => {
  const orgUuid = c.req.param('orgId')
  const member = await requireMember(createDb(c.env.DB), c.var.user.uuid, orgUuid)
  if (!canListMembers(member)) throw new ApiError(403, 'You do not have permission to do this.')
  const held = await collectionsByMember(c, orgUuid)
  const data = (await listFederatedMembers(c.env, orgUuid)).map((m) => ({
    ...m,
    collectionIds: held.get(m.id) ?? [],
  }))
  return c.json({ object: 'list', data })
})

federation.post(`${UI}/organizations/:orgId/members`, async (c) => {
  const body = await parseBody(c, federatedInviteSchema)
  return c.json(await inviteFederated(c, c.req.param('orgId'), body))
})

federation.delete(`${UI}/organizations/:orgId/members/:id`, async (c) => {
  await removeFederatedMember(c, c.req.param('orgId'), c.req.param('id'))
  return c.body(null, 200)
})

// Collection-first sharing (docs/federation.md, "Sharing a collection"): everything is scoped to a
// collection the caller can manage.

const EXT = `${UI}/organizations/:orgId/collections/:colId/external-access`

federation.get(EXT, async (c) =>
  c.json(await externalAccessState(c, c.req.param('orgId'), c.req.param('colId'))),
)

federation.post(`${EXT}/workspaces/lookup`, async (c) => {
  const { domain } = await parseBody(c, z.object({ domain: z.string().min(1).max(260) }))
  return c.json(await lookupWorkspace(c, c.req.param('orgId'), c.req.param('colId'), domain))
})

federation.post(`${EXT}/workspaces`, async (c) =>
  c.json(
    await addWorkspace(
      c,
      c.req.param('orgId'),
      c.req.param('colId'),
      await parseBody(c, workspaceSchema),
    ),
  ),
)

federation.get(`${UI}/organizations/:orgId/settings`, async (c) =>
  c.json(await getInviteSetting(c, c.req.param('orgId'))),
)

federation.put(`${UI}/organizations/:orgId/settings`, async (c) => {
  const { collectionManagersMayInvite } = await parseBody(
    c,
    z.object({ collectionManagersMayInvite: z.boolean() }),
  )
  return c.json(await setInviteSetting(c, c.req.param('orgId'), collectionManagersMayInvite))
})

federation.post(EXT, async (c) =>
  c.json({
    object: 'list',
    data: await shareCollection(
      c,
      c.req.param('orgId'),
      c.req.param('colId'),
      await parseBody(c, shareSchema),
    ),
  }),
)

federation.put(`${EXT}/queued/:id`, async (c) => {
  await updateQueuedShare(
    c,
    c.req.param('orgId'),
    c.req.param('colId'),
    c.req.param('id'),
    await parseBody(c, updateSchema),
  )
  return c.body(null, 200)
})

federation.delete(`${EXT}/queued/:id`, async (c) => {
  await removeQueuedShare(c, c.req.param('orgId'), c.req.param('colId'), c.req.param('id'))
  return c.body(null, 200)
})

federation.put(`${EXT}/:memberId`, async (c) => {
  await updateExternalAccess(
    c,
    c.req.param('orgId'),
    c.req.param('colId'),
    c.req.param('memberId'),
    await parseBody(c, updateSchema),
  )
  return c.body(null, 200)
})

federation.delete(`${EXT}/:memberId`, async (c) =>
  c.json(
    await removeExternalAccess(
      c,
      c.req.param('orgId'),
      c.req.param('colId'),
      c.req.param('memberId'),
    ),
  ),
)

// The invited user on the serving side.

federation.get(`${UI}/invitations`, async (c) =>
  c.json({ object: 'list', data: await listInvitations(c.env, c.var.user.uuid) }),
)

federation.post(`${UI}/invitations/:id/accept`, async (c) => {
  await respondToInvitation(c.env, c.var.user, c.req.param('id'), true)
  return c.body(null, 200)
})

federation.post(`${UI}/invitations/:id/decline`, async (c) => {
  await respondToInvitation(c.env, c.var.user, c.req.param('id'), false)
  return c.body(null, 200)
})

federation.get(`${UI}/memberships`, async (c) =>
  c.json({ object: 'list', data: await listMemberships(c.env, c.var.user.uuid) }),
)
