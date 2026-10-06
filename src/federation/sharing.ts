// Collection-first federated sharing (TASKS #370 to #372): the web client's Access dialog shares
// a collection with people of another workspace (a paired instance). Underneath it is still a
// federated membership holding only the granted collections; pairing is still a signed trust
// channel with pinned keys. Decisions (docs/federation.md, "Sharing a collection"):
// - sharing needs Manage on the collection (or edit any collection), like local access edits;
// - only an instance admin can activate trust: anyone else creates a pending request that an
//   instance admin approves on Admin > Federation (never from the dialog);
// - an invitation carries exactly one collection, role User, no groups, no access to all.
import { and, eq, inArray, sql } from 'drizzle-orm'
import type { Context } from 'hono'
import { z } from 'zod'
import { isAdminUser, rateLimit } from '../admin/security'
import { normalizeEmail } from '../auth/users'
import { createDb, runBatch, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { PushType, pushUserUpdate } from '../notifications/publish'
import { bumpOrgRevision, can, isAdminRole, requireMember, requireOrg } from '../orgs/access'
import { EventType, Role, Status } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import { accessOf } from '../orgs/members'
import { requireCollectionManager } from '../routes/collections'
import { FederationEvent, federationEventStatement } from './events'
import { assertFederatable, createFederatedInvite, tellPeerMemberRemoved } from './hosting'
import { normaliseFingerprint } from './identity'
import {
  addPendingPeer,
  approvePeerLocally,
  expireWorkspaceRequests,
  lookupPeerDescriptor,
} from './peer-admin'
import {
  getPeer,
  isActive,
  listPeers,
  normaliseDomainOrThrow,
  type Peer,
  PeerStatus,
  peerByDomain,
} from './peers'
import {
  countQueued,
  MAX_QUEUED_PER_PEER,
  MAX_QUEUED_PER_USER,
  notifyAdminsOfRequest,
  notifyRequester,
  QueuedStatus,
  queuedJson,
  queuedRowsForPeer,
} from './queued-shares'

type Ctx = Context<Env>

/** Distinct states of a workspace as the dialog shows them. */
export type WorkspaceState = 'active' | 'suspended' | 'awaitingInstanceAdmin' | 'awaitingRemote'

export const workspaceState = (p: Peer): WorkspaceState =>
  p.status === PeerStatus.Suspended
    ? 'suspended'
    : isActive(p)
      ? 'active'
      : p.localApproved
        ? 'awaitingRemote'
        : 'awaitingInstanceAdmin'

const workspaceJson = (p: Peer) => ({
  id: p.uuid,
  domain: p.domain,
  fingerprint: p.fingerprint,
  state: workspaceState(p),
  active: isActive(p),
})

/**
 * What a non-instance-admin may know about a peer: active workspaces and the pending requests they
 * created. Everything else is reported only as "awaiting admin" (no state, no fingerprint).
 */
const visibleTo = (p: Peer, userUuid: string, isAdmin: boolean) =>
  isAdmin || isActive(p) || (p.requestedBy === userUuid && p.status === PeerStatus.Pending)

const AWAITING_ADMIN = { workspace: null, awaitingAdmin: true } as const

/** Emails shared in one request; each one is an outbound invitation. */
const MAX_EMAILS = 10
/** Per user and hour: new invitations or access changes made from the dialog. */
const GRANTS_PER_HOUR = 60
/** Descriptor lookups per user per minute. */
const LOOKUPS_PER_MINUTE = 20
/** Workspace requests per user per hour (non-admins create pending requests). */
const REQUESTS_PER_HOUR = 5
const ADMIN_REQUESTS_PER_HOUR = 30

const accessSchema = z.object({
  readOnly: z
    .boolean()
    .nullish()
    .transform((v) => v ?? false),
  hidePasswords: z
    .boolean()
    .nullish()
    .transform((v) => v ?? false),
  manage: z
    .boolean()
    .nullish()
    .transform((v) => v ?? false),
})

export const shareSchema = accessSchema.extend({
  workspaceId: z.string().min(1).max(64),
  emails: z.array(z.string().min(3).max(256)).min(1).max(MAX_EMAILS),
})

export const workspaceSchema = z.object({
  domain: z.string().min(1).max(260),
  fingerprint: z.string().min(1).max(200),
})

export const updateSchema = accessSchema

const limit = async (c: Ctx, key: string, n: number, windowMs: number) => {
  if (!(await rateLimit(c.env.DB, key, n, windowMs, Date.now()))) {
    throw new ApiError(429, 'Too many requests. Try again later.')
  }
}

/** Grantees of one collection: federated members that hold a grant on it. */
async function granteesOf(c: Ctx, orgUuid: string, collectionUuid: string) {
  const db = createDb(c.env.DB)
  const rows = await db
    .select({
      m: schema.usersOrganizations,
      f: schema.federationMembers,
      p: schema.federationPeers,
      uc: schema.usersCollections,
    })
    .from(schema.usersCollections)
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.uuid, schema.usersCollections.organizationUserUuid),
    )
    .innerJoin(
      schema.federationMembers,
      eq(schema.federationMembers.organizationUserUuid, schema.usersOrganizations.uuid),
    )
    .innerJoin(
      schema.federationPeers,
      eq(schema.federationPeers.uuid, schema.federationMembers.peerUuid),
    )
    .where(
      and(
        eq(schema.usersCollections.collectionUuid, collectionUuid),
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
      ),
    )
  return rows.map(({ m, f, p, uc }) => ({
    object: 'externalGrantee',
    id: m.uuid,
    userId: m.userUuid,
    email: f.remoteEmail,
    status: m.status,
    peerId: p.uuid,
    peerDomain: p.domain,
    peerState: workspaceState(p),
    readOnly: uc.readOnly,
    hidePasswords: uc.hidePasswords,
    manage: uc.manage,
  }))
}

export async function externalAccessState(c: Ctx, orgUuid: string, collectionUuid: string) {
  const db = createDb(c.env.DB)
  const actor = await requireCollectionManager(db, c.var.user.uuid, orgUuid, collectionUuid)
  await expireWorkspaceRequests(c.env)
  const isAdmin = isAdminUser(c.env, c.var.user)
  const org = await requireOrg(db, orgUuid)
  return {
    object: 'externalAccess',
    isInstanceAdmin: isAdmin,
    // New invitations need manage users, unless owners and admins let collection managers do it.
    canInvite: can(actor, 'manageUsers') || org.federationManagersInvite,
    canChangeInviteSetting: isAdminRole(actor),
    collectionManagersMayInvite: org.federationManagersInvite,
    // Whether the organisation may serve federated members at all (no SSO, no required 2FA).
    available: await assertFederatable(db, orgUuid).then(
      () => true,
      () => false,
    ),
    workspaces: (await listPeers(c.env))
      .filter((p) => visibleTo(p, c.var.user.uuid, isAdmin))
      .map(workspaceJson),
    grantees: await granteesOf(c, orgUuid, collectionUuid),
    // Shares waiting for an instance admin to approve the workspace (or that ended without it).
    queued: await queuedOf(c, orgUuid, collectionUuid),
  }
}

async function queuedOf(c: Ctx, orgUuid: string, collectionUuid: string) {
  const rows = await createDb(c.env.DB)
    .select()
    .from(schema.federationQueuedShares)
    .where(
      and(
        eq(schema.federationQueuedShares.organizationUuid, orgUuid),
        eq(schema.federationQueuedShares.collectionUuid, collectionUuid),
      ),
    )
  const peers = new Map((await listPeers(c.env)).map((p) => [p.uuid, workspaceState(p)] as const))
  return rows.map((r) => queuedJson(r, peers.get(r.peerUuid) ?? null))
}

/** Shows a workspace's key fingerprint (fetched by this server) so the user can compare it. */
export async function lookupWorkspace(
  c: Ctx,
  orgUuid: string,
  collectionUuid: string,
  input: string,
) {
  const db = createDb(c.env.DB)
  await requireCollectionManager(db, c.var.user.uuid, orgUuid, collectionUuid)
  await limit(c, `fedlookup:${c.var.user.uuid}`, LOOKUPS_PER_MINUTE, 60_000)
  const isAdmin = isAdminUser(c.env, c.var.user)
  const domain = normaliseDomainOrThrow(input)
  const existing = await peerByDomain(c.env, domain)
  if (existing && !visibleTo(existing, c.var.user.uuid, isAdmin)) {
    return { domain, fingerprint: null, ...AWAITING_ADMIN }
  }
  const found = await lookupPeerDescriptor(c.env, domain)
  return {
    domain: found.domain,
    fingerprint: found.descriptor.fingerprint,
    workspace: existing ? workspaceJson(existing) : null,
  }
}

/**
 * Adds a workspace from the dialog. The typed fingerprint must equal the one this server fetched.
 * An instance admin creates and approves the peer in one step; anyone else only creates a pending
 * request, which stays inert until an instance admin approves it on Admin > Federation. The
 * remote side always approves on its own.
 */
export async function addWorkspace(
  c: Ctx,
  orgUuid: string,
  collectionUuid: string,
  body: z.infer<typeof workspaceSchema>,
) {
  const db = createDb(c.env.DB)
  const actor = c.var.user
  await requireCollectionManager(db, actor.uuid, orgUuid, collectionUuid)
  const isAdmin = isAdminUser(c.env, actor)
  await limit(
    c,
    `fedws:${actor.uuid}`,
    isAdmin ? ADMIN_REQUESTS_PER_HOUR : REQUESTS_PER_HOUR,
    3_600_000,
  )
  await expireWorkspaceRequests(c.env)
  const domain = normaliseDomainOrThrow(body.domain)
  const known = await peerByDomain(c.env, domain)
  if (known && !visibleTo(known, actor.uuid, isAdmin)) {
    return { created: false, ...AWAITING_ADMIN }
  }
  const found = await lookupPeerDescriptor(c.env, domain)
  if (
    normaliseFingerprint(body.fingerprint) !== normaliseFingerprint(found.descriptor.fingerprint)
  ) {
    throw new ApiError(
      400,
      'The fingerprint does not match the key this workspace presents. Do not add it.',
    )
  }
  let peer = known
  if (peer && peer.publicKey !== found.descriptor.publicKey) {
    throw new ApiError(
      409,
      'This workspace now presents a different key. An administrator must remove it first.',
    )
  }
  const created = !peer
  if (!peer) {
    peer = await addPendingPeer(c.env, found.domain, actor.uuid, isAdmin ? null : actor.uuid)
    if (!isAdmin) {
      await federationEventStatement(db, {
        type: FederationEvent.PeerRequested,
        organizationUuid: orgUuid,
        actingUserUuid: actor.uuid,
        peerDomain: peer.domain,
      })
      // Instance admins are told by email (when mail is on); the page also counts open requests.
      await notifyAdminsOfRequest(c.env, peer, actor.email)
    }
  }
  // Trust is activated only by an instance admin, after the fingerprint check above.
  if (
    isAdmin &&
    peer.status !== PeerStatus.Suspended &&
    !(peer.localApproved && peer.remoteApproved)
  ) {
    peer = await approvePeerLocally(c.env, peer, body.fingerprint, actor.uuid)
    if (isActive(peer)) await flushQueuedShares(c, peer)
  }
  return { created, workspace: workspaceJson(peer) }
}

async function federatedByEmail(c: Ctx, orgUuid: string, email: string) {
  const [row] = await createDb(c.env.DB)
    .select({ m: schema.usersOrganizations, f: schema.federationMembers })
    .from(schema.usersOrganizations)
    .leftJoin(
      schema.federationMembers,
      eq(schema.federationMembers.organizationUserUuid, schema.usersOrganizations.uuid),
    )
    .where(
      and(
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
        eq(schema.usersOrganizations.email, email),
      ),
    )
    .limit(1)
  return row
}

const upsertGrant = (
  c: Ctx,
  memberUuid: string,
  collectionUuid: string,
  access: z.infer<typeof accessSchema>,
) => {
  const db = createDb(c.env.DB)
  const a = accessOf({ id: memberUuid, ...access })
  return [
    db
      .delete(schema.usersCollections)
      .where(
        and(
          eq(schema.usersCollections.organizationUserUuid, memberUuid),
          eq(schema.usersCollections.collectionUuid, collectionUuid),
        ),
      ),
    db
      .insert(schema.usersCollections)
      .values({ organizationUserUuid: memberUuid, collectionUuid, ...a }),
  ]
}

export interface ShareResult {
  email: string
  ok: boolean
  /** `invited` for a new federated member, `updated` when an existing one got or changed access, `queued` while the workspace awaits an admin. */
  result?: 'invited' | 'updated' | 'queued'
  id?: string
  error?: string
}

/**
 * Shares the collection with each address on a paired workspace. A new person gets an invitation
 * scoped to exactly this collection (role User); someone who is already a federated member of
 * the organisation only gets this collection's access added or changed.
 */
export async function shareCollection(
  c: Ctx,
  orgUuid: string,
  collectionUuid: string,
  body: z.infer<typeof shareSchema>,
): Promise<ShareResult[]> {
  const db = createDb(c.env.DB)
  const actor = await requireCollectionManager(db, c.var.user.uuid, orgUuid, collectionUuid)
  await limit(c, `fedshare:${c.var.user.uuid}`, GRANTS_PER_HOUR, 3_600_000)
  const org = await requireOrg(db, orgUuid)
  const mayInvite = can(actor, 'manageUsers') || org.federationManagersInvite
  await assertFederatable(db, orgUuid)
  const peer = await getPeer(c.env, body.workspaceId)
  const access = { readOnly: body.readOnly, hidePasswords: body.hidePasswords, manage: body.manage }
  const emails = [...new Set(body.emails.map(normalizeEmail))]
  const isAdmin = isAdminUser(c.env, c.var.user)
  // A workspace still waiting for approval takes the share into a queue: nothing is sent to the
  // peer until it is active, then each item is checked again (`flushQueuedShares`).
  if (
    peer &&
    !isActive(peer) &&
    peer.status !== PeerStatus.Suspended &&
    visibleTo(peer, c.var.user.uuid, isAdmin)
  ) {
    return queueShares(c, { orgUuid, collectionUuid, peer, emails, access, mayInvite })
  }
  if (!peer || !isActive(peer)) {
    throw new ApiError(400, 'This workspace is not active yet. Both sides must approve it first.', {
      workspaceId: ['No active workspace.'],
    })
  }
  const results: ShareResult[] = []
  for (const email of emails) {
    try {
      results.push(
        await grantOne(c, {
          orgUuid,
          collectionUuid,
          org,
          peer,
          email,
          access,
          mayInvite,
          actor: { uuid: c.var.user.uuid, email: c.var.user.email },
        }),
      )
    } catch (err) {
      results.push({
        email,
        ok: false,
        error: err instanceof ApiError ? err.message : 'The request failed.',
      })
    }
  }
  return results
}

interface GrantOneInput {
  orgUuid: string
  collectionUuid: string
  org: Awaited<ReturnType<typeof requireOrg>>
  peer: Peer
  email: string
  access: z.infer<typeof accessSchema>
  mayInvite: boolean
  actor: { uuid: string; email: string }
}

/** One address of an active workspace: invites a new person or changes an existing member's access. */
async function grantOne(c: Ctx, p: GrantOneInput): Promise<ShareResult> {
  const db = createDb(c.env.DB)
  const { orgUuid, collectionUuid, org, peer, email, access, actor } = p
  if (!/^[^\s@]+@[^\s@]+$/.test(email)) throw new ApiError(400, 'Invalid email address.')
  const row = await federatedByEmail(c, orgUuid, email)
  if (row) {
    if (!row.f || row.f.peerUuid !== peer.uuid) {
      throw new ApiError(
        400,
        row.f
          ? 'This address is already a member through another workspace.'
          : 'This address is already a member of the organisation. Use the local member list.',
      )
    }
    await runBatch(db, [
      ...upsertGrant(c, row.m.uuid, collectionUuid, access),
      federationEventStatement(db, {
        type: FederationEvent.CollectionSharedExternally,
        organizationUuid: orgUuid,
        organizationUserUuid: row.m.uuid,
        actingUserUuid: actor.uuid,
        peerDomain: peer.domain,
      }),
      bumpOrgRevision(db, orgUuid, Date.now()),
    ])
    if (row.m.userUuid) {
      await pushUserUpdate(c.env, row.m.userUuid, PushType.SyncVault, {
        UserId: row.m.userUuid,
        Date: new Date().toISOString(),
      })
    }
    return { email, ok: true, result: 'updated', id: row.m.uuid }
  }
  if (!p.mayInvite) {
    throw new ApiError(
      403,
      'Inviting new external people needs the manage users permission. Ask an owner or admin, or have them allow collection managers to invite.',
    )
  }
  const invite = await createFederatedInvite(c, orgUuid, {
    viaShare: true,
    org,
    email,
    peer,
    type: Role.User,
    accessAll: false,
    collections: [{ id: collectionUuid, ...access }],
    groupIds: [],
    actor,
  })
  await federationEventStatement(db, {
    type: FederationEvent.CollectionSharedExternally,
    organizationUuid: orgUuid,
    organizationUserUuid: invite.id,
    actingUserUuid: actor.uuid,
    peerDomain: peer.domain,
  })
  return { email, ok: true, result: 'invited', id: invite.id }
}

/** Queues shares behind a workspace that awaits approval. Nothing is sent to the peer. */
async function queueShares(
  c: Ctx,
  p: {
    orgUuid: string
    collectionUuid: string
    peer: Peer
    emails: string[]
    access: z.infer<typeof accessSchema>
    mayInvite: boolean
  },
): Promise<ShareResult[]> {
  const db = createDb(c.env.DB)
  const q = schema.federationQueuedShares
  const results: ShareResult[] = []
  for (const email of p.emails) {
    try {
      if (!/^[^\s@]+@[^\s@]+$/.test(email)) throw new ApiError(400, 'Invalid email address.')
      if (!p.mayInvite) {
        throw new ApiError(
          403,
          'Inviting new external people needs the manage users permission. Ask an owner or admin, or have them allow collection managers to invite.',
        )
      }
      if (await federatedByEmail(c, p.orgUuid, email)) {
        throw new ApiError(400, 'This address is already a member of the organisation.')
      }
      const [existing] = await db
        .select()
        .from(q)
        .where(
          and(
            eq(q.peerUuid, p.peer.uuid),
            eq(q.collectionUuid, p.collectionUuid),
            eq(q.email, email),
          ),
        )
        .limit(1)
      const now = Date.now()
      if (existing && existing.requestedBy !== c.var.user.uuid) {
        throw new ApiError(400, 'This address is already queued by someone else.')
      }
      if (!existing || existing.status !== QueuedStatus.Queued) {
        if ((await countQueued(c.env, { peerUuid: p.peer.uuid })) >= MAX_QUEUED_PER_PEER) {
          throw new ApiError(429, 'Too many people are queued for this workspace.')
        }
        if ((await countQueued(c.env, { userUuid: c.var.user.uuid })) >= MAX_QUEUED_PER_USER) {
          throw new ApiError(429, 'You have too many people waiting for an administrator.')
        }
      }
      const id = existing?.uuid ?? crypto.randomUUID()
      const values = {
        readOnly: p.access.readOnly,
        hidePasswords: p.access.hidePasswords,
        manage: p.access.manage,
        status: QueuedStatus.Queued,
        note: null,
        updatedAt: now,
      }
      await runBatch(db, [
        existing
          ? db.update(q).set(values).where(eq(q.uuid, id))
          : db.insert(q).values({
              uuid: id,
              peerUuid: p.peer.uuid,
              peerDomain: p.peer.domain,
              organizationUuid: p.orgUuid,
              collectionUuid: p.collectionUuid,
              email,
              requestedBy: c.var.user.uuid,
              createdAt: now,
              ...values,
            }),
        federationEventStatement(db, {
          type: FederationEvent.ShareQueued,
          organizationUuid: p.orgUuid,
          actingUserUuid: c.var.user.uuid,
          peerDomain: p.peer.domain,
        }),
      ])
      results.push({ email, ok: true, result: 'queued', id })
    } catch (err) {
      results.push({
        email,
        ok: false,
        error: err instanceof ApiError ? err.message : 'The request failed.',
      })
    }
  }
  return results
}

/**
 * Sends what was queued behind a workspace that has just become active. Every item is checked
 * again as of now: the requester must still manage the collection and still be allowed to invite,
 * and the organisation must still be able to serve federated members. Items that no longer qualify
 * are kept as `dropped` with the reason; the others become normal invitations.
 */
export async function flushQueuedShares(c: Ctx, activated: Peer) {
  const peer = await getPeer(c.env, activated.uuid)
  if (!peer || !isActive(peer)) return
  const rows = await queuedRowsForPeer(c.env, peer.uuid)
  if (rows.length === 0) return
  const db = createDb(c.env.DB)
  const q = schema.federationQueuedShares
  const outcome = new Map<string, { sent: number; dropped: number }>()
  for (const r of rows) {
    const tally = outcome.get(r.requestedBy) ?? { sent: 0, dropped: 0 }
    outcome.set(r.requestedBy, tally)
    try {
      const [requester] = await db
        .select()
        .from(schema.users)
        .where(eq(schema.users.uuid, r.requestedBy))
        .limit(1)
      if (!requester) throw new ApiError(400, 'The requester no longer exists.')
      const actor = await requireCollectionManager(
        db,
        r.requestedBy,
        r.organizationUuid,
        r.collectionUuid,
      )
      const org = await requireOrg(db, r.organizationUuid)
      await assertFederatable(db, r.organizationUuid)
      await grantOne(c, {
        orgUuid: r.organizationUuid,
        collectionUuid: r.collectionUuid,
        org,
        peer,
        email: r.email,
        access: { readOnly: r.readOnly, hidePasswords: r.hidePasswords, manage: r.manage },
        mayInvite: can(actor, 'manageUsers') || org.federationManagersInvite,
        actor: { uuid: requester.uuid, email: requester.email },
      })
      await runBatch(db, [
        db.delete(q).where(eq(q.uuid, r.uuid)),
        federationEventStatement(db, {
          type: FederationEvent.QueuedShareSent,
          organizationUuid: r.organizationUuid,
          actingUserUuid: r.requestedBy,
          peerDomain: peer.domain,
        }),
      ])
      tally.sent += 1
    } catch (err) {
      const note = err instanceof ApiError ? err.message.slice(0, 300) : 'It could not be sent.'
      await runBatch(db, [
        db
          .update(q)
          .set({ status: QueuedStatus.Dropped, note, updatedAt: Date.now() })
          .where(eq(q.uuid, r.uuid)),
        federationEventStatement(db, {
          type: FederationEvent.QueuedShareDropped,
          organizationUuid: r.organizationUuid,
          actingUserUuid: r.requestedBy,
          peerDomain: peer.domain,
        }),
      ])
      tally.dropped += 1
    }
  }
  for (const [userUuid, t] of outcome) {
    await notifyRequester(c.env, userUuid, peer.domain, { ...t, cancelled: null })
  }
}

/** A queued share of this collection, or 404 (the path must match, so ids cannot cross collections). */
async function queuedRow(c: Ctx, orgUuid: string, collectionUuid: string, id: string) {
  const [row] = await createDb(c.env.DB)
    .select()
    .from(schema.federationQueuedShares)
    .where(
      and(
        eq(schema.federationQueuedShares.uuid, id),
        eq(schema.federationQueuedShares.organizationUuid, orgUuid),
        eq(schema.federationQueuedShares.collectionUuid, collectionUuid),
      ),
    )
    .limit(1)
  if (!row) throw new ApiError(404, 'Queued share not found.')
  return row
}

export async function updateQueuedShare(
  c: Ctx,
  orgUuid: string,
  collectionUuid: string,
  id: string,
  access: z.infer<typeof accessSchema>,
) {
  const db = createDb(c.env.DB)
  await requireCollectionManager(db, c.var.user.uuid, orgUuid, collectionUuid)
  await limit(c, `fedshare:${c.var.user.uuid}`, GRANTS_PER_HOUR, 3_600_000)
  const row = await queuedRow(c, orgUuid, collectionUuid, id)
  if (row.status !== QueuedStatus.Queued) throw new ApiError(400, 'This share is no longer queued.')
  await db
    .update(schema.federationQueuedShares)
    .set({ ...access, updatedAt: Date.now() })
    .where(eq(schema.federationQueuedShares.uuid, id))
}

export async function removeQueuedShare(
  c: Ctx,
  orgUuid: string,
  collectionUuid: string,
  id: string,
) {
  const db = createDb(c.env.DB)
  await requireCollectionManager(db, c.var.user.uuid, orgUuid, collectionUuid)
  await limit(c, `fedshare:${c.var.user.uuid}`, GRANTS_PER_HOUR, 3_600_000)
  await queuedRow(c, orgUuid, collectionUuid, id)
  await db.delete(schema.federationQueuedShares).where(eq(schema.federationQueuedShares.uuid, id))
}

/** Loads a federated member that holds a grant on this collection, or 404. */
async function grantee(c: Ctx, orgUuid: string, collectionUuid: string, memberUuid: string) {
  const [row] = await createDb(c.env.DB)
    .select({ m: schema.usersOrganizations, f: schema.federationMembers })
    .from(schema.usersCollections)
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.uuid, schema.usersCollections.organizationUserUuid),
    )
    .innerJoin(
      schema.federationMembers,
      eq(schema.federationMembers.organizationUserUuid, schema.usersOrganizations.uuid),
    )
    .where(
      and(
        eq(schema.usersCollections.collectionUuid, collectionUuid),
        eq(schema.usersCollections.organizationUserUuid, memberUuid),
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
      ),
    )
    .limit(1)
  if (!row) throw new ApiError(404, 'External access not found.')
  return row
}

export async function updateExternalAccess(
  c: Ctx,
  orgUuid: string,
  collectionUuid: string,
  memberUuid: string,
  access: z.infer<typeof accessSchema>,
) {
  const db = createDb(c.env.DB)
  await requireCollectionManager(db, c.var.user.uuid, orgUuid, collectionUuid)
  await limit(c, `fedshare:${c.var.user.uuid}`, GRANTS_PER_HOUR, 3_600_000)
  const row = await grantee(c, orgUuid, collectionUuid, memberUuid)
  await runBatch(db, [
    ...upsertGrant(c, memberUuid, collectionUuid, access),
    bumpOrgRevision(db, orgUuid, Date.now()),
  ])
  if (row.m.userUuid) {
    await pushUserUpdate(c.env, row.m.userUuid, PushType.SyncVault, {
      UserId: row.m.userUuid,
      Date: new Date().toISOString(),
    })
  }
}

/**
 * Removes the grant on this collection (a collection manager's whole power). The federated
 * membership itself is purged only when the sharing flow created it, the person has not accepted
 * yet or is awaiting confirm (never an active member), and nothing else is held; the check and the
 * delete run in one batch with the grant removal, so a concurrent grant cannot be lost. Anything
 * else is left to people with the manage users permission.
 */
export async function removeExternalAccess(
  c: Ctx,
  orgUuid: string,
  collectionUuid: string,
  memberUuid: string,
) {
  const db = createDb(c.env.DB)
  await requireCollectionManager(db, c.var.user.uuid, orgUuid, collectionUuid)
  await limit(c, `fedshare:${c.var.user.uuid}`, GRANTS_PER_HOUR, 3_600_000)
  const row = await grantee(c, orgUuid, collectionUuid, memberUuid)
  const fm = schema.federationMembers
  const uo = schema.usersOrganizations
  await runBatch(db, [
    db
      .delete(schema.usersCollections)
      .where(
        and(
          eq(schema.usersCollections.organizationUserUuid, memberUuid),
          eq(schema.usersCollections.collectionUuid, collectionUuid),
        ),
      ),
    db
      .delete(uo)
      .where(
        and(
          eq(uo.uuid, memberUuid),
          eq(uo.organizationUuid, orgUuid),
          eq(uo.atype, Role.User),
          eq(uo.accessAll, false),
          inArray(uo.status, [Status.Invited, Status.Accepted]),
          sql`exists (select 1 from ${fm} where ${fm.organizationUserUuid} = ${memberUuid} and ${fm.createdViaShare} = 1)`,
          sql`not exists (select 1 from ${schema.usersCollections} where ${schema.usersCollections.organizationUserUuid} = ${memberUuid})`,
          sql`not exists (select 1 from ${schema.groupsUsers} where ${schema.groupsUsers.organizationUserUuid} = ${memberUuid})`,
        ),
      ),
    federationEventStatement(db, {
      type: FederationEvent.CollectionUnsharedExternally,
      organizationUuid: orgUuid,
      organizationUserUuid: memberUuid,
      actingUserUuid: c.var.user.uuid,
    }),
    eventStatement(db, c, {
      type: EventType.CollectionUpdated,
      organizationUuid: orgUuid,
      collectionUuid,
    }),
    bumpOrgRevision(db, orgUuid, Date.now()),
  ])
  const [still] = await db.select({ id: uo.uuid }).from(uo).where(eq(uo.uuid, memberUuid)).limit(1)
  if (!still) {
    await db.insert(schema.events).values({
      uuid: crypto.randomUUID(),
      eventType: EventType.OrganizationUserRemoved,
      organizationUuid: orgUuid,
      organizationUserUuid: memberUuid,
      userUuid: row.m.userUuid,
      actingUserUuid: c.var.user.uuid,
      eventDate: Date.now(),
    })
    await tellPeerMemberRemoved(c, row.m, row.f)
    return { removedMember: true }
  }
  if (row.m.userUuid) {
    await pushUserUpdate(c.env, row.m.userUuid, PushType.SyncVault, {
      UserId: row.m.userUuid,
      Date: new Date().toISOString(),
    })
  }
  return { removedMember: false }
}

/** Org-level switch: may collection managers invite new external people (default off). */
export async function setInviteSetting(c: Ctx, orgUuid: string, enabled: boolean) {
  const db = createDb(c.env.DB)
  const actor = await requireMember(db, c.var.user.uuid, orgUuid)
  if (!isAdminRole(actor)) throw new ApiError(403, 'You do not have permission to do this.')
  await runBatch(db, [
    db
      .update(schema.organizations)
      .set({ federationManagersInvite: enabled, updatedAt: Date.now() })
      .where(eq(schema.organizations.uuid, orgUuid)),
    eventStatement(db, c, { type: EventType.OrganizationUpdated, organizationUuid: orgUuid }),
  ])
  return { collectionManagersMayInvite: enabled }
}

export async function getInviteSetting(c: Ctx, orgUuid: string) {
  const db = createDb(c.env.DB)
  const actor = await requireMember(db, c.var.user.uuid, orgUuid)
  const org = await requireOrg(db, orgUuid)
  return {
    collectionManagersMayInvite: org.federationManagersInvite,
    canChange: isAdminRole(actor),
  }
}

/** Per peer: the organisations sharing with it, with counts (names of collections are encrypted). */
export async function sharingByPeer(c: Ctx) {
  const db = createDb(c.env.DB)
  const members = await db
    .select({
      peerUuid: schema.federationMembers.peerUuid,
      memberUuid: schema.usersOrganizations.uuid,
      orgUuid: schema.usersOrganizations.organizationUuid,
      orgName: schema.organizations.name,
    })
    .from(schema.federationMembers)
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.uuid, schema.federationMembers.organizationUserUuid),
    )
    .innerJoin(
      schema.organizations,
      eq(schema.organizations.uuid, schema.usersOrganizations.organizationUuid),
    )
  const grants = await db
    .select({
      memberUuid: schema.usersCollections.organizationUserUuid,
      collectionUuid: schema.usersCollections.collectionUuid,
    })
    .from(schema.usersCollections)
    .innerJoin(
      schema.federationMembers,
      eq(
        schema.federationMembers.organizationUserUuid,
        schema.usersCollections.organizationUserUuid,
      ),
    )
  const byPeer = new Map<
    string,
    Map<
      string,
      { organizationId: string; organizationName: string; people: number; collections: Set<string> }
    >
  >()
  const memberKey = new Map<string, { peer: string; orgId: string }>()
  for (const m of members) {
    const orgs = byPeer.get(m.peerUuid) ?? new Map()
    const o = orgs.get(m.orgUuid) ?? {
      organizationId: m.orgUuid,
      organizationName: m.orgName,
      people: 0,
      collections: new Set<string>(),
    }
    o.people += 1
    orgs.set(m.orgUuid, o)
    byPeer.set(m.peerUuid, orgs)
    memberKey.set(m.memberUuid, { peer: m.peerUuid, orgId: m.orgUuid })
  }
  for (const g of grants) {
    const k = memberKey.get(g.memberUuid)
    if (k) byPeer.get(k.peer)?.get(k.orgId)?.collections.add(g.collectionUuid)
  }
  const out = new Map<
    string,
    { organizationId: string; organizationName: string; people: number; collections: number }[]
  >()
  for (const [peer, orgs] of byPeer) {
    out.set(
      peer,
      [...orgs.values()].map((o) => ({
        organizationId: o.organizationId,
        organizationName: o.organizationName,
        people: o.people,
        collections: o.collections.size,
      })),
    )
  }
  return out
}

/** Federated members of an organisation that hold a grant, with the collection ids they hold. */
export async function collectionsByMember(c: Ctx, orgUuid: string) {
  const rows = await createDb(c.env.DB)
    .select({
      memberUuid: schema.usersCollections.organizationUserUuid,
      collectionUuid: schema.usersCollections.collectionUuid,
    })
    .from(schema.usersCollections)
    .innerJoin(
      schema.federationMembers,
      eq(
        schema.federationMembers.organizationUserUuid,
        schema.usersCollections.organizationUserUuid,
      ),
    )
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.uuid, schema.usersCollections.organizationUserUuid),
    )
    .where(eq(schema.usersOrganizations.organizationUuid, orgUuid))
  const out = new Map<string, string[]>()
  for (const r of rows) out.set(r.memberUuid, [...(out.get(r.memberUuid) ?? []), r.collectionUuid])
  return out
}
