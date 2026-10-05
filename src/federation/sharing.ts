// Collection-first federated sharing (TASKS #370 to #372): the web client's Access dialog shares
// a collection with people of another workspace (a paired instance). Underneath it is still a
// federated membership holding only the granted collections; pairing is still a signed trust
// channel with pinned keys. Decisions (docs/federation.md, "Sharing a collection"):
// - sharing needs Manage on the collection (or edit any collection), like local access edits;
// - only an instance admin can activate trust: anyone else creates a pending request that an
//   instance admin approves on Admin > Federation (never from the dialog);
// - an invitation carries exactly one collection, role User, no groups, no access to all.
import { and, eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { z } from 'zod'
import { isAdminUser, rateLimit } from '../admin/security'
import { normalizeEmail } from '../auth/users'
import { createDb, runBatch, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { PushType, pushUserUpdate } from '../notifications/publish'
import { bumpOrgRevision, requireOrg } from '../orgs/access'
import { EventType, Role } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import { accessOf } from '../orgs/members'
import { requireCollectionManager } from '../routes/collections'
import { FederationEvent, federationEventStatement } from './events'
import { assertFederatable, createFederatedInvite, purgeFederatedMember } from './hosting'
import { normaliseFingerprint } from './identity'
import { addPendingPeer, approvePeerLocally, lookupPeerDescriptor } from './peer-admin'
import { getPeer, isActive, listPeers, type Peer, PeerStatus, peerByDomain } from './peers'

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
  await requireCollectionManager(db, c.var.user.uuid, orgUuid, collectionUuid)
  return {
    object: 'externalAccess',
    isInstanceAdmin: isAdminUser(c.env, c.var.user),
    // Whether the organisation may serve federated members at all (no SSO, no required 2FA).
    available: await assertFederatable(db, orgUuid).then(
      () => true,
      () => false,
    ),
    workspaces: (await listPeers(c.env)).map(workspaceJson),
    grantees: await granteesOf(c, orgUuid, collectionUuid),
  }
}

/** Shows a workspace's key fingerprint (fetched by this server) so the user can compare it. */
export async function lookupWorkspace(
  c: Ctx,
  orgUuid: string,
  collectionUuid: string,
  domain: string,
) {
  const db = createDb(c.env.DB)
  await requireCollectionManager(db, c.var.user.uuid, orgUuid, collectionUuid)
  await limit(c, `fedlookup:${c.var.user.uuid}`, LOOKUPS_PER_MINUTE, 60_000)
  const found = await lookupPeerDescriptor(c.env, domain)
  const existing = await peerByDomain(c.env, found.domain)
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
  const found = await lookupPeerDescriptor(c.env, body.domain)
  if (
    normaliseFingerprint(body.fingerprint) !== normaliseFingerprint(found.descriptor.fingerprint)
  ) {
    throw new ApiError(
      400,
      'The fingerprint does not match the key this workspace presents. Do not add it.',
    )
  }
  let peer = await peerByDomain(c.env, found.domain)
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
    }
  }
  // Trust is activated only by an instance admin, after the fingerprint check above.
  if (
    isAdmin &&
    peer.status !== PeerStatus.Suspended &&
    !(peer.localApproved && peer.remoteApproved)
  ) {
    peer = await approvePeerLocally(c.env, peer, body.fingerprint, actor.uuid)
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
  /** `invited` for a new federated member, `updated` when an existing one got or changed access. */
  result?: 'invited' | 'updated'
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
  await requireCollectionManager(db, c.var.user.uuid, orgUuid, collectionUuid)
  await limit(c, `fedshare:${c.var.user.uuid}`, GRANTS_PER_HOUR, 3_600_000)
  const org = await requireOrg(db, orgUuid)
  await assertFederatable(db, orgUuid)
  const peer = await getPeer(c.env, body.workspaceId)
  if (!peer || !isActive(peer)) {
    throw new ApiError(400, 'This workspace is not active yet. Both sides must approve it first.', {
      workspaceId: ['No active workspace.'],
    })
  }
  const access = { readOnly: body.readOnly, hidePasswords: body.hidePasswords, manage: body.manage }
  const emails = [...new Set(body.emails.map(normalizeEmail))]
  const results: ShareResult[] = []
  for (const email of emails) {
    try {
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
            actingUserUuid: c.var.user.uuid,
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
        results.push({ email, ok: true, result: 'updated', id: row.m.uuid })
        continue
      }
      const invite = await createFederatedInvite(c, orgUuid, {
        org,
        email,
        peer,
        type: Role.User,
        accessAll: false,
        collections: [{ id: collectionUuid, ...access }],
        groupIds: [],
      })
      await federationEventStatement(db, {
        type: FederationEvent.CollectionSharedExternally,
        organizationUuid: orgUuid,
        organizationUserUuid: invite.id,
        actingUserUuid: c.var.user.uuid,
        peerDomain: peer.domain,
      })
      results.push({ email, ok: true, result: 'invited', id: invite.id })
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
 * Removes the grant on this collection. When the person then holds nothing else in the
 * organisation (role User, no other collection, no group, no access to everything) the federated
 * membership is removed and the home instance is told, so the replica is purged there; otherwise
 * the home instance is told to resync.
 */
export async function removeExternalAccess(
  c: Ctx,
  orgUuid: string,
  collectionUuid: string,
  memberUuid: string,
) {
  const db = createDb(c.env.DB)
  await requireCollectionManager(db, c.var.user.uuid, orgUuid, collectionUuid)
  const row = await grantee(c, orgUuid, collectionUuid, memberUuid)
  const others = await db
    .select({ id: schema.usersCollections.collectionUuid })
    .from(schema.usersCollections)
    .where(eq(schema.usersCollections.organizationUserUuid, memberUuid))
  const groups = await db
    .select({ id: schema.groupsUsers.groupUuid })
    .from(schema.groupsUsers)
    .where(eq(schema.groupsUsers.organizationUserUuid, memberUuid))
  const holdsNothingElse =
    row.m.atype === Role.User &&
    !row.m.accessAll &&
    groups.length === 0 &&
    others.every((o) => o.id === collectionUuid)
  await federationEventStatement(db, {
    type: FederationEvent.CollectionUnsharedExternally,
    organizationUuid: orgUuid,
    organizationUserUuid: memberUuid,
    actingUserUuid: c.var.user.uuid,
  })
  if (holdsNothingElse) {
    await purgeFederatedMember(c, orgUuid, row.m, row.f)
    return { removedMember: true }
  }
  await runBatch(db, [
    db
      .delete(schema.usersCollections)
      .where(
        and(
          eq(schema.usersCollections.organizationUserUuid, memberUuid),
          eq(schema.usersCollections.collectionUuid, collectionUuid),
        ),
      ),
    eventStatement(db, c, {
      type: EventType.CollectionUpdated,
      organizationUuid: orgUuid,
      collectionUuid,
    }),
    bumpOrgRevision(db, orgUuid, Date.now()),
  ])
  if (row.m.userUuid) {
    await pushUserUpdate(c.env, row.m.userUuid, PushType.SyncVault, {
      UserId: row.m.userUuid,
      Date: new Date().toISOString(),
    })
  }
  return { removedMember: false }
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
