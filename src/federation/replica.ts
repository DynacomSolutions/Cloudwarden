// Serving side (TASKS #303, #305): the instance where the federated user has their account. It
// keeps an encrypted replica of each federated organisation (the server only ever holds the
// EncStrings the hosting side holds) and merges it into the user's sync and profile.
import { and, eq, inArray, notInArray } from 'drizzle-orm'
import { z } from 'zod'
import { normalizeEmail } from '../auth/users'
import { createDb, type Db, runBatch, schema } from '../db'
import { genericEmail } from '../email'
import { sendNotice, vaultBase } from '../email/send'
import type { Bindings, User } from '../env'
import { ApiError } from '../errors'
import { errorKind, log } from '../log'
import { PushType, pushUserUpdate } from '../notifications/publish'
import { FederationEvent, federationEventStatement } from './events'
import { isShadowUser } from './hosting'
import { baseUrl } from './identity'
import { getPeer, isActive, type Peer, peerJsonCall } from './peers'

const CIPHER_FETCH_CHUNK = 200

// ----- invitations -----

export const incomingInviteSchema = z.object({
  memberId: z.string().regex(/^[0-9a-f-]{36}$/),
  organizationId: z.string().regex(/^[0-9a-f-]{36}$/),
  organizationName: z.string().min(1).max(512),
  inviterEmail: z.string().max(256).nullish(),
  email: z.string().min(3).max(256),
})

export async function receiveInvitation(
  env: Bindings,
  peer: Peer,
  body: z.infer<typeof incomingInviteSchema>,
) {
  const db = createDb(env.DB)
  const [user] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, normalizeEmail(body.email)))
    .limit(1)
  // Stand-in accounts are never federated onwards: no chains of instances.
  if (!user || (await isShadowUser(env, user.uuid))) {
    throw new ApiError(404, 'No account with this address on the invited instance.')
  }
  const now = Date.now()
  await runBatch(db, [
    db
      .insert(schema.federationInvitations)
      .values({
        uuid: crypto.randomUUID(),
        peerUuid: peer.uuid,
        remoteMemberUuid: body.memberId,
        organizationUuid: body.organizationId,
        organizationName: body.organizationName,
        inviterEmail: body.inviterEmail ?? null,
        userUuid: user.uuid,
        status: 'pending',
        createdAt: now,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: [
          schema.federationInvitations.peerUuid,
          schema.federationInvitations.remoteMemberUuid,
        ],
        set: { status: 'pending', organizationName: body.organizationName, updatedAt: now },
      }),
    federationEventStatement(db, {
      type: FederationEvent.InvitationReceived,
      userUuid: user.uuid,
      organizationUuid: body.organizationId,
      peerDomain: peer.domain,
    }),
  ])
  await sendNotice(
    env,
    user.email,
    genericEmail(`Invitation to join ${body.organizationName}`, [
      `You have been invited to join the organisation ${body.organizationName}, hosted on ${peer.domain}.`,
      'Your account stays on this server; the organisation items appear in your vault after an administrator of the organisation confirms you.',
      `Accept or decline the invitation in the web vault: ${vaultBase(env)}/#/federation`,
    ]),
  )
  return { status: 'pending' }
}

export async function revokeInvitation(env: Bindings, peer: Peer, memberId: string) {
  await createDb(env.DB)
    .delete(schema.federationInvitations)
    .where(
      and(
        eq(schema.federationInvitations.peerUuid, peer.uuid),
        eq(schema.federationInvitations.remoteMemberUuid, memberId),
        eq(schema.federationInvitations.status, 'pending'),
      ),
    )
}

export async function listInvitations(env: Bindings, userUuid: string) {
  const rows = await createDb(env.DB)
    .select({ i: schema.federationInvitations, p: schema.federationPeers })
    .from(schema.federationInvitations)
    .innerJoin(
      schema.federationPeers,
      eq(schema.federationPeers.uuid, schema.federationInvitations.peerUuid),
    )
    .where(eq(schema.federationInvitations.userUuid, userUuid))
  return rows.map(({ i, p }) => ({
    object: 'federatedInvitation',
    id: i.uuid,
    organizationId: i.organizationUuid,
    organizationName: i.organizationName,
    inviterEmail: i.inviterEmail,
    peerDomain: p.domain,
    peerActive: isActive(p),
    status: i.status,
    creationDate: new Date(i.createdAt).toISOString(),
  }))
}

async function ownInvitation(db: Db, user: User, id: string) {
  const [inv] = await db
    .select()
    .from(schema.federationInvitations)
    .where(
      and(
        eq(schema.federationInvitations.uuid, id),
        eq(schema.federationInvitations.userUuid, user.uuid),
      ),
    )
    .limit(1)
  if (inv?.status !== 'pending') throw new ApiError(404, 'Invitation not found.')
  return inv
}

export async function respondToInvitation(env: Bindings, user: User, id: string, accept: boolean) {
  const db = createDb(env.DB)
  const inv = await ownInvitation(db, user, id)
  const peer = await getPeer(env, inv.peerUuid)
  if (!peer || !isActive(peer))
    throw new ApiError(503, "The organisation's home instance is not reachable through federation.")
  if (accept && !user.publicKey) throw new ApiError(400, 'Your account has no key pair yet.')
  try {
    await peerJsonCall(
      env,
      peer,
      `/federation/v1/invitations/${inv.remoteMemberUuid}/${accept ? 'accept' : 'decline'}`,
      {
        body: accept
          ? { userId: user.uuid, email: user.email, name: user.name, publicKey: user.publicKey }
          : {},
        user: user.uuid,
      },
    )
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      await db.delete(schema.federationInvitations).where(eq(schema.federationInvitations.uuid, id))
      throw new ApiError(404, 'The invitation is no longer valid.')
    }
    throw err
  }
  await runBatch(db, [
    db
      .update(schema.federationInvitations)
      .set({ status: accept ? 'accepted' : 'declined', updatedAt: Date.now() })
      .where(eq(schema.federationInvitations.uuid, id)),
    federationEventStatement(db, {
      type: accept ? FederationEvent.InvitationAccepted : FederationEvent.InvitationDeclined,
      userUuid: user.uuid,
      actingUserUuid: user.uuid,
      organizationUuid: inv.organizationUuid,
      peerDomain: peer.domain,
    }),
  ])
  if (accept) await syncUserFromPeer(env, user, peer)
}

// ----- replica -----

/** Rewrites the hosting side's links so clients only ever talk to their own server. */
export function rewriteLinks(text: string, env: Bindings, peer: Peer): string {
  const from = baseUrl(peer.domain)
  const own = vaultBase(env)
  return text
    .split(`${from}/attachments/`)
    .join(`${own}/federation/attachments/${peer.uuid}/`)
    .split(`${from}/`)
    .join(`${own}/`)
}

interface OrgList {
  organizations: { id: string; status: number; revisionDate: number }[]
}
interface OrgIndex {
  profile: Record<string, unknown>
  collections: unknown[]
  policies: unknown[]
  ciphers: { id: string; digest: string; revisionDate: number }[]
}

/**
 * Pulls every federated organisation the user has on `peer` (incremental: only ciphers whose
 * digest changed are fetched) and purges what the hosting side no longer lists. Returns true when
 * anything changed.
 */
export async function syncUserFromPeer(env: Bindings, user: User, peer: Peer): Promise<boolean> {
  const db = createDb(env.DB)
  const userPath = `/federation/v1/members/${user.uuid}`
  let list: OrgList
  try {
    list = await peerJsonCall<OrgList>(env, peer, `${userPath}/organizations`, {
      body: { publicKey: user.publicKey },
      user: user.uuid,
    })
  } catch (err) {
    // 404: the hosting side does not know the user any more (removed or unpaired).
    if (err instanceof ApiError && err.status === 404) list = { organizations: [] }
    else throw err
  }
  let changed = await purgeReplica(env, user.uuid, {
    peerUuid: peer.uuid,
    keep: list.organizations.map((o) => o.id),
  })
  const now = Date.now()
  for (const org of list.organizations) {
    const index = await peerJsonCall<OrgIndex>(
      env,
      peer,
      `${userPath}/organizations/${org.id}/index`,
      {
        body: {},
        user: user.uuid,
      },
    )
    const existing = await db
      .select({
        id: schema.federationReplicaCiphers.cipherUuid,
        digest: schema.federationReplicaCiphers.digest,
      })
      .from(schema.federationReplicaCiphers)
      .where(
        and(
          eq(schema.federationReplicaCiphers.userUuid, user.uuid),
          eq(schema.federationReplicaCiphers.organizationUuid, org.id),
        ),
      )
    const have = new Map(existing.map((r) => [r.id, r.digest]))
    const wanted = index.ciphers.filter((c) => have.get(c.id) !== c.digest).map((c) => c.id)
    const gone = existing.map((r) => r.id).filter((id) => !index.ciphers.some((c) => c.id === id))
    const statements: unknown[] = []
    for (let i = 0; i < wanted.length; i += CIPHER_FETCH_CHUNK) {
      const part = wanted.slice(i, i + CIPHER_FETCH_CHUNK)
      const got = await peerJsonCall<{
        ciphers: { id: string; digest: string; json: Record<string, unknown> }[]
      }>(env, peer, `${userPath}/organizations/${org.id}/ciphers`, {
        body: { ids: part },
        user: user.uuid,
      })
      for (const c of got.ciphers) {
        if (c.json.organizationId !== org.id) continue
        const json = rewriteLinks(JSON.stringify(c.json), env, peer)
        statements.push(
          db
            .insert(schema.federationReplicaCiphers)
            .values({
              userUuid: user.uuid,
              cipherUuid: c.id,
              organizationUuid: org.id,
              json,
              digest: c.digest,
              updatedAt: now,
            })
            .onConflictDoUpdate({
              target: [
                schema.federationReplicaCiphers.userUuid,
                schema.federationReplicaCiphers.cipherUuid,
              ],
              set: { json, digest: c.digest, organizationUuid: org.id, updatedAt: now },
            }),
        )
      }
    }
    for (let i = 0; i < gone.length; i += 80) {
      statements.push(
        db
          .delete(schema.federationReplicaCiphers)
          .where(
            and(
              eq(schema.federationReplicaCiphers.userUuid, user.uuid),
              inArray(schema.federationReplicaCiphers.cipherUuid, gone.slice(i, i + 80)),
            ),
          ),
      )
    }
    const profileJson = rewriteLinks(
      JSON.stringify({ ...index.profile, userId: user.uuid }),
      env,
      peer,
    )
    const collectionsJson = JSON.stringify(index.collections)
    const policiesJson = JSON.stringify(index.policies)
    const [prev] = await db
      .select()
      .from(schema.federationReplicaOrgs)
      .where(
        and(
          eq(schema.federationReplicaOrgs.userUuid, user.uuid),
          eq(schema.federationReplicaOrgs.organizationUuid, org.id),
        ),
      )
      .limit(1)
    const orgChanged =
      !prev ||
      prev.profileJson !== profileJson ||
      prev.collectionsJson !== collectionsJson ||
      prev.policiesJson !== policiesJson
    if (orgChanged || statements.length) {
      changed = true
      statements.push(
        db
          .insert(schema.federationReplicaOrgs)
          .values({
            userUuid: user.uuid,
            organizationUuid: org.id,
            peerUuid: peer.uuid,
            profileJson,
            collectionsJson,
            policiesJson,
            revisionDate: org.revisionDate,
            syncedAt: now,
          })
          .onConflictDoUpdate({
            target: [
              schema.federationReplicaOrgs.userUuid,
              schema.federationReplicaOrgs.organizationUuid,
            ],
            set: {
              profileJson,
              collectionsJson,
              policiesJson,
              revisionDate: org.revisionDate,
              syncedAt: now,
              peerUuid: peer.uuid,
            },
          }),
      )
      await runBatch(db, statements as never)
    }
  }
  if (changed) {
    await db
      .update(schema.users)
      .set({ updatedAt: Date.now() })
      .where(eq(schema.users.uuid, user.uuid))
  }
  return changed
}

/**
 * Deletes replica rows of a user: all of them, those of one peer, or those of one peer except the
 * organisations in `keep`. Returns true when something was removed.
 */
export async function purgeReplica(
  env: Bindings,
  userUuid: string,
  scope: { peerUuid?: string; keep?: string[] } = {},
): Promise<boolean> {
  const db = createDb(env.DB)
  const ro = schema.federationReplicaOrgs
  const conds = [eq(ro.userUuid, userUuid)]
  if (scope.peerUuid) conds.push(eq(ro.peerUuid, scope.peerUuid))
  if (scope.keep?.length) conds.push(notInArray(ro.organizationUuid, scope.keep))
  const orgs = await db
    .select({ id: ro.organizationUuid })
    .from(ro)
    .where(and(...conds))
  if (orgs.length === 0) return false
  const ids = orgs.map((o) => o.id)
  const ciphers = await db
    .select({ id: schema.federationReplicaCiphers.cipherUuid })
    .from(schema.federationReplicaCiphers)
    .where(
      and(
        eq(schema.federationReplicaCiphers.userUuid, userUuid),
        inArray(schema.federationReplicaCiphers.organizationUuid, ids),
      ),
    )
  const cipherIds = ciphers.map((c) => c.id)
  const statements: unknown[] = [
    db.delete(ro).where(and(eq(ro.userUuid, userUuid), inArray(ro.organizationUuid, ids))),
    db
      .delete(schema.federationReplicaCiphers)
      .where(
        and(
          eq(schema.federationReplicaCiphers.userUuid, userUuid),
          inArray(schema.federationReplicaCiphers.organizationUuid, ids),
        ),
      ),
    ...ids.map((id) =>
      federationEventStatement(db, {
        type: FederationEvent.ReplicaPurged,
        userUuid,
        organizationUuid: id,
      }),
    ),
    db.update(schema.users).set({ updatedAt: Date.now() }).where(eq(schema.users.uuid, userUuid)),
  ]
  for (let i = 0; i < cipherIds.length; i += 80) {
    statements.push(
      db
        .delete(schema.federationItemFolders)
        .where(
          and(
            eq(schema.federationItemFolders.userUuid, userUuid),
            inArray(schema.federationItemFolders.cipherUuid, cipherIds.slice(i, i + 80)),
          ),
        ),
    )
  }
  await runBatch(db, statements as never)
  return true
}

/** Users of this instance that hold anything from `peer`. */
async function usersOfPeer(env: Bindings, peerUuid: string): Promise<string[]> {
  const db = createDb(env.DB)
  const [a, b] = await Promise.all([
    db
      .select({ u: schema.federationReplicaOrgs.userUuid })
      .from(schema.federationReplicaOrgs)
      .where(eq(schema.federationReplicaOrgs.peerUuid, peerUuid)),
    db
      .select({ u: schema.federationInvitations.userUuid })
      .from(schema.federationInvitations)
      .where(
        and(
          eq(schema.federationInvitations.peerUuid, peerUuid),
          eq(schema.federationInvitations.status, 'accepted'),
        ),
      ),
  ])
  return [...new Set([...a, ...b].map((r) => r.u))]
}

async function loadUser(env: Bindings, uuid: string) {
  const [u] = await createDb(env.DB)
    .select()
    .from(schema.users)
    .where(eq(schema.users.uuid, uuid))
    .limit(1)
  return u
}

/** Tells the user's devices to resynchronise. */
async function announce(
  env: Bindings,
  userUuid: string,
  type: number = PushType.SyncVault,
  payload?: Record<string, unknown>,
  contextId: string | null = null,
) {
  const date = new Date().toISOString()
  await pushUserUpdate(
    env,
    userUuid,
    type as PushType,
    (payload as never) ?? { UserId: userUuid, Date: date },
    contextId,
  )
}

export const eventSchema = z.object({
  userId: z.string().regex(/^[0-9a-f-]{36}$/),
  type: z.number().int().min(0).max(64),
  payload: z.record(z.string(), z.unknown()).default({}),
  contextId: z.string().max(256).nullish(),
})

/** A change event from the hosting side: refresh the replica, then fan it out to the devices. */
export async function handlePeerEvent(
  env: Bindings,
  peer: Peer,
  body: z.infer<typeof eventSchema>,
) {
  if (!(await usersOfPeer(env, peer.uuid)).includes(body.userId)) {
    throw new ApiError(404, 'Unknown federated user.')
  }
  const user = await loadUser(env, body.userId)
  if (!user) throw new ApiError(404, 'Unknown federated user.')
  await syncUserFromPeer(env, user, peer)
  // Payloads carry the hosting side's ids, which are also ours: only the user id is rewritten.
  const payload = { ...body.payload, UserId: user.uuid }
  await announce(env, user.uuid, body.type, payload, body.contextId ?? null)
}

/** Pulls every peer for one user (after a forwarded write, and from the schedule). */
export async function syncUser(env: Bindings, user: User): Promise<void> {
  const db = createDb(env.DB)
  const peers = await db
    .select({ id: schema.federationReplicaOrgs.peerUuid })
    .from(schema.federationReplicaOrgs)
    .where(eq(schema.federationReplicaOrgs.userUuid, user.uuid))
  for (const id of new Set(peers.map((p) => p.id))) {
    const peer = await getPeer(env, id)
    if (peer && isActive(peer)) await syncUserFromPeer(env, user, peer)
  }
}

/** Scheduled catch-up for lost events: every user of every active peer. */
export async function resyncAll(env: Bindings): Promise<void> {
  const peers = await createDb(env.DB).select().from(schema.federationPeers)
  for (const peer of peers.filter(isActive)) {
    for (const uuid of await usersOfPeer(env, peer.uuid)) {
      const user = await loadUser(env, uuid)
      if (!user) continue
      try {
        if (await syncUserFromPeer(env, user, peer)) await announce(env, uuid)
      } catch (err) {
        log('warn', 'federation.resync_failed', { errorKind: errorKind(err) }, env)
      }
    }
  }
}

/** Unpairing or a removed peer: purge every replica that came from it and tell the devices. */
export async function dropServedForPeer(env: Bindings, peer: Peer) {
  for (const uuid of await usersOfPeer(env, peer.uuid)) {
    if (await purgeReplica(env, uuid, { peerUuid: peer.uuid })) await announce(env, uuid)
  }
}

// ----- merging into sync and profile -----

async function activeReplicaOrgs(db: Db, userUuid: string) {
  return db
    .select({ o: schema.federationReplicaOrgs })
    .from(schema.federationReplicaOrgs)
    .innerJoin(
      schema.federationPeers,
      eq(schema.federationPeers.uuid, schema.federationReplicaOrgs.peerUuid),
    )
    .where(
      and(
        eq(schema.federationReplicaOrgs.userUuid, userUuid),
        eq(schema.federationPeers.status, 'active'),
        eq(schema.federationPeers.localApproved, true),
        eq(schema.federationPeers.remoteApproved, true),
      ),
    )
}

/** Profile `organizations` entries for federated organisations (suspended peers are hidden). */
export async function federatedProfileOrgs(env: Bindings, userUuid: string): Promise<unknown[]> {
  if (env.FEDERATION_ENABLED !== 'true') return []
  const rows = await activeReplicaOrgs(createDb(env.DB), userUuid)
  return rows.map((r) => JSON.parse(r.o.profileJson))
}

export async function folderOverlay(db: Db, userUuid: string, cipherIds?: string[]) {
  const where = cipherIds
    ? and(
        eq(schema.federationItemFolders.userUuid, userUuid),
        inArray(schema.federationItemFolders.cipherUuid, cipherIds),
      )
    : eq(schema.federationItemFolders.userUuid, userUuid)
  const rows = await db.select().from(schema.federationItemFolders).where(where)
  return new Map(rows.map((r) => [r.cipherUuid, r.folderUuid]))
}

/** Collections, ciphers and policies of federated organisations for `/api/sync`. */
export async function federatedSyncData(env: Bindings, userUuid: string) {
  const empty = {
    collections: [] as unknown[],
    ciphers: [] as unknown[],
    policies: [] as unknown[],
  }
  if (env.FEDERATION_ENABLED !== 'true') return empty
  const db = createDb(env.DB)
  const orgs = await activeReplicaOrgs(db, userUuid)
  if (orgs.length === 0) return empty
  const ids = orgs.map((r) => r.o.organizationUuid)
  const [ciphers, folders] = await Promise.all([
    db
      .select({ json: schema.federationReplicaCiphers.json })
      .from(schema.federationReplicaCiphers)
      .where(
        and(
          eq(schema.federationReplicaCiphers.userUuid, userUuid),
          inArray(schema.federationReplicaCiphers.organizationUuid, ids),
        ),
      ),
    folderOverlay(db, userUuid),
  ])
  return {
    collections: orgs.flatMap((r) => JSON.parse(r.o.collectionsJson) as unknown[]),
    policies: orgs.flatMap((r) => JSON.parse(r.o.policiesJson) as unknown[]),
    ciphers: ciphers.map((c) => {
      const j = JSON.parse(c.json) as Record<string, unknown>
      return { ...j, folderId: folders.get(j.id as string) ?? null }
    }),
  }
}

/** Which of `ids` are federated items of this user, by organisation. */
export async function federatedCipherOrgs(db: Db, userUuid: string, ids: string[]) {
  const out = new Map<string, string>()
  for (let i = 0; i < ids.length; i += 80) {
    const rows = await db
      .select({
        id: schema.federationReplicaCiphers.cipherUuid,
        org: schema.federationReplicaCiphers.organizationUuid,
      })
      .from(schema.federationReplicaCiphers)
      .where(
        and(
          eq(schema.federationReplicaCiphers.userUuid, userUuid),
          inArray(schema.federationReplicaCiphers.cipherUuid, ids.slice(i, i + 80)),
        ),
      )
    for (const r of rows) out.set(r.id, r.org)
  }
  return out
}

/** The replica organisation (with its peer) of a user, if `orgUuid` is federated for them. */
export async function replicaOrg(db: Db, userUuid: string, orgUuid: string) {
  const [row] = await db
    .select({ o: schema.federationReplicaOrgs, p: schema.federationPeers })
    .from(schema.federationReplicaOrgs)
    .innerJoin(
      schema.federationPeers,
      eq(schema.federationPeers.uuid, schema.federationReplicaOrgs.peerUuid),
    )
    .where(
      and(
        eq(schema.federationReplicaOrgs.userUuid, userUuid),
        eq(schema.federationReplicaOrgs.organizationUuid, orgUuid),
      ),
    )
    .limit(1)
  return row
}

/** Federated organisations of a user with their home instance, for the user's own page. */
export async function listMemberships(env: Bindings, userUuid: string) {
  const db = createDb(env.DB)
  const rows = await db
    .select({ o: schema.federationReplicaOrgs, p: schema.federationPeers })
    .from(schema.federationReplicaOrgs)
    .innerJoin(
      schema.federationPeers,
      eq(schema.federationPeers.uuid, schema.federationReplicaOrgs.peerUuid),
    )
    .where(eq(schema.federationReplicaOrgs.userUuid, userUuid))
  return rows.map(({ o, p }) => {
    const profile = JSON.parse(o.profileJson) as { name?: string; status?: number }
    return {
      organizationId: o.organizationUuid,
      name: profile.name ?? null,
      status: profile.status ?? null,
      peerDomain: p.domain,
      peerStatus: p.status,
      syncedDate: new Date(o.syncedAt).toISOString(),
    }
  })
}
