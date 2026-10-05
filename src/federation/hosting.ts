// Hosting side (TASKS #302, #304): the instance that owns an organisation and serves a peer's user
// through a local stand-in ("shadow") account. Every permission check is the normal one, run as
// that account, so roles and collection access behave exactly as for local members.
import { and, eq, inArray } from 'drizzle-orm'
import type { Context } from 'hono'
import { z } from 'zod'
import { randomB64u, sha256B64u } from '../auth/crypto'
import { signAccessToken } from '../auth/session'
import { normalizeEmail } from '../auth/users'
import { createDb, type Db, runBatch, schema } from '../db'
import type { Bindings, Env, User } from '../env'
import { ApiError } from '../errors'
import { errorKind, log } from '../log'
import {
  listAccessibleCollections,
  loadUserAccess,
  requireOrg,
  requirePermission,
} from '../orgs/access'
import { listOrgCipherRows, orgCipherJson } from '../orgs/ciphers'
import { EventType, PolicyType, Role, Status } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import {
  accessOf,
  assertCanAssign,
  assertCanGrant,
  assertIdsInOrg,
  dedupeSelections,
  permissionsColumn,
  type Selection,
  VALID_ROLES,
} from '../orgs/members'
import { listUserPolicies, policyJson, twoFactorRequired } from '../orgs/policies'
import { collectionDetailsJson, profileOrganizations } from '../orgs/views'
import { attachmentsByCipher } from '../vault/attachments'
import { FederationEvent, federationEventStatement } from './events'
import { federationEnabled } from './identity'
import { getPeer, isActive, type Peer, peerByDomain, peerJsonCall } from './peers'
import { FEDERATION_CLIENT_ID, STAND_IN_HASH_PREFIX } from './standin'

type Ctx = Context<Env>

export async function shadowOf(env: Bindings, userUuid: string) {
  const [row] = await createDb(env.DB)
    .select()
    .from(schema.federationShadowUsers)
    .where(eq(schema.federationShadowUsers.userUuid, userUuid))
    .limit(1)
  return row
}

export const isShadowUser = async (env: Bindings, userUuid: string) =>
  (await shadowOf(env, userUuid)) !== undefined

// ----- invitation (org admin on the hosting side) -----

export const federatedInviteSchema = z.object({
  email: z.string().min(3).max(256),
  peerId: z.string().nullish(),
  type: z
    .number()
    .int()
    .refine((t) => VALID_ROLES.includes(t), 'Invalid role.')
    .refine((t) => t !== Role.Owner, 'Members of another server cannot be owners.'),
  accessAll: z.boolean().nullish(),
  collections: z
    .array(
      z.object({
        id: z.string().min(1),
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
      }),
    )
    .nullish(),
  groups: z.array(z.string()).nullish(),
  permissions: z.record(z.string(), z.boolean().nullable()).nullish(),
})

/**
 * Organisations whose login rules the hosting side cannot apply to a member of another server:
 * required two-step login, single sign-on (and with it trusted devices and Key Connector), and
 * the Require SSO policy.
 */
/** True when the organisation may serve federated members right now (see assertFederatable). */
export async function federatableOrg(db: Db, orgUuid: string): Promise<boolean> {
  try {
    await assertFederatable(db, orgUuid)
    return true
  } catch {
    return false
  }
}

export async function assertFederatable(db: Db, orgUuid: string) {
  if (await twoFactorRequired(db, orgUuid)) throw new ApiError(400, NOT_FEDERATED_2FA)
  const [sso] = await db
    .select({ enabled: schema.ssoConfigs.enabled })
    .from(schema.ssoConfigs)
    .where(eq(schema.ssoConfigs.organizationUuid, orgUuid))
    .limit(1)
  const [requireSso] = await db
    .select({ id: schema.policies.uuid })
    .from(schema.policies)
    .where(
      and(
        eq(schema.policies.organizationUuid, orgUuid),
        eq(schema.policies.atype, PolicyType.RequireSso),
        eq(schema.policies.enabled, true),
      ),
    )
    .limit(1)
  if (sso?.enabled || requireSso) {
    throw new ApiError(
      400,
      'This organisation uses single sign-on (or requires it), which is not available to members of another server.',
    )
  }
}

const NOT_FEDERATED_2FA =
  'This organisation requires two-step login, which cannot be verified for members of another instance.'

export async function inviteFederated(
  c: Ctx,
  orgUuid: string,
  body: z.infer<typeof federatedInviteSchema>,
) {
  const env = c.env
  const db = createDb(env.DB)
  const actor = await requirePermission(db, c.var.user.uuid, orgUuid, 'manageUsers')
  assertCanAssign(actor, body.type)
  assertCanGrant(actor, body)
  const org = await requireOrg(db, orgUuid)
  await assertFederatable(db, orgUuid)
  const email = normalizeEmail(body.email)
  if (!/^[^\s@]+@[^\s@]+$/.test(email)) {
    throw new ApiError(400, 'The request is invalid.', { email: ['Invalid email address.'] })
  }
  const peer = body.peerId
    ? await getPeer(env, body.peerId)
    : await peerByDomain(env, email.split('@')[1] as string)
  if (!peer || !isActive(peer)) {
    throw new ApiError(400, 'Choose an active federation peer for this address.', {
      peerId: ['No active peer.'],
    })
  }
  const collections = dedupeSelections(body.collections ?? [])
  const groupIds = [...new Set(body.groups ?? [])]
  if (collections.length) {
    await assertIdsInOrg(
      db,
      'collection',
      orgUuid,
      collections.map((s) => s.id),
    )
  }
  if (groupIds.length) await assertIdsInOrg(db, 'group', orgUuid, groupIds)
  return createFederatedInvite(c, orgUuid, {
    org,
    email,
    peer,
    type: body.type,
    accessAll: body.accessAll === true,
    collections,
    groupIds,
    permissions: body.permissions,
  })
}

export interface FederatedInviteInput {
  org: { name: string }
  email: string
  peer: Peer
  type: number
  accessAll: boolean
  collections: Selection[]
  groupIds: string[]
  permissions?: Record<string, boolean | null> | null
  /** Created by the collection sharing flow (a collection manager may later undo it). */
  viaShare?: boolean
}

/**
 * Creates the invited membership and asks the peer to invite the user. The caller has already
 * authorised the actor, checked `assertFederatable` and validated the collection and group ids.
 */
export async function createFederatedInvite(c: Ctx, orgUuid: string, input: FederatedInviteInput) {
  const env = c.env
  const db = createDb(env.DB)
  const { org, email, peer, collections, groupIds } = input
  const body = { type: input.type, accessAll: input.accessAll, permissions: input.permissions }
  const [local] = await db
    .select({ uuid: schema.users.uuid })
    .from(schema.users)
    .where(eq(schema.users.email, email))
    .limit(1)
  if (local && !(await isShadowUser(env, local.uuid))) {
    throw new ApiError(
      400,
      'This address has an account on this instance. Invite it as a normal member.',
    )
  }
  const [existing] = await db
    .select({ uuid: schema.usersOrganizations.uuid })
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
        eq(schema.usersOrganizations.email, email),
      ),
    )
    .limit(1)
  if (existing)
    throw new ApiError(400, 'User already invited.', { email: [`${email} is already a member.`] })

  const now = Date.now()
  const memberUuid = crypto.randomUUID()
  await runBatch(db, [
    db.insert(schema.usersOrganizations).values({
      uuid: memberUuid,
      userUuid: null,
      organizationUuid: orgUuid,
      email,
      permissions: permissionsColumn(body.type, body.permissions),
      accessAll: body.accessAll === true,
      akey: '',
      status: Status.Invited,
      atype: body.type,
      resetPasswordKey: null,
      externalId: null,
      accessSecretsManager: false,
      createdAt: now,
      updatedAt: now,
    }),
    db.insert(schema.federationMembers).values({
      organizationUserUuid: memberUuid,
      peerUuid: peer.uuid,
      remoteEmail: email,
      remoteUserUuid: null,
      createdViaShare: input.viaShare === true,
      createdAt: now,
    }),
    ...(body.accessAll
      ? []
      : collections.map((s) =>
          db.insert(schema.usersCollections).values({
            organizationUserUuid: memberUuid,
            collectionUuid: s.id,
            ...accessOf(s),
          }),
        )),
    ...groupIds.map((g) =>
      db.insert(schema.groupsUsers).values({ groupUuid: g, organizationUserUuid: memberUuid }),
    ),
    eventStatement(db, c, {
      type: EventType.OrganizationUserInvited,
      organizationUuid: orgUuid,
      organizationUserUuid: memberUuid,
    }),
    federationEventStatement(db, {
      type: FederationEvent.MemberInvited,
      organizationUuid: orgUuid,
      organizationUserUuid: memberUuid,
      actingUserUuid: c.var.user.uuid,
      peerDomain: peer.domain,
    }),
  ])
  try {
    await peerJsonCall(env, peer, '/federation/v1/invitations', {
      body: {
        memberId: memberUuid,
        organizationId: orgUuid,
        organizationName: org.name,
        inviterEmail: c.var.user.email,
        email,
      },
    })
  } catch (err) {
    await db.delete(schema.usersOrganizations).where(eq(schema.usersOrganizations.uuid, memberUuid))
    throw err
  }
  return { id: memberUuid, email, peer: peer.domain, status: Status.Invited }
}

/** Federated members of an organisation with their home instance. */
export async function listFederatedMembers(env: Bindings, orgUuid: string) {
  const rows = await createDb(env.DB)
    .select({
      m: schema.usersOrganizations,
      f: schema.federationMembers,
      p: schema.federationPeers,
    })
    .from(schema.federationMembers)
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.uuid, schema.federationMembers.organizationUserUuid),
    )
    .innerJoin(
      schema.federationPeers,
      eq(schema.federationPeers.uuid, schema.federationMembers.peerUuid),
    )
    .where(eq(schema.usersOrganizations.organizationUuid, orgUuid))
  return rows.map(({ m, f, p }) => ({
    object: 'federatedMember',
    id: m.uuid,
    userId: m.userUuid,
    email: f.remoteEmail,
    type: m.atype,
    status: m.status,
    accessAll: m.accessAll,
    peerId: p.uuid,
    peerDomain: p.domain,
    peerStatus: p.status,
  }))
}

/** Removes a federated member (any status) and tells the peer, so an open invitation disappears. */
export async function removeFederatedMember(c: Ctx, orgUuid: string, memberUuid: string) {
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, orgUuid, 'manageUsers')
  const [row] = await db
    .select({ m: schema.usersOrganizations, f: schema.federationMembers })
    .from(schema.federationMembers)
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.uuid, schema.federationMembers.organizationUserUuid),
    )
    .where(
      and(
        eq(schema.federationMembers.organizationUserUuid, memberUuid),
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
      ),
    )
    .limit(1)
  if (!row) throw new ApiError(404, 'User not found.')
  const actor = await requirePermission(db, c.var.user.uuid, orgUuid, 'manageUsers')
  assertCanAssign(actor, row.m.atype)
  await purgeFederatedMember(c, orgUuid, row.m, row.f)
}

/** Deletes a federated membership in any status and tells the peer (shared with collection sharing). */
export async function purgeFederatedMember(
  c: Ctx,
  orgUuid: string,
  m: typeof schema.usersOrganizations.$inferSelect,
  f: typeof schema.federationMembers.$inferSelect,
) {
  const db = createDb(c.env.DB)
  const memberUuid = m.uuid
  await runBatch(db, [
    db.delete(schema.usersOrganizations).where(eq(schema.usersOrganizations.uuid, memberUuid)),
    eventStatement(db, c, {
      type: EventType.OrganizationUserRemoved,
      organizationUuid: orgUuid,
      organizationUserUuid: memberUuid,
      userUuid: m.userUuid,
    }),
  ])
  await tellPeerMemberRemoved(c, m, f)
}

/** After a membership row is gone: withdraw the invitation and make the home instance purge. */
export async function tellPeerMemberRemoved(
  c: Ctx,
  m: typeof schema.usersOrganizations.$inferSelect,
  f: typeof schema.federationMembers.$inferSelect,
) {
  const peer = await getPeer(c.env, f.peerUuid)
  if (peer && isActive(peer)) {
    // Pending invitations are withdrawn; for members the push below makes the peer purge.
    await peerJsonCall(c.env, peer, `/federation/v1/invitations/${m.uuid}/revoke`, {
      body: {},
    }).catch(() => {})
    if (m.userUuid) await notifyPeerOfUser(c.env, m.userUuid, 5, {}, null)
  }
}

// ----- inbound from the serving side -----

export const acceptSchema = z.object({
  userId: z.string().regex(/^[0-9a-f-]{36}$/),
  email: z.string().min(3).max(256),
  name: z.string().max(256).nullish(),
  publicKey: z.string().min(16).max(4096),
})

async function federatedMember(db: Db, peer: Peer, memberUuid: string) {
  const [row] = await db
    .select({ m: schema.usersOrganizations, f: schema.federationMembers })
    .from(schema.federationMembers)
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.uuid, schema.federationMembers.organizationUserUuid),
    )
    .where(
      and(
        eq(schema.federationMembers.organizationUserUuid, memberUuid),
        eq(schema.federationMembers.peerUuid, peer.uuid),
      ),
    )
    .limit(1)
  return row
}

/** The peer's user accepted: create or reuse the stand-in account and mark the member accepted. */
export async function acceptFederatedInvite(
  env: Bindings,
  peer: Peer,
  memberUuid: string,
  body: z.infer<typeof acceptSchema>,
) {
  const db = createDb(env.DB)
  const row = await federatedMember(db, peer, memberUuid)
  if (!row || row.m.status !== Status.Invited) throw new ApiError(404, 'Invitation not found.')
  const email = normalizeEmail(body.email)
  if (email !== row.f.remoteEmail)
    throw new ApiError(400, 'The invitation was for another address.')
  await assertFederatable(db, row.m.organizationUuid)
  const [byId] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.uuid, body.userId))
    .limit(1)
  const shadow = byId ? await shadowOf(env, byId.uuid) : undefined
  if (byId && shadow?.peerUuid !== peer.uuid) throw new ApiError(409, 'User id conflict.')
  const [byEmail] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, email))
    .limit(1)
  if (byEmail && byEmail.uuid !== body.userId) {
    throw new ApiError(409, 'This address already has an account on the hosting instance.')
  }
  const now = Date.now()
  const statements: unknown[] = []
  if (!byId) {
    statements.push(
      db.insert(schema.users).values({
        uuid: body.userId,
        email,
        name: body.name ?? email,
        // Not a PBKDF2 output: password login can never succeed for a stand-in account.
        passwordHash: `${STAND_IN_HASH_PREFIX}${randomB64u(16)}`,
        salt: randomB64u(16),
        passwordIterations: 100_000,
        akey: '',
        publicKey: body.publicKey,
        securityStamp: crypto.randomUUID(),
        verifiedAt: now,
        verifyDevices: false,
        createdAt: now,
        updatedAt: now,
      }),
      db.insert(schema.federationShadowUsers).values({
        userUuid: body.userId,
        peerUuid: peer.uuid,
        remoteEmail: email,
        createdAt: now,
      }),
    )
  } else {
    statements.push(
      db
        .update(schema.users)
        .set({ publicKey: body.publicKey, name: body.name ?? byId.name, updatedAt: now })
        .where(eq(schema.users.uuid, byId.uuid)),
    )
    // A new key pair invalidates the organisation keys wrapped for the old one.
    if (byId.publicKey !== body.publicKey) {
      statements.push(
        db
          .update(schema.usersOrganizations)
          .set({ status: Status.Accepted, akey: '', updatedAt: now })
          .where(
            and(
              eq(schema.usersOrganizations.userUuid, byId.uuid),
              eq(schema.usersOrganizations.status, Status.Confirmed),
            ),
          ),
        federationEventStatement(db, {
          type: FederationEvent.MemberKeyChanged,
          userUuid: byId.uuid,
          peerDomain: peer.domain,
        }),
      )
    }
  }
  statements.push(
    db
      .update(schema.usersOrganizations)
      .set({ userUuid: body.userId, status: Status.Accepted, updatedAt: now })
      .where(eq(schema.usersOrganizations.uuid, memberUuid)),
    db
      .update(schema.federationMembers)
      .set({ remoteUserUuid: body.userId })
      .where(eq(schema.federationMembers.organizationUserUuid, memberUuid)),
    federationEventStatement(db, {
      type: FederationEvent.InvitationAccepted,
      organizationUuid: row.m.organizationUuid,
      organizationUserUuid: memberUuid,
      userUuid: body.userId,
      peerDomain: peer.domain,
    }),
  )
  try {
    await runBatch(db, statements as never)
  } catch {
    throw new ApiError(400, 'The user is already a member of this organisation.')
  }
  return { organizationId: row.m.organizationUuid }
}

export async function declineFederatedInvite(env: Bindings, peer: Peer, memberUuid: string) {
  const db = createDb(env.DB)
  const row = await federatedMember(db, peer, memberUuid)
  if (!row || row.m.status !== Status.Invited) throw new ApiError(404, 'Invitation not found.')
  await runBatch(db, [
    db.delete(schema.usersOrganizations).where(eq(schema.usersOrganizations.uuid, memberUuid)),
    federationEventStatement(db, {
      type: FederationEvent.InvitationDeclined,
      organizationUuid: row.m.organizationUuid,
      organizationUserUuid: memberUuid,
      peerDomain: peer.domain,
    }),
  ])
}

/** The stand-in account a signed request speaks for; it must belong to the calling peer. */
export async function requireShadow(
  env: Bindings,
  peer: Peer,
  userUuid: string | null,
): Promise<User> {
  if (!userUuid) throw new ApiError(400, 'Missing federated user.')
  const shadow = await shadowOf(env, userUuid)
  if (!shadow || shadow.peerUuid !== peer.uuid) throw new ApiError(404, 'Unknown federated user.')
  const [user] = await createDb(env.DB)
    .select()
    .from(schema.users)
    .where(eq(schema.users.uuid, userUuid))
    .limit(1)
  if (!user) throw new ApiError(404, 'Unknown federated user.')
  return user
}

const LISTED = [Status.Accepted, Status.Confirmed, Status.Revoked] as number[]

/**
 * Organisations the user belongs to here. A changed public key (the user replaced their key pair
 * at home) invalidates the wrapped organisation keys: those memberships go back to accepted and
 * an admin confirms again with the new fingerprint.
 */
export async function memberOrganizations(
  env: Bindings,
  peer: Peer,
  user: User,
  publicKey: string | null,
) {
  const db = createDb(env.DB)
  if (publicKey && publicKey !== user.publicKey) {
    const now = Date.now()
    await runBatch(db, [
      db
        .update(schema.users)
        .set({ publicKey, updatedAt: now })
        .where(eq(schema.users.uuid, user.uuid)),
      db
        .update(schema.usersOrganizations)
        .set({ status: Status.Accepted, akey: '', updatedAt: now })
        .where(
          and(
            eq(schema.usersOrganizations.userUuid, user.uuid),
            eq(schema.usersOrganizations.status, Status.Confirmed),
          ),
        ),
      federationEventStatement(db, {
        type: FederationEvent.MemberKeyChanged,
        userUuid: user.uuid,
        peerDomain: peer.domain,
      }),
    ])
  }
  const rows = await db
    .select({ m: schema.usersOrganizations, o: schema.organizations })
    .from(schema.usersOrganizations)
    .innerJoin(
      schema.organizations,
      eq(schema.organizations.uuid, schema.usersOrganizations.organizationUuid),
    )
    .where(
      and(
        eq(schema.usersOrganizations.userUuid, user.uuid),
        inArray(schema.usersOrganizations.status, LISTED),
      ),
    )
  // Organisations that turned on SSO, Require SSO or required two-step login stop serving
  // federated members at once: the serving side purges them on its next pull.
  const open: typeof rows = []
  for (const r of rows) if (await federatableOrg(db, r.o.uuid)) open.push(r)
  return open.map((r) => ({
    id: r.o.uuid,
    status: r.m.status,
    revisionDate: Math.max(r.o.updatedAt, r.m.updatedAt),
  }))
}

/** Digest of a cipher view without its short-lived attachment links. */
export async function cipherDigest(json: Record<string, unknown>): Promise<string> {
  const attachments = (json.attachments as { url?: unknown }[] | null) ?? null
  const stable = {
    ...json,
    attachments: attachments?.map(({ url: _url, ...rest }) => rest) ?? null,
  }
  return sha256B64u(JSON.stringify(stable))
}

/** The organisation exactly as the user's sync would show it here, restricted to one org. */
export async function orgView(env: Bindings, user: User, orgUuid: string) {
  const db = createDb(env.DB)
  const profile = (await profileOrganizations(db, user.uuid)).find((o) => o.id === orgUuid)
  if (!profile || !(await federatableOrg(db, orgUuid))) {
    throw new ApiError(404, 'Organization not found.')
  }
  const ua = await loadUserAccess(db, user.uuid)
  const [collections, cipherRows, policies] = await Promise.all([
    listAccessibleCollections(db, user.uuid, ua),
    listOrgCipherRows(db, user.uuid, ua),
    listUserPolicies(db, user.uuid),
  ])
  const mine = cipherRows.filter((r) => r.cipher.organizationUuid === orgUuid)
  const attachments = await attachmentsByCipher(
    env,
    db,
    mine.map((r) => r.cipher.uuid),
  )
  const ciphers = mine.map((r) => ({
    ...orgCipherJson(r, attachments.get(r.cipher.uuid) ?? null),
    // Folders are the serving side's business.
    folderId: null,
  }))
  return {
    profile,
    collections: collections
      .filter((r) => r.collection.organizationUuid === orgUuid)
      .map((r) => collectionDetailsJson(r.collection, r.access)),
    policies: policies.filter((p) => p.organizationUuid === orgUuid).map(policyJson),
    ciphers,
  }
}

// ----- forwarded client requests -----

const ORG_PATH = /^\/api\/organizations\/([0-9a-f-]{36})(\/.*)?$/
const CIPHER_PATH = /^\/api\/ciphers(\/.*)?$/
const ATTACHMENT_DOWNLOAD = /^\/attachments\/[0-9a-f-]{36}\/[A-Za-z0-9_-]+$/

/** Features that do not cross instances (docs/federation.md, "Not federated"). */
export const NOT_FEDERATED =
  /\/(sso|scim|reset-password|reset-password-enrollment|api-key|rotate-api-key|billing|subscription|license|tax|payment|import|export|auto-enroll-status|keys\/rotate|leave-sso|domain|secrets|projects|service-accounts|access-policies|integrations|event-integrations|scim-config|delete-recover|delete-recover-token)(\/|$)/i

export const NOT_FEDERATED_MESSAGE =
  'This feature is not available for organisations hosted on another instance (federated). Use the home instance of the organisation.'

function bodyOrgId(body: Uint8Array): string | null {
  try {
    const parsed = JSON.parse(new TextDecoder().decode(body)) as Record<string, unknown>
    const pick = (o: unknown) =>
      o && typeof o === 'object'
        ? ((o as Record<string, unknown>).organizationId ??
          (o as Record<string, unknown>).OrganizationId)
        : null
    const id = pick(parsed) ?? pick(parsed.cipher) ?? pick(parsed.Cipher)
    return typeof id === 'string' ? id : null
  } catch {
    return null
  }
}

/** Throws unless the forwarded call is one a federated member may make. */
export function assertForwardable(
  method: string,
  path: string,
  query: URLSearchParams,
  body: Uint8Array,
) {
  if (NOT_FEDERATED.test(path)) throw new ApiError(400, NOT_FEDERATED_MESSAGE)
  if (ATTACHMENT_DOWNLOAD.test(path) && method === 'GET') return
  if (ORG_PATH.test(path)) {
    const rest = ORG_PATH.exec(path)?.[2] ?? ''
    if (rest === '' && method !== 'GET') throw new ApiError(400, NOT_FEDERATED_MESSAGE)
    if (rest === '/delete') throw new ApiError(400, NOT_FEDERATED_MESSAGE)
    return
  }
  const m = CIPHER_PATH.exec(path)
  if (!m) throw new ApiError(403, 'This path cannot be used through federation.')
  const rest = m[1] ?? ''
  if (rest === '' && method === 'GET') throw new ApiError(403, 'Personal items are not federated.')
  if (['/import', '/move', '/share', '/archive', '/unarchive'].includes(rest)) {
    throw new ApiError(400, NOT_FEDERATED_MESSAGE)
  }
  if (rest === '/purge' && !query.get('organizationId'))
    throw new ApiError(400, NOT_FEDERATED_MESSAGE)
  if (/^\/[^/]+\/share$/.test(rest)) throw new ApiError(400, NOT_FEDERATED_MESSAGE)
  if (method === 'POST' && ['', '/create', '/admin'].includes(rest) && !bodyOrgId(body)) {
    throw new ApiError(400, 'Only organisation items can be created through federation.')
  }
}

/** The organisations a forwarded request touches: by path, query, body or cipher ids. */
async function touchedOrgs(db: Db, path: string, query: URLSearchParams, body: Uint8Array) {
  const orgs = new Set<string>()
  const org = ORG_PATH.exec(path)?.[1]
  if (org) orgs.add(org)
  const q = query.get('organizationId')
  if (q) orgs.add(q)
  const b = bodyOrgId(body)
  if (b) orgs.add(b)
  const ids: string[] = []
  const one = /^\/api\/ciphers\/([0-9a-f-]{36})(\/|$)/.exec(path)?.[1]
  if (one) ids.push(one)
  const att = /^\/attachments\/([0-9a-f-]{36})\//.exec(path)?.[1]
  if (att) ids.push(att)
  try {
    const parsed = JSON.parse(new TextDecoder().decode(body)) as { ids?: unknown }
    if (Array.isArray(parsed?.ids))
      ids.push(...parsed.ids.filter((x): x is string => typeof x === 'string'))
  } catch {
    // Not JSON (attachment uploads): the path names the item.
  }
  for (const part of chunkIds([...new Set(ids)].slice(0, 500))) {
    const rows = await db
      .select({ org: schema.ciphers.organizationUuid })
      .from(schema.ciphers)
      .where(inArray(schema.ciphers.uuid, part))
    for (const r of rows) if (r.org) orgs.add(r.org)
  }
  return orgs
}

async function assertTouchesFederatableOrgs(
  db: Db,
  path: string,
  query: URLSearchParams,
  body: Uint8Array,
) {
  for (const org of await touchedOrgs(db, path, query, body)) {
    if (!(await federatableOrg(db, org))) {
      throw new ApiError(
        400,
        'This organisation now uses single sign-on or required two-step login, which members of another server cannot use.',
      )
    }
  }
}

/** Runs a forwarded client request as the stand-in account, through the normal routes. */
export async function executeForwarded(c: Ctx, user: User, device: string | null, rest: string) {
  const url = new URL(c.req.url)
  const path = `/${rest}`
  // Dot segments or encoded separators could step outside the allowlist once the URL is parsed.
  if (new URL(path, 'https://h.invalid').pathname !== path || /%2f|%5c|\\/i.test(path)) {
    throw new ApiError(400, 'Invalid path.')
  }
  const body = c.var.federation.body
  assertForwardable(c.req.method, path, url.searchParams, body)
  await assertTouchesFederatableOrgs(createDb(c.env.DB), path, url.searchParams, body)
  const token = await signAccessToken(
    c.env,
    user,
    device ?? 'federation',
    ['api'],
    FEDERATION_CLIENT_ID,
  )
  const headers = new Headers({ authorization: `Bearer ${token}`, 'device-type': '14' })
  const ct = c.req.header('content-type')
  if (ct) headers.set('content-type', ct)
  const target = new Request(`${c.env.DOMAIN.replace(/\/+$/, '')}${path}${url.search}`, {
    method: c.req.method,
    headers,
    body: c.req.method === 'GET' || c.req.method === 'HEAD' ? undefined : body,
  })
  const { app } = await import('../index')
  let ctx: ExecutionContext | undefined
  try {
    ctx = c.executionCtx as ExecutionContext
  } catch {
    ctx = undefined
  }
  const res = await app.fetch(target, c.env, ctx)
  const out = new Headers()
  for (const h of ['content-type', 'content-disposition', 'content-length']) {
    const v = res.headers.get(h)
    if (v) out.set(h, v)
  }
  out.set('cache-control', 'no-store')
  return new Response(res.body, { status: res.status, headers: out })
}

// ----- change events to the serving side -----

/**
 * Hook for `pushUserUpdate`: a push meant for a stand-in account goes to its home instance as a
 * signed event instead of to sockets. Returns true when the user is a stand-in (handled here).
 */
export async function notifyPeerOfUser(
  env: Bindings,
  userUuid: string,
  type: number,
  payload: Record<string, unknown>,
  contextId: string | null,
): Promise<boolean> {
  if (!federationEnabled(env)) return false
  const shadow = await shadowOf(env, userUuid).catch(() => undefined)
  if (!shadow) return false
  const peer = await getPeer(env, shadow.peerUuid)
  if (!peer || !isActive(peer)) return true
  try {
    await peerJsonCall(env, peer, '/federation/v1/events', {
      body: { userId: userUuid, type, payload, contextId },
      user: userUuid,
    })
  } catch (err) {
    // The serving side also resynchronises on a schedule, so a lost event only delays changes.
    log('warn', 'federation.event_failed', { errorKind: errorKind(err) }, env)
  }
  return true
}

/** Removes everything a peer's users hold here: stand-in accounts and open invitations. */
export async function dropHostedForPeer(env: Bindings, peer: Peer) {
  const db = createDb(env.DB)
  const members = await db
    .select({ id: schema.federationMembers.organizationUserUuid })
    .from(schema.federationMembers)
    .where(eq(schema.federationMembers.peerUuid, peer.uuid))
  const shadows = await db
    .select({ id: schema.federationShadowUsers.userUuid })
    .from(schema.federationShadowUsers)
    .where(eq(schema.federationShadowUsers.peerUuid, peer.uuid))
  const statements: unknown[] = []
  for (const part of chunkIds(members.map((m) => m.id))) {
    statements.push(
      db.delete(schema.usersOrganizations).where(inArray(schema.usersOrganizations.uuid, part)),
    )
  }
  for (const part of chunkIds(shadows.map((s) => s.id))) {
    statements.push(db.delete(schema.users).where(inArray(schema.users.uuid, part)))
  }
  if (statements.length) await runBatch(db, statements as never)
}

const chunkIds = (ids: string[], size = 80) => {
  const out: string[][] = []
  for (let i = 0; i < ids.length; i += size) out.push(ids.slice(i, i + size))
  return out
}
