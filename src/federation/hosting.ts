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
import { EventType, Status } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import {
  accessOf,
  assertCanAssign,
  assertCanGrant,
  assertIdsInOrg,
  dedupeSelections,
  permissionsColumn,
  VALID_ROLES,
} from '../orgs/members'
import { listUserPolicies, policyJson, twoFactorRequired } from '../orgs/policies'
import { collectionDetailsJson, profileOrganizations } from '../orgs/views'
import { attachmentsByCipher } from '../vault/attachments'
import { FederationEvent, federationEventStatement } from './events'
import { federationEnabled } from './identity'
import { getPeer, isActive, type Peer, peerByDomain, peerJsonCall } from './peers'

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
    .refine((t) => VALID_ROLES.includes(t), 'Invalid role.'),
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
  if (await twoFactorRequired(db, orgUuid)) throw new ApiError(400, NOT_FEDERATED_2FA)
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
  await runBatch(db, [
    db.delete(schema.usersOrganizations).where(eq(schema.usersOrganizations.uuid, memberUuid)),
    eventStatement(db, c, {
      type: EventType.OrganizationUserRemoved,
      organizationUuid: orgUuid,
      organizationUserUuid: memberUuid,
      userUuid: row.m.userUuid,
    }),
  ])
  const peer = await getPeer(c.env, row.f.peerUuid)
  if (peer && isActive(peer)) {
    // Pending invitations are withdrawn; for members the push below makes the peer purge.
    await peerJsonCall(c.env, peer, `/federation/v1/invitations/${memberUuid}/revoke`, {
      body: {},
    }).catch(() => {})
    if (row.m.userUuid) await notifyPeerOfUser(c.env, row.m.userUuid, 5, {}, null)
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
  if (await twoFactorRequired(db, row.m.organizationUuid))
    throw new ApiError(400, NOT_FEDERATED_2FA)
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
        passwordHash: `!federated.${randomB64u(16)}`,
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
  return rows.map((r) => ({
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
  if (!profile) throw new ApiError(404, 'Organization not found.')
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
  /\/(sso|scim|reset-password|reset-password-enrollment|api-key|rotate-api-key|billing|subscription|license|tax|payment|import|export|auto-enroll-status|keys\/rotate|leave-sso|domain|secrets|projects|service-accounts|access-policies)(\/|$)/i

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
  const token = await signAccessToken(c.env, user, device ?? 'federation', ['api'])
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
