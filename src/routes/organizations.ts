import { and, eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { canCreateOrganizations } from '../admin/security'
import { verifyMasterPassword } from '../auth/passwords'
import { createDb, runBatch, schema } from '../db'
import { later } from '../email/send'
import type { Env } from '../env'
import { ApiError } from '../errors'
import {
  bumpOrgRevision,
  getMember,
  isAdminRole,
  requireMember,
  requireOrg,
  requireOwner,
} from '../orgs/access'
import { dropMemberStateFor } from '../orgs/ciphers'
import { EventType, Role, Status } from '../orgs/constants'
import { assertNotClaimed } from '../orgs/domains'
import { eventStatement } from '../orgs/events'
import { assertNotLastOwner } from '../orgs/members'
import { authOnce } from '../orgs/util'
import { orgJson, profileOrganizations } from '../orgs/views'
import { parseBody } from '../validation'
import { deleteBlobs } from '../vault/blobs'
import { bumpRevision } from '../vault/ciphers'

export const organizations = new Hono<Env>()
organizations.use('/api/organizations', authOnce)
organizations.use('/api/organizations/*', authOnce)

type Ctx = Context<Env>

const keysSchema = z.object({
  publicKey: z.string().min(1),
  encryptedPrivateKey: z.string().min(1),
})

const createSchema = z.object({
  name: z.string().min(1).max(50),
  billingEmail: z.string().min(1).max(256),
  key: z.string().min(1),
  keys: keysSchema.nullish(),
  collectionName: z.string().nullish(),
  planType: z.number().int().nullish(),
})

// The caller's memberships, shaped like the profile `organizations` array.
organizations.get('/api/organizations', async (c) =>
  c.json({
    data: await profileOrganizations(createDb(c.env.DB), c.var.user.uuid),
    object: 'list',
    continuationToken: null,
  }),
)

// Members read the organisation public key to encrypt keys for it (reset password, key rotation).
organizations.get('/api/organizations/:id/public-key', async (c) => {
  const db = createDb(c.env.DB)
  const org = await requireOrg(db, c.req.param('id'))
  await requireMember(db, c.var.user.uuid, org.uuid)
  return c.json({ object: 'organizationPublicKey', publicKey: org.publicKey })
})

/**
 * Creates an organisation with the caller as its confirmed owner. Only holders of an instance role
 * (owner or admin) with a verified address may: invite links can register accounts, so organisation
 * creation is not open to everyone.
 */
export const createOrganization = async (c: Ctx) => {
  if (!canCreateOrganizations(c.env, c.var.user)) {
    throw new ApiError(403, 'Only instance administrators can create organisations.')
  }
  const body = await parseBody(c, createSchema)
  const db = createDb(c.env.DB)
  const user = c.var.user
  const orgUuid = crypto.randomUUID()
  const memberUuid = crypto.randomUUID()
  const now = Date.now()
  const collectionUuid = body.collectionName ? crypto.randomUUID() : null
  await runBatch(db, [
    db.insert(schema.organizations).values({
      uuid: orgUuid,
      name: body.name,
      billingEmail: body.billingEmail.trim().toLowerCase(),
      publicKey: body.keys?.publicKey ?? null,
      privateKey: body.keys?.encryptedPrivateKey ?? null,
      createdAt: now,
      updatedAt: now,
    }),
    db.insert(schema.usersOrganizations).values({
      uuid: memberUuid,
      userUuid: user.uuid,
      organizationUuid: orgUuid,
      email: user.email,
      accessAll: true,
      accessSecretsManager: true,
      akey: body.key,
      status: Status.Confirmed,
      atype: Role.Owner,
      createdAt: now,
      updatedAt: now,
    }),
    ...(collectionUuid
      ? [
          db.insert(schema.collections).values({
            uuid: collectionUuid,
            organizationUuid: orgUuid,
            name: body.collectionName as string,
            createdAt: now,
            updatedAt: now,
          }),
          db.insert(schema.usersCollections).values({
            organizationUserUuid: memberUuid,
            collectionUuid,
            readOnly: false,
            hidePasswords: false,
            manage: true,
          }),
        ]
      : []),
    bumpRevision(db, user.uuid, now),
  ])
  return c.json(orgJson(await requireOrg(db, orgUuid)))
}
organizations.post('/api/organizations', createOrganization)
// A self-hosted server takes no payment for any plan, so this is ordinary creation (TASKS #231).
organizations.post('/api/organizations/create-without-payment', createOrganization)

/** Details, settings and keys need an owner, an admin or a custom member. */
async function requireManager(c: Ctx, orgUuid: string) {
  const db = createDb(c.env.DB)
  const m = await requireMember(db, c.var.user.uuid, orgUuid)
  if (m.atype === Role.User || m.atype === Role.Manager) {
    throw new ApiError(403, 'You do not have permission to do this.')
  }
  return m
}

// The SDK reads the organisation private key (encrypted with the organisation key) to build an
// invite link; owners, admins and custom members only. Not in NOT_FEDERATED, like `/keys`.
organizations.get('/api/organizations/:id/private-key', async (c) => {
  const id = c.req.param('id')
  await requireManager(c, id)
  const org = await requireOrg(createDb(c.env.DB), id)
  return c.json({ object: 'organizationPrivateKey', privateKey: org.privateKey })
})

organizations.get('/api/organizations/:id', async (c) => {
  const id = c.req.param('id')
  await requireManager(c, id)
  return c.json(orgJson(await requireOrg(createDb(c.env.DB), id)))
})

const updateSchema = z.object({
  name: z.string().min(1).max(50).nullish(),
  billingEmail: z.string().min(1).max(256).nullish(),
  keys: keysSchema.nullish(),
})
const updateOrg = async (c: Ctx) => {
  const id = c.req.param('id') ?? ''
  const body = await parseBody(c, updateSchema)
  const db = createDb(c.env.DB)
  const m = await requireManager(c, id)
  if (!isAdminRole(m)) throw new ApiError(403, 'You do not have permission to do this.')
  const org = await requireOrg(db, id)
  const billingChanged =
    !!body.billingEmail && body.billingEmail.trim().toLowerCase() !== org.billingEmail
  // The billing address receives the deletion link, so only an owner may change it.
  if (billingChanged && m.atype !== Role.Owner) {
    throw new ApiError(403, 'Only owners can change the billing email.')
  }
  const now = Date.now()
  await runBatch(db, [
    db
      .update(schema.organizations)
      .set({
        name: body.name ?? org.name,
        billingEmail: body.billingEmail ? body.billingEmail.trim().toLowerCase() : org.billingEmail,
        // A new billing address voids deletion links already mailed.
        ...(billingChanged ? { deleteNonce: null } : {}),
        // Keys are write-once: an organisation that already has them keeps them.
        ...(body.keys && !org.publicKey
          ? { publicKey: body.keys.publicKey, privateKey: body.keys.encryptedPrivateKey }
          : {}),
        updatedAt: now,
      })
      .where(eq(schema.organizations.uuid, id)),
    eventStatement(db, c, { type: EventType.OrganizationUpdated, organizationUuid: id }),
    bumpOrgRevision(db, id, now),
  ])
  return c.json(orgJson(await requireOrg(db, id)))
}
organizations.put('/api/organizations/:id', updateOrg)
organizations.post('/api/organizations/:id', updateOrg)

/**
 * Deletes an organisation with its members' links, events and attachment blobs. Federated
 * invitations and replicas of it go too, and the peers of stand-in members are told to resync.
 */
export async function eraseOrganization(c: Ctx, db: ReturnType<typeof createDb>, id: string) {
  const blobKeys = (
    await db
      .select({ key: schema.attachments.r2Key })
      .from(schema.attachments)
      .innerJoin(schema.ciphers, eq(schema.ciphers.uuid, schema.attachments.cipherUuid))
      .where(eq(schema.ciphers.organizationUuid, id))
  ).map((r) => r.key)
  const federated = await db
    .select({ user: schema.usersOrganizations.userUuid, member: schema.usersOrganizations.uuid })
    .from(schema.federationMembers)
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.uuid, schema.federationMembers.organizationUserUuid),
    )
    .where(eq(schema.usersOrganizations.organizationUuid, id))
  // Members are bumped first: their rows disappear with the organisation.
  await runBatch(db, [
    bumpOrgRevision(db, id, Date.now()),
    db.delete(schema.events).where(eq(schema.events.organizationUuid, id)),
    db
      .delete(schema.federationInvitations)
      .where(eq(schema.federationInvitations.organizationUuid, id)),
    db
      .delete(schema.federationReplicaCiphers)
      .where(eq(schema.federationReplicaCiphers.organizationUuid, id)),
    db
      .delete(schema.federationReplicaOrgs)
      .where(eq(schema.federationReplicaOrgs.organizationUuid, id)),
    db.delete(schema.organizations).where(eq(schema.organizations.uuid, id)),
  ])
  deleteBlobs(c, blobKeys)
  if (federated.length > 0) {
    // Stand-in accounts live on in the peers' replicas until those resync (SyncVault, type 5).
    later(
      c,
      (async () => {
        const { notifyPeerOfUser } = await import('../federation/hosting')
        for (const f of federated) {
          if (f.user) await notifyPeerOfUser(c.env, f.user, 5, {}, null).catch(() => {})
        }
      })(),
    )
  }
}

const deleteOrg = async (c: Ctx) => {
  const id = c.req.param('id') ?? ''
  const { masterPasswordHash } = await parseBody(
    c,
    z.object({ masterPasswordHash: z.string().min(1) }),
  )
  const db = createDb(c.env.DB)
  await requireOwner(db, c.var.user.uuid, id)
  if (!(await verifyMasterPassword(c.var.user, masterPasswordHash))) {
    throw new ApiError(400, 'Invalid password.', { masterPasswordHash: ['Invalid password.'] })
  }
  await eraseOrganization(c, db, id)
  return c.body(null, 200)
}
organizations.delete('/api/organizations/:id', deleteOrg)
organizations.post('/api/organizations/:id/delete', deleteOrg)

/** A pending invitation addressed to `email` that is not yet linked to an account. */
async function invitedByEmail(db: ReturnType<typeof createDb>, orgUuid: string, email: string) {
  const [m] = await db
    .select()
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
        eq(schema.usersOrganizations.email, email),
        eq(schema.usersOrganizations.status, Status.Invited),
      ),
    )
    .limit(1)
  return m
}

organizations.get('/api/organizations/:id/keys', async (c) => {
  const id = c.req.param('id')
  const db = createDb(c.env.DB)
  const member =
    (await getMember(db, c.var.user.uuid, id)) ?? (await invitedByEmail(db, id, c.var.user.email))
  // Invited and accepted members need the public key to enrol in account recovery while
  // joining; only confirmed members receive the (organisation-key encrypted) private key.
  if (!member || member.status === Status.Revoked)
    throw new ApiError(404, 'Organization not found.')
  const org = await requireOrg(db, id)
  return c.json({
    object: 'organizationKeys',
    publicKey: org.publicKey,
    privateKey: member.status === Status.Confirmed ? org.privateKey : null,
  })
})

organizations.post('/api/organizations/:id/keys', async (c) => {
  const id = c.req.param('id')
  const body = await parseBody(c, keysSchema)
  const db = createDb(c.env.DB)
  await requireOwner(db, c.var.user.uuid, id)
  const org = await requireOrg(db, id)
  if (org.publicKey) throw new ApiError(400, 'Organization already has keys.')
  await db
    .update(schema.organizations)
    .set({ publicKey: body.publicKey, privateKey: body.encryptedPrivateKey, updatedAt: Date.now() })
    .where(eq(schema.organizations.uuid, id))
  return c.json({
    object: 'organizationKeys',
    publicKey: body.publicKey,
    privateKey: body.encryptedPrivateKey,
  })
})

organizations.post('/api/organizations/:id/leave', async (c) => {
  const id = c.req.param('id')
  const db = createDb(c.env.DB)
  const m = await requireMember(db, c.var.user.uuid, id)
  await assertNotLastOwner(db, id, m)
  await assertNotClaimed(
    db,
    c.var.user,
    'Your account is claimed by this organization; you cannot leave it.',
    id,
  )
  await runBatch(db, [
    ...dropMemberStateFor(db, c.var.user.uuid, id),
    db
      .delete(schema.usersOrganizations)
      .where(
        and(
          eq(schema.usersOrganizations.uuid, m.uuid),
          eq(schema.usersOrganizations.organizationUuid, id),
        ),
      ),
    eventStatement(db, c, {
      type: EventType.OrganizationUserRemoved,
      organizationUuid: id,
      organizationUserUuid: m.uuid,
      userUuid: m.userUuid,
    }),
    bumpRevision(db, c.var.user.uuid, Date.now()),
  ])
  return c.body(null, 200)
})
