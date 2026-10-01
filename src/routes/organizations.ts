import { and, eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { verifyMasterPassword } from '../auth/passwords'
import { createDb, runBatch, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import {
  bumpOrgRevision,
  isAdminRole,
  requireMember,
  requireOrg,
  requireOwner,
} from '../orgs/access'
import { EventType, Role, Status } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import { assertNotLastOwner } from '../orgs/members'
import { authOnce } from '../orgs/util'
import { orgJson } from '../orgs/views'
import { parseBody } from '../validation'
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

organizations.post('/api/organizations', async (c) => {
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
})

/** Details, settings and keys need an owner, an admin or a custom member. */
async function requireManager(c: Ctx, orgUuid: string) {
  const db = createDb(c.env.DB)
  const m = await requireMember(db, c.var.user.uuid, orgUuid)
  if (m.atype === Role.User || m.atype === Role.Manager) {
    throw new ApiError(403, 'You do not have permission to do this.')
  }
  return m
}

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
  const now = Date.now()
  await runBatch(db, [
    db
      .update(schema.organizations)
      .set({
        name: body.name ?? org.name,
        billingEmail: body.billingEmail ? body.billingEmail.trim().toLowerCase() : org.billingEmail,
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
  // Members are bumped first: their rows disappear with the organisation.
  await runBatch(db, [
    bumpOrgRevision(db, id, Date.now()),
    db.delete(schema.events).where(eq(schema.events.organizationUuid, id)),
    db.delete(schema.organizations).where(eq(schema.organizations.uuid, id)),
  ])
  return c.body(null, 200)
}
organizations.delete('/api/organizations/:id', deleteOrg)
organizations.post('/api/organizations/:id/delete', deleteOrg)

organizations.get('/api/organizations/:id/keys', async (c) => {
  const id = c.req.param('id')
  const db = createDb(c.env.DB)
  await requireMember(db, c.var.user.uuid, id)
  const org = await requireOrg(db, id)
  return c.json({
    object: 'organizationKeys',
    publicKey: org.publicKey,
    privateKey: org.privateKey,
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
  await runBatch(db, [
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
