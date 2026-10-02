import { and, eq, inArray } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { signPurposeToken, verifyPurposeToken } from '../auth/purpose-token'
import { normalizeEmail } from '../auth/users'
import { createDb, type Db, runBatch, schema } from '../db'
import { createEmailTransport, orgInviteEmail } from '../email'
import type { Env } from '../env'
import { ApiError } from '../errors'
import {
  bumpOrgRevision,
  type Member,
  requireMember,
  requireOrg,
  requirePermission,
} from '../orgs/access'
import { EventType, Role, Status } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import {
  accessOf,
  assertCanAssign,
  assertCanGrant,
  assertIdsInOrg,
  assertNotLastOwner,
  canListMembers,
  dedupeSelections,
  getTarget,
  loadMemberLists,
  memberJson,
  permissionsColumn,
  statusAfterRestore,
  VALID_ROLES,
} from '../orgs/members'
import { notifyOrgKeys } from '../orgs/notify'
import { assertTwoFactorCompliant } from '../orgs/policies'
import { authOnce, batch } from '../orgs/util'
import { parseBody } from '../validation'
import { chunk } from '../vault/ciphers'

export const orgUsers = new Hono<Env>()
orgUsers.use('/api/organizations/*', authOnce)

type Ctx = Context<Env>

const INVITE_TTL_SECONDS = 5 * 24 * 3600
const MAX_BULK = 500
export const INVITE_PURPOSE = 'orginvite'

const selectionSchema = z.object({
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
})
const permissionsSchema = z.record(z.string(), z.boolean().nullable()).nullish()
const idsSchema = z.object({ ids: z.array(z.string()).max(MAX_BULK).default([]) })

const org = (c: Ctx) => c.req.param('orgId') ?? ''
const bulkOk = (rows: { id: string; error: string | null }[], c: Ctx) =>
  c.json({
    object: 'list',
    data: rows.map((r) => ({ object: 'organizationUserBulkResponse', ...r })),
    continuationToken: null,
  })

// ----- listing -----

const listMembers = async (c: Ctx, mini: boolean) => {
  const orgUuid = org(c)
  const db = createDb(c.env.DB)
  const actor = await requireMember(db, c.var.user.uuid, orgUuid)
  if (!mini && !canListMembers(actor))
    throw new ApiError(403, 'You do not have permission to do this.')
  const includeCollections = c.req.query('includeCollections') === 'true'
  const includeGroups = c.req.query('includeGroups') === 'true'
  const rows = await db
    .select({ m: schema.usersOrganizations, u: schema.users })
    .from(schema.usersOrganizations)
    .leftJoin(schema.users, eq(schema.users.uuid, schema.usersOrganizations.userUuid))
    .where(eq(schema.usersOrganizations.organizationUuid, orgUuid))
  const lists = await loadMemberLists(db, orgUuid, {
    collections: includeCollections,
    groups: includeGroups,
  })
  return c.json({
    object: 'list',
    data: rows.map((r) => memberJson(r.m, r.u, lists)),
    continuationToken: null,
  })
}
orgUsers.get('/api/organizations/:orgId/users', (c) => listMembers(c, false))
orgUsers.get('/api/organizations/:orgId/users/mini-details', (c) => listMembers(c, true))

// ----- invitation -----

const inviteSchema = z.object({
  emails: z.array(z.string().min(3).max(256)).min(1).max(MAX_BULK),
  type: z
    .number()
    .int()
    .refine((t) => VALID_ROLES.includes(t), 'Invalid role.'),
  accessAll: z.boolean().nullish(),
  collections: z.array(selectionSchema).nullish(),
  groups: z.array(z.string()).nullish(),
  permissions: permissionsSchema,
  accessSecretsManager: z.boolean().nullish(),
})

function inviteLink(c: Ctx, orgRow: { uuid: string; name: string }, m: Member, token: string) {
  const q = new URLSearchParams({
    organizationId: orgRow.uuid,
    organizationUserId: m.uuid,
    email: m.email ?? '',
    organizationName: orgRow.name,
    token,
  })
  return `${c.env.DOMAIN.replace(/\/+$/, '')}/#/accept-organization?${q.toString()}`
}

async function sendInvite(c: Ctx, orgRow: { uuid: string; name: string }, m: Member) {
  const transport = createEmailTransport(c.env)
  if (!transport.configured || !m.email) return
  const token = await signPurposeToken(
    c.env,
    INVITE_PURPOSE,
    { sub: m.uuid, email: m.email, ref: orgRow.uuid },
    INVITE_TTL_SECONDS,
  )
  try {
    await transport.send({
      to: m.email,
      ...orgInviteEmail(orgRow.name, inviteLink(c, orgRow, m, token)),
    })
  } catch {
    // The invitation is stored; an administrator can resend it. Message content is never logged.
  }
}

orgUsers.post('/api/organizations/:orgId/users/invite', async (c) => {
  const orgUuid = org(c)
  const body = await parseBody(c, inviteSchema)
  const db = createDb(c.env.DB)
  const actor = await requirePermission(db, c.var.user.uuid, orgUuid, 'manageUsers')
  assertCanAssign(actor, body.type)
  assertCanGrant(actor, body)
  const orgRow = await requireOrg(db, orgUuid)
  const collections = dedupeSelections(body.collections ?? [])
  const groupIds = [...new Set(body.groups ?? [])]
  if (collections.length)
    await assertIdsInOrg(
      db,
      'collection',
      orgUuid,
      collections.map((s) => s.id),
    )
  if (groupIds.length) await assertIdsInOrg(db, 'group', orgUuid, groupIds)

  const emails = [...new Set(body.emails.map(normalizeEmail))]
  if (emails.some((e) => !e.includes('@'))) {
    throw new ApiError(400, 'The request is invalid.', { emails: ['Invalid email address.'] })
  }
  const now = Date.now()
  const members: Member[] = []
  for (const email of emails) {
    const [account] = await db
      .select({ uuid: schema.users.uuid })
      .from(schema.users)
      .where(eq(schema.users.email, email))
      .limit(1)
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
      throw new ApiError(400, 'User already invited.', {
        emails: [`${email} is already a member.`],
      })
    members.push({
      uuid: crypto.randomUUID(),
      userUuid: account?.uuid ?? null,
      organizationUuid: orgUuid,
      email,
      permissions: permissionsColumn(body.type, body.permissions),
      accessAll: body.accessAll === true,
      akey: '',
      status: Status.Invited,
      atype: body.type,
      resetPasswordKey: null,
      externalId: null,
      accessSecretsManager: body.accessSecretsManager === true,
      createdAt: now,
      updatedAt: now,
    })
  }
  await runBatch(db, [
    ...members.flatMap((m) => [
      db.insert(schema.usersOrganizations).values(m),
      ...(m.userUuid
        ? []
        : [
            // Lets an address without an account register while signups are closed.
            db
              .insert(schema.invitations)
              .values({
                uuid: crypto.randomUUID(),
                email: m.email as string,
                invitedBy: actor.userUuid as string,
                createdAt: now,
              })
              .onConflictDoNothing(),
          ]),
      ...(body.accessAll
        ? []
        : collections.map((s) =>
            db.insert(schema.usersCollections).values({
              organizationUserUuid: m.uuid,
              collectionUuid: s.id,
              ...accessOf(s),
            }),
          )),
      ...groupIds.map((g) =>
        db.insert(schema.groupsUsers).values({ groupUuid: g, organizationUserUuid: m.uuid }),
      ),
      eventStatement(db, c, {
        type: EventType.OrganizationUserInvited,
        organizationUuid: orgUuid,
        organizationUserUuid: m.uuid,
        userUuid: m.userUuid,
      }),
    ]),
  ])
  for (const m of members) await sendInvite(c, orgRow, m)
  return c.body(null, 200)
})

async function reinvite(c: Ctx, id: string, actor: Member): Promise<string | null> {
  const db = createDb(c.env.DB)
  const target = await getTarget(db, org(c), id)
  assertCanAssign(actor, target.atype)
  if (target.status !== Status.Invited) return 'User has already accepted the invitation.'
  await sendInvite(c, await requireOrg(db, org(c)), target)
  return null
}

orgUsers.post('/api/organizations/:orgId/users/reinvite', async (c) => {
  const { ids } = await parseBody(c, idsSchema)
  const actor = await requirePermission(createDb(c.env.DB), c.var.user.uuid, org(c), 'manageUsers')
  const out = []
  for (const id of ids) {
    out.push({ id, error: await reinvite(c, id, actor).catch((e: ApiError) => e.message) })
  }
  return bulkOk(out, c)
})

orgUsers.post('/api/organizations/:orgId/users/:id/reinvite', async (c) => {
  const actor = await requirePermission(createDb(c.env.DB), c.var.user.uuid, org(c), 'manageUsers')
  const error = await reinvite(c, c.req.param('id'), actor)
  if (error) throw new ApiError(400, error)
  return c.body(null, 200)
})

// ----- accept and confirm -----

orgUsers.post('/api/organizations/:orgId/users/:id/accept', async (c) => {
  const orgUuid = org(c)
  const id = c.req.param('id')
  const body = await parseBody(
    c,
    z.object({ token: z.string().min(1), resetPasswordKey: z.string().nullish() }),
  )
  const db = createDb(c.env.DB)
  const user = c.var.user
  const claims = await verifyPurposeToken(c.env, INVITE_PURPOSE, body.token)
  const target = await getTarget(db, orgUuid, id).catch(() => null)
  if (
    !claims ||
    !target ||
    claims.sub !== id ||
    claims.ref !== orgUuid ||
    claims.email !== user.email
  ) {
    throw new ApiError(400, 'Invalid token.')
  }
  if (target.status !== Status.Invited) throw new ApiError(400, 'Invitation already accepted.')
  if (target.userUuid && target.userUuid !== user.uuid) throw new ApiError(400, 'Invalid token.')
  await assertTwoFactorCompliant(db, user.uuid, orgUuid)
  const now = Date.now()
  try {
    await runBatch(db, [
      db
        .update(schema.usersOrganizations)
        .set({ userUuid: user.uuid, status: Status.Accepted, updatedAt: now })
        .where(eq(schema.usersOrganizations.uuid, id)),
    ])
  } catch {
    throw new ApiError(400, 'You are already a member of this organization.')
  }
  return c.body(null, 200)
})

/** Statements that confirm one accepted member, or an error message. */
async function confirmStatements(
  c: Ctx,
  db: Db,
  actor: Member,
  id: string,
  key: string,
): Promise<{ error: string } | { statements: unknown[]; userUuid: string }> {
  const target = await getTarget(db, actor.organizationUuid, id).catch(() => null)
  if (!target) return { error: 'User not found.' }
  if (target.status !== Status.Accepted || !target.userUuid)
    return { error: 'User is not ready to be confirmed.' }
  try {
    assertCanAssign(actor, target.atype)
    await assertTwoFactorCompliant(db, target.userUuid, actor.organizationUuid)
  } catch (e) {
    return { error: (e as ApiError).message }
  }
  const now = Date.now()
  return {
    userUuid: target.userUuid,
    statements: [
      db
        .update(schema.usersOrganizations)
        .set({ status: Status.Confirmed, akey: key, updatedAt: now })
        .where(eq(schema.usersOrganizations.uuid, id)),
      eventStatement(db, c, {
        type: EventType.OrganizationUserConfirmed,
        organizationUuid: actor.organizationUuid,
        organizationUserUuid: id,
        userUuid: target.userUuid,
      }),
      db.update(schema.users).set({ updatedAt: now }).where(eq(schema.users.uuid, target.userUuid)),
    ],
  }
}

orgUsers.post('/api/organizations/:orgId/users/confirm', async (c) => {
  const body = await parseBody(
    c,
    z.object({ keys: z.array(z.object({ id: z.string(), key: z.string().min(1) })).max(MAX_BULK) }),
  )
  const db = createDb(c.env.DB)
  const actor = await requirePermission(db, c.var.user.uuid, org(c), 'manageUsers')
  const out: { id: string; error: string | null }[] = []
  const statements: unknown[] = []
  const confirmed: string[] = []
  for (const k of body.keys) {
    const r = await confirmStatements(c, db, actor, k.id, k.key)
    if ('error' in r) out.push({ id: k.id, error: r.error })
    else {
      statements.push(...r.statements)
      confirmed.push(r.userUuid)
      out.push({ id: k.id, error: null })
    }
  }
  await batch(db, statements)
  for (const u of confirmed) notifyOrgKeys(c, u)
  return bulkOk(out, c)
})

orgUsers.post('/api/organizations/:orgId/users/:id/confirm', async (c) => {
  const body = await parseBody(
    c,
    z.object({ key: z.string().min(1), defaultUserCollectionName: z.string().nullish() }),
  )
  const db = createDb(c.env.DB)
  const actor = await requirePermission(db, c.var.user.uuid, org(c), 'manageUsers')
  const r = await confirmStatements(c, db, actor, c.req.param('id'), body.key)
  if ('error' in r) throw new ApiError(r.error === 'User not found.' ? 404 : 400, r.error)
  await batch(db, r.statements)
  notifyOrgKeys(c, r.userUuid)
  return c.body(null, 200)
})

orgUsers.post('/api/organizations/:orgId/users/public-keys', async (c) => {
  const { ids } = await parseBody(c, idsSchema)
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, org(c), 'manageUsers')
  const data = []
  for (const part of chunk(ids)) {
    const rows = await db
      .select({
        m: schema.usersOrganizations.uuid,
        u: schema.users.uuid,
        key: schema.users.publicKey,
      })
      .from(schema.usersOrganizations)
      .innerJoin(schema.users, eq(schema.users.uuid, schema.usersOrganizations.userUuid))
      .where(
        and(
          eq(schema.usersOrganizations.organizationUuid, org(c)),
          inArray(schema.usersOrganizations.uuid, part),
        ),
      )
    for (const r of rows) {
      data.push({
        object: 'organizationUserPublicKeyResponseModel',
        id: r.m,
        userId: r.u,
        key: r.key,
      })
    }
  }
  return c.json({ object: 'list', data, continuationToken: null })
})

// ----- revoke, restore, remove (bulk first: static paths before `/:id`) -----

type Op = (c: Ctx, db: Db, actor: Member, target: Member) => Promise<unknown[]>

const revokeOp: Op = async (c, db, actor, target) => {
  assertCanAssign(actor, target.atype)
  if (target.userUuid === actor.userUuid) throw new ApiError(400, 'You cannot revoke yourself.')
  if (target.status === Status.Revoked) throw new ApiError(400, 'User is already revoked.')
  if (target.status === Status.Invited) throw new ApiError(400, 'Invited users cannot be revoked.')
  await assertNotLastOwner(db, target.organizationUuid, target)
  return [
    db
      .update(schema.usersOrganizations)
      .set({ status: Status.Revoked, updatedAt: Date.now() })
      .where(eq(schema.usersOrganizations.uuid, target.uuid)),
    eventStatement(db, c, {
      type: EventType.OrganizationUserRevoked,
      organizationUuid: target.organizationUuid,
      organizationUserUuid: target.uuid,
      userUuid: target.userUuid,
    }),
  ]
}

const restoreOp: Op = async (c, db, actor, target) => {
  assertCanAssign(actor, target.atype)
  if (target.status !== Status.Revoked) throw new ApiError(400, 'User is not revoked.')
  if (target.userUuid) await assertTwoFactorCompliant(db, target.userUuid, target.organizationUuid)
  return [
    db
      .update(schema.usersOrganizations)
      .set({ status: statusAfterRestore(target), updatedAt: Date.now() })
      .where(eq(schema.usersOrganizations.uuid, target.uuid)),
    eventStatement(db, c, {
      type: EventType.OrganizationUserRestored,
      organizationUuid: target.organizationUuid,
      organizationUserUuid: target.uuid,
      userUuid: target.userUuid,
    }),
  ]
}

const removeOp: Op = async (c, db, actor, target) => {
  assertCanAssign(actor, target.atype)
  await assertNotLastOwner(db, target.organizationUuid, target)
  const now = Date.now()
  return [
    // Bumped before the delete: afterwards the member is no longer in the organisation.
    bumpOrgRevision(db, target.organizationUuid, now),
    db.delete(schema.usersOrganizations).where(eq(schema.usersOrganizations.uuid, target.uuid)),
    eventStatement(db, c, {
      type: EventType.OrganizationUserRemoved,
      organizationUuid: target.organizationUuid,
      organizationUserUuid: target.uuid,
      userUuid: target.userUuid,
    }),
  ]
}

async function runOps(c: Ctx, ids: string[], op: Op) {
  const db = createDb(c.env.DB)
  const actor = await requirePermission(db, c.var.user.uuid, org(c), 'manageUsers')
  const out: { id: string; error: string | null }[] = []
  const statements: unknown[] = []
  for (const id of ids) {
    try {
      statements.push(...(await op(c, db, actor, await getTarget(db, org(c), id))))
      out.push({ id, error: null })
    } catch (e) {
      if (!(e instanceof ApiError)) throw e
      out.push({ id, error: e.message })
    }
  }
  statements.push(bumpOrgRevision(db, org(c), Date.now()))
  await batch(db, statements)
  return out
}

const single = async (c: Ctx, op: Op) => {
  const [r] = await runOps(c, [c.req.param('id') ?? ''], op)
  if (r?.error) throw new ApiError(r.error === 'User not found.' ? 404 : 400, r.error)
  return c.body(null, 200)
}

/** Grants Secrets Manager access (TASKS #220); the web client's bulk "activate Secrets Manager". */
const enableSecretsManagerOp: Op = async (c, db, actor, target) => {
  assertCanAssign(actor, target.atype)
  return [
    db
      .update(schema.usersOrganizations)
      .set({ accessSecretsManager: true, updatedAt: Date.now() })
      .where(eq(schema.usersOrganizations.uuid, target.uuid)),
    eventStatement(db, c, {
      type: EventType.OrganizationUserUpdated,
      organizationUuid: target.organizationUuid,
      organizationUserUuid: target.uuid,
      userUuid: target.userUuid,
    }),
  ]
}

orgUsers.put('/api/organizations/:orgId/users/enable-secrets-manager', async (c) =>
  bulkOk(await runOps(c, (await parseBody(c, idsSchema)).ids, enableSecretsManagerOp), c),
)
orgUsers.put('/api/organizations/:orgId/users/revoke', async (c) =>
  bulkOk(await runOps(c, (await parseBody(c, idsSchema)).ids, revokeOp), c),
)
orgUsers.put('/api/organizations/:orgId/users/restore', async (c) =>
  bulkOk(await runOps(c, (await parseBody(c, idsSchema)).ids, restoreOp), c),
)
orgUsers.delete('/api/organizations/:orgId/users', async (c) =>
  bulkOk(await runOps(c, (await parseBody(c, idsSchema)).ids, removeOp), c),
)
orgUsers.put('/api/organizations/:orgId/users/:id/revoke', (c) => single(c, revokeOp))
orgUsers.put('/api/organizations/:orgId/users/:id/restore', (c) => single(c, restoreOp))
orgUsers.put('/api/organizations/:orgId/users/:id/restore/vnext', (c) => single(c, restoreOp))
orgUsers.delete('/api/organizations/:orgId/users/:id', (c) => single(c, removeOp))
orgUsers.post('/api/organizations/:orgId/users/:id/delete', (c) => single(c, removeOp))

// ----- single member -----

orgUsers.get('/api/organizations/:orgId/users/:id', async (c) => {
  const db = createDb(c.env.DB)
  const actor = await requireMember(db, c.var.user.uuid, org(c))
  if (!canListMembers(actor)) throw new ApiError(403, 'You do not have permission to do this.')
  const target = await getTarget(db, org(c), c.req.param('id'))
  const [u] = target.userUuid
    ? await db.select().from(schema.users).where(eq(schema.users.uuid, target.userUuid)).limit(1)
    : []
  const lists = await loadMemberLists(db, org(c), { collections: true, groups: true })
  return c.json(memberJson(target, u ?? null, lists, true))
})

const updateSchema = z.object({
  type: z
    .number()
    .int()
    .refine((t) => VALID_ROLES.includes(t), 'Invalid role.'),
  accessAll: z.boolean().nullish(),
  collections: z.array(selectionSchema).nullish(),
  groups: z.array(z.string()).nullish(),
  permissions: permissionsSchema,
  accessSecretsManager: z.boolean().nullish(),
})
const updateMember = async (c: Ctx) => {
  const body = await parseBody(c, updateSchema)
  const orgUuid = org(c)
  const db = createDb(c.env.DB)
  const actor = await requirePermission(db, c.var.user.uuid, orgUuid, 'manageUsers')
  const target = await getTarget(db, orgUuid, c.req.param('id') ?? '')
  assertCanAssign(actor, target.atype)
  assertCanAssign(actor, body.type)
  assertCanGrant(actor, body)
  // Owners may edit themselves (guarded by the last-owner check); nobody else may.
  if (target.uuid === actor.uuid && actor.atype !== Role.Owner) {
    throw new ApiError(403, 'You cannot change your own access.')
  }
  if (body.type !== Role.Owner) await assertNotLastOwner(db, orgUuid, target)
  const collections = dedupeSelections(body.collections ?? [])
  const groupIds = [...new Set(body.groups ?? [])]
  if (collections.length)
    await assertIdsInOrg(
      db,
      'collection',
      orgUuid,
      collections.map((s) => s.id),
    )
  if (groupIds.length) await assertIdsInOrg(db, 'group', orgUuid, groupIds)
  const now = Date.now()
  const accessAll = body.accessAll === true
  await runBatch(db, [
    db
      .update(schema.usersOrganizations)
      .set({
        atype: body.type,
        accessAll,
        permissions: permissionsColumn(body.type, body.permissions),
        ...(body.accessSecretsManager == null
          ? {}
          : { accessSecretsManager: body.accessSecretsManager }),
        updatedAt: now,
      })
      .where(eq(schema.usersOrganizations.uuid, target.uuid)),
    ...(body.collections !== undefined || accessAll
      ? [
          db
            .delete(schema.usersCollections)
            .where(eq(schema.usersCollections.organizationUserUuid, target.uuid)),
          ...(accessAll
            ? []
            : collections.map((s) =>
                db.insert(schema.usersCollections).values({
                  organizationUserUuid: target.uuid,
                  collectionUuid: s.id,
                  ...accessOf(s),
                }),
              )),
        ]
      : []),
    ...(body.groups != null
      ? [
          db
            .delete(schema.groupsUsers)
            .where(eq(schema.groupsUsers.organizationUserUuid, target.uuid)),
          ...groupIds.map((g) =>
            db
              .insert(schema.groupsUsers)
              .values({ groupUuid: g, organizationUserUuid: target.uuid }),
          ),
          eventStatement(db, c, {
            type: EventType.OrganizationUserUpdatedGroups,
            organizationUuid: orgUuid,
            organizationUserUuid: target.uuid,
            userUuid: target.userUuid,
          }),
        ]
      : []),
    eventStatement(db, c, {
      type: EventType.OrganizationUserUpdated,
      organizationUuid: orgUuid,
      organizationUserUuid: target.uuid,
      userUuid: target.userUuid,
    }),
    bumpOrgRevision(db, orgUuid, now),
  ])
  return c.body(null, 200)
}
orgUsers.put('/api/organizations/:orgId/users/:id', updateMember)
orgUsers.post('/api/organizations/:orgId/users/:id', updateMember)

orgUsers.get('/api/organizations/:orgId/users/:id/groups', async (c) => {
  const db = createDb(c.env.DB)
  const actor = await requireMember(db, c.var.user.uuid, org(c))
  if (!canListMembers(actor)) throw new ApiError(403, 'You do not have permission to do this.')
  const target = await getTarget(db, org(c), c.req.param('id'))
  const rows = await db
    .select({ g: schema.groupsUsers.groupUuid })
    .from(schema.groupsUsers)
    .where(eq(schema.groupsUsers.organizationUserUuid, target.uuid))
  return c.json(rows.map((r) => r.g))
})

orgUsers.put('/api/organizations/:orgId/users/:id/groups', async (c) => {
  const { groupIds } = await parseBody(c, z.object({ groupIds: z.array(z.string()).default([]) }))
  const db = createDb(c.env.DB)
  const actor = await requirePermission(db, c.var.user.uuid, org(c), 'manageUsers')
  const target = await getTarget(db, org(c), c.req.param('id'))
  assertCanAssign(actor, target.atype)
  if (target.uuid === actor.uuid) throw new ApiError(403, 'You cannot change your own groups.')
  const ids = [...new Set(groupIds)]
  if (ids.length) await assertIdsInOrg(db, 'group', org(c), ids)
  await runBatch(db, [
    db.delete(schema.groupsUsers).where(eq(schema.groupsUsers.organizationUserUuid, target.uuid)),
    ...ids.map((g) =>
      db.insert(schema.groupsUsers).values({ groupUuid: g, organizationUserUuid: target.uuid }),
    ),
    eventStatement(db, c, {
      type: EventType.OrganizationUserUpdatedGroups,
      organizationUuid: org(c),
      organizationUserUuid: target.uuid,
      userUuid: target.userUuid,
    }),
    bumpOrgRevision(db, org(c), Date.now()),
  ])
  return c.body(null, 200)
})
