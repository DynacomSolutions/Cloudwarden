// Bitwarden Public API (TASKS #271), served at `/api/public/*` (self-hosted layout) and
// `/public/*` (cloud layout). Authenticated with an organisation token from the
// `client_credentials` grant (`client_id=organization.<id>`, `scope=api.organization`). Request and
// response models follow Bitwarden's published Public API reference: `member`, `group`,
// `collection`, `policy` and `event` objects inside `list` envelopes, errors as
// `{ object: 'error', message, errors }`. Changes are made with admin authority: owners can
// neither be created nor changed here, matching an admin acting in the web client.
import { type AnyColumn, and, eq, inArray, type SQL } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { isAdminEmail } from '../admin/security'
import { isEmailTakenError, sendEmailChangeNotices } from '../auth/email-change'
import { stampRotationStatements } from '../auth/session'
import { createDb, type Db, schema } from '../db'
import { later } from '../email/send'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { errorKind, log } from '../log'
import { bumpOrgRevision, type Member, requireOrg, storedPermissions } from '../orgs/access'
import { requireOrgApiAuth } from '../orgs/api-keys'
import {
  EventSystemUser,
  EventType,
  MAX_POLICY_TYPE,
  PolicyType,
  PUBLIC_PERMISSION_KEYS,
  Role,
  Status,
} from '../orgs/constants'
import { importDirectory, importSchema } from '../orgs/directory-import'
import { orgClaimsEmail } from '../orgs/domains'
import { eventStatement, listEvents, publicEventRange } from '../orgs/events'
import {
  accessOf,
  assertCanAssign,
  assertIdsInOrg,
  assertNotLastOwner,
  dedupeSelections,
  getTarget,
  loadMemberLists,
  type MemberLists,
  permissionsColumn,
  type Selection,
  VALID_ROLES,
} from '../orgs/members'
import { parseData } from '../orgs/policies'
import { assertPolicyData, findPolicy, savePolicy } from '../orgs/policy-save'
import {
  insertMemberStatements,
  invitedMember,
  memberByEmail,
  statusOnRestore,
  systemActor,
} from '../orgs/provisioning'
import {
  assertSeatsAvailable,
  loadSubscription,
  mergeSubscription,
  subscriptionJson,
  subscriptionUpdateSchema,
  subscriptionUpsert,
} from '../orgs/subscription'
import { batch } from '../orgs/util'
import { normalizeKeys } from '../validation'
import { sendInvite } from './org-users'

type Ctx = Context<Env>

// The published import model requires `overwriteExisting`.
const publicImportSchema = importSchema.extend({ overwriteExisting: z.boolean() })

export const publicApi = new Hono<Env>()

const PREFIXES = ['/api/public', '/public'] as const

const orgOf = (c: Ctx) => c.var.orgApi?.organizationUuid ?? ''
/** List envelope. Only the event list carries a `continuationToken`, as the published models do. */
const list = (data: unknown[]) => ({ object: 'list', data })

/** Public API error envelope. */
const fail = (c: Ctx, status: number, message: string, errors: unknown = null) =>
  c.json({ object: 'error', message, errors }, status as 400)

async function body<S extends z.ZodType>(c: Ctx, s: S): Promise<z.infer<S>> {
  const raw = await c.req.json().catch(() => null)
  const parsed = s.safeParse(normalizeKeys(raw, 4))
  if (!parsed.success) {
    const errors: Record<string, string[]> = {}
    for (const issue of parsed.error.issues) {
      const key = issue.path.join('.') || 'body'
      errors[key] = [...(errors[key] ?? []), issue.message]
    }
    throw new ApiError(400, 'The request is invalid.', errors)
  }
  return parsed.data
}

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
// The published member types are 0, 1, 2 and 4. Manager (3) is gone.
const PUBLIC_ROLES = VALID_ROLES.filter((t) => t !== Role.Manager)
const roleSchema = z
  .number()
  .int()
  .refine((t) => PUBLIC_ROLES.includes(t), 'Invalid member type.')

const association = (s: Selection) => ({
  id: s.id,
  readOnly: s.readOnly,
  hidePasswords: s.hidePasswords,
  manage: s.manage,
})

// ----- members -----

type UserRow = typeof schema.users.$inferSelect

/** Custom permissions as the published model lists them: its 13 keys, nothing else. */
const publicPermissions = (m: Member) => {
  const stored = storedPermissions(m)
  return Object.fromEntries(PUBLIC_PERMISSION_KEYS.map((k) => [k, stored[k]]))
}

/**
 * The published model has no Manager type. A Manager holds no organisation permission here, so it
 * reads back as a Custom member with every permission off, and that shape is accepted on write.
 */
const publicType = (m: Member) => (m.atype === Role.Manager ? Role.Custom : m.atype)

function memberJson(m: Member, user: UserRow | null, lists: MemberLists) {
  return {
    object: 'member',
    id: m.uuid,
    userId: m.userUuid,
    name: user?.name ?? null,
    email: user?.email ?? m.email ?? '',
    twoFactorEnabled: m.userUuid ? lists.twoFactor.has(m.userUuid) : false,
    status: m.status,
    collections: (lists.collections.get(m.uuid) ?? []).map(association),
    resetPasswordEnrolled: m.resetPasswordKey !== null,
    ssoExternalId: m.userUuid ? (lists.ssoExternalIds.get(m.userUuid) ?? null) : null,
    type: publicType(m),
    externalId: m.externalId,
    permissions: publicType(m) === Role.Custom ? publicPermissions(m) : null,
  }
}

async function memberWithUser(db: Db, m: Member) {
  const [u] = m.userUuid
    ? await db.select().from(schema.users).where(eq(schema.users.uuid, m.userUuid)).limit(1)
    : []
  const lists = await loadMemberLists(db, m.organizationUuid, { collections: true, groups: true })
  return memberJson(m, u ?? null, lists)
}

const memberCreateSchema = z.object({
  email: z.string().min(3).max(256),
  name: z.string().max(50).nullish(),
  type: roleSchema,
  externalId: z.string().max(300).nullish(),
  permissions: permissionsSchema,
  collections: z.array(selectionSchema).nullish(),
  groups: z.array(z.string()).nullish(),
})
const memberUpdateSchema = memberCreateSchema.extend({ email: z.string().max(256).nullish() })

/**
 * Permissions column for a member write. Only the published keys come from the request; a key
 * outside the published model (`manageCiphers`) keeps the value the member already has.
 */
function memberPermissionsColumn(
  type: number,
  input: Record<string, boolean | null> | null | undefined,
  existing?: Member,
) {
  if (type !== Role.Custom) return null
  const kept = existing ? storedPermissions(existing) : null
  const merged: Record<string, boolean | null> = { ...kept }
  for (const k of PUBLIC_PERMISSION_KEYS) merged[k] = input?.[k] === true
  return permissionsColumn(type, merged)
}

const EMAIL_TAKEN = 'The email address is already in use.'

/**
 * Changes of the account name and email address of a member. Both are allowed for a claimed
 * member only: one whose accepted account is on a domain the organisation verified. The email
 * address also needs an account without a master password and a new address on a verified domain.
 */
async function identityStatements(
  c: Ctx,
  db: Db,
  orgUuid: string,
  target: Member,
  change: { name?: string | null; email?: string | null },
) {
  const wantName = change.name !== null && change.name !== undefined
  const wantEmail =
    change.email !== null && change.email !== undefined && change.email.trim() !== ''
  const none = { statements: [], notify: null }
  if (!wantName && !wantEmail) return none
  const [user] = target.userUuid
    ? await db.select().from(schema.users).where(eq(schema.users.uuid, target.userUuid)).limit(1)
    : []
  const newName = wantName ? (change.name as string) : null
  const newEmail = wantEmail ? (change.email as string).trim().toLowerCase() : null
  const nameChanges = newName !== null && newName !== (user?.name ?? null)
  const emailChanges = newEmail !== null && newEmail !== (user?.email ?? target.email ?? '')
  if (!nameChanges && !emailChanges) return none
  const claimed =
    user !== undefined &&
    target.status >= Status.Accepted &&
    (await orgClaimsEmail(db, orgUuid, user.email))
  const errors: Record<string, string[]> = {}
  if (nameChanges && !claimed) errors.name = ['Name can only be changed for a claimed member.']
  if (emailChanges) {
    if (!claimed || !user) {
      errors.email = ['Email can only be changed for a claimed member.']
    } else if (user.passwordHash !== '') {
      errors.email = ['Email cannot be changed for a member with a master password.']
    } else if (!newEmail?.includes('@') || !(await orgClaimsEmail(db, orgUuid, newEmail))) {
      errors.email = ['The new email address must be on a domain verified by the organization.']
    } else if (isAdminEmail(c.env.ADMIN_EMAILS, newEmail)) {
      // Same answer as for an address that is taken, so the ADMIN_EMAILS list cannot be probed.
      errors.email = [EMAIL_TAKEN]
    } else {
      const [taken] = await db
        .select({ uuid: schema.users.uuid })
        .from(schema.users)
        .where(eq(schema.users.email, newEmail))
        .limit(1)
      if (taken) errors.email = [EMAIL_TAKEN]
    }
  }
  if (Object.keys(errors).length > 0) throw new ApiError(400, 'The request is invalid.', errors)
  if (!user) return none
  const now = Date.now()
  const changedEmail = emailChanges && newEmail !== null ? newEmail : null
  return {
    statements: [
      db
        .update(schema.users)
        .set({
          ...(nameChanges && newName !== null ? { name: newName } : {}),
          ...(changedEmail !== null
            ? {
                email: changedEmail,
                // A granted instance role belongs to the old address: a new one needs a fresh grant.
                instanceRole: 'user',
              }
            : {}),
          updatedAt: now,
        })
        .where(eq(schema.users.uuid, user.uuid)),
      ...(changedEmail !== null
        ? [
            // Old sessions of the account stop working, as after the account's own change.
            ...stampRotationStatements(db, user.uuid),
            ...(target.email !== null
              ? [
                  db
                    .update(schema.usersOrganizations)
                    .set({ email: changedEmail })
                    .where(eq(schema.usersOrganizations.uuid, target.uuid)),
                ]
              : []),
          ]
        : []),
    ],
    notify:
      changedEmail !== null
        ? () => later(c, sendEmailChangeNotices(c.env, user.email, changedEmail))
        : null,
  }
}

const ev = (db: Db, c: Ctx, e: Parameters<typeof eventStatement>[2]) =>
  eventStatement(db, c, { ...e, organizationUuid: orgOf(c), systemUser: EventSystemUser.PublicApi })

async function checkRefs(db: Db, orgUuid: string, cols: Selection[], groups: string[]) {
  if (cols.length)
    await assertIdsInOrg(
      db,
      'collection',
      orgUuid,
      cols.map((s) => s.id),
    )
  if (groups.length) await assertIdsInOrg(db, 'group', orgUuid, groups)
}

const accessStatements = (
  db: Db,
  memberUuid: string,
  accessAll: boolean,
  cols: Selection[] | null,
  groups: string[] | null,
  fresh: boolean,
) => [
  ...(cols !== null || accessAll
    ? [
        ...(fresh
          ? []
          : [
              db
                .delete(schema.usersCollections)
                .where(eq(schema.usersCollections.organizationUserUuid, memberUuid)),
            ]),
        ...(accessAll ? [] : (cols ?? [])).map((s) =>
          db.insert(schema.usersCollections).values({
            organizationUserUuid: memberUuid,
            collectionUuid: s.id,
            ...accessOf(s),
          }),
        ),
      ]
    : []),
  ...(groups !== null
    ? [
        ...(fresh
          ? []
          : [
              db
                .delete(schema.groupsUsers)
                .where(eq(schema.groupsUsers.organizationUserUuid, memberUuid)),
            ]),
        ...groups.map((g) =>
          db.insert(schema.groupsUsers).values({ groupUuid: g, organizationUserUuid: memberUuid }),
        ),
      ]
    : []),
]

function registerMembers(r: Hono<Env>, p: string) {
  r.get(`${p}/members`, async (c) => {
    const db = createDb(c.env.DB)
    const rows = await db
      .select({ m: schema.usersOrganizations, u: schema.users })
      .from(schema.usersOrganizations)
      .leftJoin(schema.users, eq(schema.users.uuid, schema.usersOrganizations.userUuid))
      .where(eq(schema.usersOrganizations.organizationUuid, orgOf(c)))
    const lists = await loadMemberLists(db, orgOf(c), { collections: true, groups: false })
    return c.json(list(rows.map((r) => memberJson(r.m, r.u, lists))))
  })

  r.post(`${p}/members`, async (c) => {
    const b = await body(c, memberCreateSchema)
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    assertCanAssign(systemActor(orgUuid), b.type)
    const email = b.email.trim().toLowerCase()
    if (!email.includes('@'))
      throw new ApiError(400, 'The request is invalid.', { email: ['Invalid email address.'] })
    if (await memberByEmail(db, orgUuid, email)) throw new ApiError(400, 'User already invited.')
    await assertSeatsAvailable(db, orgUuid)
    const cols = dedupeSelections(b.collections ?? [])
    const groups = [...new Set(b.groups ?? [])]
    await checkRefs(db, orgUuid, cols, groups)
    const m = await invitedMember(db, orgUuid, {
      email,
      type: b.type,
      accessAll: false,
      externalId: b.externalId ?? null,
      permissions: memberPermissionsColumn(b.type, b.permissions),
    })
    await batch(db, [
      ...insertMemberStatements(db, m, `organization:${orgUuid}`),
      ...accessStatements(db, m.uuid, m.accessAll, cols, groups, true),
      ev(db, c, {
        type: EventType.OrganizationUserInvited,
        organizationUserUuid: m.uuid,
        userUuid: m.userUuid,
      }),
    ])
    await sendInvite(c, await requireOrg(db, orgUuid), m)
    return c.json(await memberWithUser(db, m))
  })

  r.get(`${p}/members/:id`, async (c) => {
    const db = createDb(c.env.DB)
    return c.json(await memberWithUser(db, await getTarget(db, orgOf(c), c.req.param('id'))))
  })

  r.put(`${p}/members/:id`, async (c) => {
    const b = await body(c, memberUpdateSchema)
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const target = await getTarget(db, orgUuid, c.req.param('id'))
    const actor = systemActor(orgUuid)
    assertCanAssign(actor, target.atype)
    assertCanAssign(actor, b.type)
    const cols = b.collections == null ? null : dedupeSelections(b.collections)
    const groups = b.groups == null ? null : [...new Set(b.groups)]
    await checkRefs(db, orgUuid, cols ?? [], groups ?? [])
    // The published model has no `accessAll`. As the spec says, a property that is not provided is
    // reset, so a PUT ends blanket access and applies the collections it names.
    const accessAll = false
    const identity = await identityStatements(c, db, orgUuid, target, b)
    const now = Date.now()
    try {
      await batch(db, [
        db
          .update(schema.usersOrganizations)
          .set({
            atype: b.type,
            accessAll,
            externalId: b.externalId ?? null,
            permissions: memberPermissionsColumn(b.type, b.permissions, target),
            updatedAt: now,
          })
          .where(eq(schema.usersOrganizations.uuid, target.uuid)),
        ...identity.statements,
        ...accessStatements(db, target.uuid, accessAll, cols, groups, false),
        ev(db, c, {
          type: EventType.OrganizationUserUpdated,
          organizationUserUuid: target.uuid,
          userUuid: target.userUuid,
        }),
        bumpOrgRevision(db, orgUuid, now),
      ])
    } catch (err) {
      // Another account took the address after the check above.
      if (isEmailTakenError(err))
        throw new ApiError(400, 'The request is invalid.', { email: [EMAIL_TAKEN] })
      throw err
    }
    identity.notify?.()
    return c.json(await memberWithUser(db, await getTarget(db, orgUuid, target.uuid)))
  })

  r.delete(`${p}/members/:id`, async (c) => {
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const target = await getTarget(db, orgUuid, c.req.param('id'))
    assertCanAssign(systemActor(orgUuid), target.atype)
    await assertNotLastOwner(db, orgUuid, target)
    await batch(db, [
      bumpOrgRevision(db, orgUuid, Date.now()),
      db.delete(schema.usersOrganizations).where(eq(schema.usersOrganizations.uuid, target.uuid)),
      ev(db, c, {
        type: EventType.OrganizationUserRemoved,
        organizationUserUuid: target.uuid,
        userUuid: target.userUuid,
      }),
    ])
    return c.body(null, 200)
  })

  r.get(`${p}/members/:id/group-ids`, async (c) => {
    const db = createDb(c.env.DB)
    const target = await getTarget(db, orgOf(c), c.req.param('id'))
    const rows = await db
      .select({ g: schema.groupsUsers.groupUuid })
      .from(schema.groupsUsers)
      .where(eq(schema.groupsUsers.organizationUserUuid, target.uuid))
    return c.json(rows.map((r) => r.g))
  })

  r.put(`${p}/members/:id/group-ids`, async (c) => {
    const b = await body(c, z.object({ groupIds: z.array(z.string()).nullish() }))
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const target = await getTarget(db, orgUuid, c.req.param('id'))
    assertCanAssign(systemActor(orgUuid), target.atype)
    const groups = [...new Set(b.groupIds ?? [])]
    await checkRefs(db, orgUuid, [], groups)
    await batch(db, [
      ...accessStatements(db, target.uuid, false, null, groups, false),
      ev(db, c, {
        type: EventType.OrganizationUserUpdatedGroups,
        organizationUserUuid: target.uuid,
        userUuid: target.userUuid,
      }),
      bumpOrgRevision(db, orgUuid, Date.now()),
    ])
    return c.body(null, 200)
  })

  r.post(`${p}/members/:id/reinvite`, async (c) => {
    const db = createDb(c.env.DB)
    const target = await getTarget(db, orgOf(c), c.req.param('id'))
    if (target.status !== Status.Invited)
      throw new ApiError(400, 'User has already accepted the invitation.')
    await sendInvite(c, await requireOrg(db, orgOf(c)), target)
    return c.body(null, 200)
  })

  r.post(`${p}/members/:id/revoke`, async (c) => {
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const target = await getTarget(db, orgUuid, c.req.param('id'))
    assertCanAssign(systemActor(orgUuid), target.atype)
    if (target.status === Status.Revoked) throw new ApiError(400, 'User is already revoked.')
    await batch(db, [
      db
        .update(schema.usersOrganizations)
        .set({ status: Status.Revoked, updatedAt: Date.now() })
        .where(eq(schema.usersOrganizations.uuid, target.uuid)),
      ev(db, c, {
        type: EventType.OrganizationUserRevoked,
        organizationUserUuid: target.uuid,
        userUuid: target.userUuid,
      }),
      bumpOrgRevision(db, orgUuid, Date.now()),
    ])
    return c.body(null, 200)
  })

  r.post(`${p}/members/:id/restore`, async (c) => {
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const target = await getTarget(db, orgUuid, c.req.param('id'))
    assertCanAssign(systemActor(orgUuid), target.atype)
    if (target.status !== Status.Revoked) throw new ApiError(400, 'User is not revoked.')
    await batch(db, [
      db
        .update(schema.usersOrganizations)
        .set({ status: statusOnRestore(target), updatedAt: Date.now() })
        .where(eq(schema.usersOrganizations.uuid, target.uuid)),
      ev(db, c, {
        type: EventType.OrganizationUserRestored,
        organizationUserUuid: target.uuid,
        userUuid: target.userUuid,
      }),
      bumpOrgRevision(db, orgUuid, Date.now()),
    ])
    return c.body(null, 200)
  })
}

// ----- groups -----

type GroupRow = typeof schema.groups.$inferSelect

async function loadGroup(db: Db, orgUuid: string, id: string) {
  const [g] = await db
    .select()
    .from(schema.groups)
    .where(and(eq(schema.groups.uuid, id), eq(schema.groups.organizationUuid, orgUuid)))
    .limit(1)
  if (!g) throw new ApiError(404, 'Group not found.')
  return g
}

async function groupJson(db: Db, groups: GroupRow[]) {
  const ids = groups.map((g) => g.uuid)
  const grants = ids.length
    ? await db
        .select()
        .from(schema.collectionsGroups)
        .where(inArray(schema.collectionsGroups.groupUuid, ids))
    : []
  return groups.map((g) => ({
    object: 'group',
    id: g.uuid,
    name: g.name,
    externalId: g.externalId,
    collections: grants
      .filter((x) => x.groupUuid === g.uuid)
      .map((x) => association({ id: x.collectionUuid, ...x })),
  }))
}

const groupSchema = z.object({
  name: z.string().min(1).max(100),
  externalId: z.string().max(300).nullish(),
  collections: z.array(selectionSchema).nullish(),
})

function groupCollectionStatements(
  db: Db,
  groupUuid: string,
  cols: Selection[] | null,
  fresh: boolean,
) {
  if (cols === null) return []
  return [
    ...(fresh
      ? []
      : [
          db
            .delete(schema.collectionsGroups)
            .where(eq(schema.collectionsGroups.groupUuid, groupUuid)),
        ]),
    ...cols.map((s) =>
      db
        .insert(schema.collectionsGroups)
        .values({ groupUuid, collectionUuid: s.id, ...accessOf(s) }),
    ),
  ]
}

function registerGroups(r: Hono<Env>, p: string) {
  r.get(`${p}/groups`, async (c) => {
    const db = createDb(c.env.DB)
    const rows = await db
      .select()
      .from(schema.groups)
      .where(eq(schema.groups.organizationUuid, orgOf(c)))
    return c.json(list(await groupJson(db, rows)))
  })

  r.post(`${p}/groups`, async (c) => {
    const b = await body(c, groupSchema)
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const cols = dedupeSelections(b.collections ?? [])
    await checkRefs(db, orgUuid, cols, [])
    const uuid = crypto.randomUUID()
    const now = Date.now()
    await batch(db, [
      db.insert(schema.groups).values({
        uuid,
        organizationUuid: orgUuid,
        name: b.name,
        accessAll: false,
        externalId: b.externalId ?? null,
        createdAt: now,
        updatedAt: now,
      }),
      ...groupCollectionStatements(db, uuid, cols, true),
      ev(db, c, { type: EventType.GroupCreated, groupUuid: uuid }),
      bumpOrgRevision(db, orgUuid, now),
    ])
    return c.json((await groupJson(db, [await loadGroup(db, orgUuid, uuid)]))[0])
  })

  r.get(`${p}/groups/:id`, async (c) => {
    const db = createDb(c.env.DB)
    return c.json((await groupJson(db, [await loadGroup(db, orgOf(c), c.req.param('id'))]))[0])
  })

  r.put(`${p}/groups/:id`, async (c) => {
    const b = await body(c, groupSchema)
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const g = await loadGroup(db, orgUuid, c.req.param('id'))
    // The published model has no `accessAll`. A property that is not provided is reset, so a PUT
    // ends blanket access and applies the collections it names.
    const cols = b.collections == null ? null : dedupeSelections(b.collections)
    await checkRefs(db, orgUuid, cols ?? [], [])
    const now = Date.now()
    await batch(db, [
      db
        .update(schema.groups)
        .set({
          name: b.name,
          accessAll: false,
          externalId: b.externalId ?? null,
          updatedAt: now,
        })
        .where(eq(schema.groups.uuid, g.uuid)),
      ...groupCollectionStatements(db, g.uuid, cols, false),
      ev(db, c, { type: EventType.GroupUpdated, groupUuid: g.uuid }),
      bumpOrgRevision(db, orgUuid, now),
    ])
    return c.json((await groupJson(db, [await loadGroup(db, orgUuid, g.uuid)]))[0])
  })

  r.delete(`${p}/groups/:id`, async (c) => {
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const g = await loadGroup(db, orgUuid, c.req.param('id'))
    await batch(db, [
      bumpOrgRevision(db, orgUuid, Date.now()),
      db.delete(schema.groups).where(eq(schema.groups.uuid, g.uuid)),
      ev(db, c, { type: EventType.GroupDeleted, groupUuid: g.uuid }),
    ])
    return c.body(null, 200)
  })

  r.get(`${p}/groups/:id/member-ids`, async (c) => {
    const db = createDb(c.env.DB)
    const g = await loadGroup(db, orgOf(c), c.req.param('id'))
    const rows = await db
      .select({ m: schema.groupsUsers.organizationUserUuid })
      .from(schema.groupsUsers)
      .where(eq(schema.groupsUsers.groupUuid, g.uuid))
    return c.json(rows.map((r) => r.m))
  })

  r.put(`${p}/groups/:id/member-ids`, async (c) => {
    const b = await body(c, z.object({ memberIds: z.array(z.string()).nullish() }))
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const g = await loadGroup(db, orgUuid, c.req.param('id'))
    const members = [...new Set(b.memberIds ?? [])]
    if (members.length) await assertIdsInOrg(db, 'member', orgUuid, members)
    await batch(db, [
      db.delete(schema.groupsUsers).where(eq(schema.groupsUsers.groupUuid, g.uuid)),
      ...members.map((m) =>
        db.insert(schema.groupsUsers).values({ groupUuid: g.uuid, organizationUserUuid: m }),
      ),
      ev(db, c, { type: EventType.GroupUpdated, groupUuid: g.uuid }),
      bumpOrgRevision(db, orgUuid, Date.now()),
    ])
    return c.body(null, 200)
  })
}

// ----- collections -----

type CollectionRow = typeof schema.collections.$inferSelect

async function loadCollection(db: Db, orgUuid: string, id: string) {
  const [col] = await db
    .select()
    .from(schema.collections)
    .where(and(eq(schema.collections.uuid, id), eq(schema.collections.organizationUuid, orgUuid)))
    .limit(1)
  if (!col) throw new ApiError(404, 'Collection not found.')
  return col
}

async function collectionJson(db: Db, cols: CollectionRow[]) {
  const ids = cols.map((x) => x.uuid)
  const grants = ids.length
    ? await db
        .select()
        .from(schema.collectionsGroups)
        .where(inArray(schema.collectionsGroups.collectionUuid, ids))
    : []
  return cols.map((col) => ({
    object: 'collection',
    id: col.uuid,
    externalId: col.externalId,
    groups: grants
      .filter((g) => g.collectionUuid === col.uuid)
      .map((g) => association({ id: g.groupUuid, ...g })),
  }))
}

function registerCollections(r: Hono<Env>, p: string) {
  r.get(`${p}/collections`, async (c) => {
    const db = createDb(c.env.DB)
    const rows = await db
      .select()
      .from(schema.collections)
      .where(eq(schema.collections.organizationUuid, orgOf(c)))
    return c.json(list(await collectionJson(db, rows)))
  })

  r.get(`${p}/collections/:id`, async (c) => {
    const db = createDb(c.env.DB)
    return c.json(
      (await collectionJson(db, [await loadCollection(db, orgOf(c), c.req.param('id'))]))[0],
    )
  })

  r.put(`${p}/collections/:id`, async (c) => {
    const b = await body(
      c,
      z.object({
        externalId: z.string().max(300).nullish(),
        groups: z.array(selectionSchema).nullish(),
      }),
    )
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const col = await loadCollection(db, orgUuid, c.req.param('id'))
    const groups = b.groups == null ? null : dedupeSelections(b.groups)
    if (groups?.length)
      await assertIdsInOrg(
        db,
        'group',
        orgUuid,
        groups.map((g) => g.id),
      )
    const now = Date.now()
    await batch(db, [
      db
        .update(schema.collections)
        .set({ externalId: b.externalId ?? null, updatedAt: now })
        .where(eq(schema.collections.uuid, col.uuid)),
      ...(groups === null
        ? []
        : [
            db
              .delete(schema.collectionsGroups)
              .where(eq(schema.collectionsGroups.collectionUuid, col.uuid)),
            ...groups.map((g) =>
              db
                .insert(schema.collectionsGroups)
                .values({ collectionUuid: col.uuid, groupUuid: g.id, ...accessOf(g) }),
            ),
          ]),
      ev(db, c, { type: EventType.CollectionUpdated, collectionUuid: col.uuid }),
      bumpOrgRevision(db, orgUuid, now),
    ])
    return c.json((await collectionJson(db, [await loadCollection(db, orgUuid, col.uuid)]))[0])
  })

  r.delete(`${p}/collections/:id`, async (c) => {
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const col = await loadCollection(db, orgUuid, c.req.param('id'))
    await batch(db, [
      bumpOrgRevision(db, orgUuid, Date.now()),
      db.delete(schema.collections).where(eq(schema.collections.uuid, col.uuid)),
      ev(db, c, { type: EventType.CollectionDeleted, collectionUuid: col.uuid }),
    ])
    return c.body(null, 200)
  })
}

// ----- policies -----

type PolicyRow = typeof schema.policies.$inferSelect

const policyJson = (p: PolicyRow) => ({
  object: 'policy',
  id: p.uuid,
  type: p.atype,
  enabled: p.enabled,
  data: parseData(p.data),
})

const policyType = (c: Ctx) => {
  const t = Number(c.req.param('type'))
  if (!Number.isInteger(t) || t < 0 || t > MAX_POLICY_TYPE)
    throw new ApiError(400, 'Invalid policy type.')
  return t
}

/**
 * Policy metadata is data the policy needs when it is turned on but that is not part of its
 * stored data. Only the organisation data ownership policy has any (the name of the default
 * collection). Cloudwarden validates it and stores nothing.
 */
function assertPolicyMetadata(type: number, metadata: Record<string, unknown> | null | undefined) {
  if (!metadata) return
  const name = metadata.defaultUserCollectionName
  if (type === PolicyType.PersonalOwnership && name != null && typeof name !== 'string')
    throw new ApiError(400, 'The request is invalid.', {
      'metadata.defaultUserCollectionName': ['Must be a string.'],
    })
}

function registerPolicies(r: Hono<Env>, p: string) {
  r.get(`${p}/policies`, async (c) => {
    const rows = await createDb(c.env.DB)
      .select()
      .from(schema.policies)
      .where(eq(schema.policies.organizationUuid, orgOf(c)))
    return c.json(list(rows.map(policyJson)))
  })

  r.get(`${p}/policies/:type`, async (c) => {
    const row = await findPolicy(createDb(c.env.DB), orgOf(c), policyType(c))
    if (!row) throw new ApiError(404, 'Policy not found.')
    return c.json(policyJson(row))
  })

  r.put(`${p}/policies/:type`, async (c) => {
    const type = policyType(c)
    const b = await body(
      c,
      z.object({
        enabled: z.boolean(),
        data: z.record(z.string(), z.unknown()).nullish(),
        metadata: z.record(z.string(), z.unknown()).nullish(),
      }),
    )
    assertPolicyData(type, b.data)
    assertPolicyMetadata(type, b.metadata)
    const db = createDb(c.env.DB)
    const row = await savePolicy(c, db, orgOf(c), type, b, EventSystemUser.PublicApi)
    return c.json(policyJson(row))
  })
}

// ----- events -----

const publicEventJson = (e: typeof schema.events.$inferSelect) => ({
  object: 'event',
  type: e.eventType,
  itemId: e.cipherUuid,
  collectionId: e.collectionUuid,
  groupId: e.groupUuid,
  policyId: e.policyUuid,
  memberId: e.organizationUserUuid,
  actingUserId: e.actingUserUuid,
  installationId: null,
  date: new Date(e.eventDate).toISOString(),
  device: e.deviceType,
  ipAddress: e.ipAddress,
  secretId: e.secretUuid,
  projectId: e.projectUuid,
  serviceAccountId: e.serviceAccountUuid,
})

function registerEvents(r: Hono<Env>, p: string) {
  r.get(`${p}/events`, async (c) => {
    const e = schema.events
    const range = publicEventRange(c.req.query('start'), c.req.query('end'))
    const where: SQL[] = [eq(e.organizationUuid, orgOf(c))]
    // The first filter present wins, in this order. With none, the whole organisation is listed.
    const filters: [string, AnyColumn][] = [
      ['actingUserId', e.actingUserUuid],
      ['itemId', e.cipherUuid],
      ['secretId', e.secretUuid],
      ['projectId', e.projectUuid],
    ]
    for (const [name, column] of filters) {
      const value = c.req.query(name)
      if (!value) continue
      where.push(eq(column, value))
      break
    }
    const page = await listEvents(createDb(c.env.DB), c, and(...where), publicEventJson, range)
    return c.json(page)
  })
}

// ----- organisation -----

function registerOrganization(r: Hono<Env>, p: string) {
  r.get(`${p}/organization/subscription`, async (c) => {
    return c.json(subscriptionJson(await loadSubscription(createDb(c.env.DB), orgOf(c))))
  })

  r.put(`${p}/organization/subscription`, async (c) => {
    const b = await body(c, subscriptionUpdateSchema)
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const now = Date.now()
    const row = await mergeSubscription(db, orgUuid, await loadSubscription(db, orgUuid), b, now)
    await batch(db, [
      subscriptionUpsert(db, row, b),
      ev(db, c, { type: EventType.OrganizationUpdated }),
      bumpOrgRevision(db, orgUuid, now),
    ])
    return c.body(null, 200)
  })

  r.post(`${p}/organization/import`, async (c) => {
    const b = await body(c, publicImportSchema)
    await importDirectory(c, orgOf(c), b, EventSystemUser.PublicApi)
    return c.body(null, 200)
  })
}

for (const p of PREFIXES) {
  publicApi.use(`${p}/*`, requireOrgApiAuth)
  registerMembers(publicApi, p)
  registerGroups(publicApi, p)
  registerCollections(publicApi, p)
  registerPolicies(publicApi, p)
  registerEvents(publicApi, p)
  registerOrganization(publicApi, p)
}

publicApi.onError((err, c) => {
  if (err instanceof ApiError) return fail(c, err.status, err.message, err.validationErrors)
  log(
    'error',
    'unhandled',
    { errorKind: errorKind(err), method: c.req.method, route: c.req.routePath },
    c.env,
  )
  return fail(c, 500, 'An error has occurred.')
})
