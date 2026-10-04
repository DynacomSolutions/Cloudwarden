import { and, eq, inArray, isNull, ne } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { createDb, type Db, runBatch, schema } from '../db'
import { emailVerifiedFor } from '../emailless'
import type { Env } from '../env'
import { ApiError } from '../errors'
import {
  bumpOrgRevision,
  can,
  collectionAccess,
  getMember,
  isAdminRole,
  loadUserAccess,
  manageAll,
  requireMember,
  requireOrg,
} from '../orgs/access'
import { listOrgCipherRows, orgCipherJson } from '../orgs/ciphers'
import { EventType, PolicyType, Role, Status } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import { notifyOrgKeys } from '../orgs/notify'
import {
  assertAutoConfirmEligible,
  assertTwoFactorCompliant,
  enabledPolicy,
  parseData,
  policyJson,
} from '../orgs/policies'
import { authOnce, batch } from '../orgs/util'
import { collectionJson, orgJson } from '../orgs/views'
import { rateLimit } from '../ratelimit'
import { parseBody } from '../validation'

/**
 * Organisation settings, export and invite links (TASKS #231). Mounted
 * before the other organisation routers: the public invite-link routes must not meet their
 * `authOnce` middleware.
 */
export const orgSettings = new Hono<Env>()

type Ctx = Context<Env>
type LinkRow = typeof schema.orgInviteLinks.$inferSelect

const FORBIDDEN = () => new ApiError(403, 'You do not have permission to do this.')
const list = (data: unknown[]) => ({ object: 'list', data, continuationToken: null })

// ----- public invite-link routes (no account yet) -----

const publicLimit = rateLimit('invite-link', 60)
const codeSchema = z
  .object({ organizationId: z.string().min(1), code: z.string().min(1) })
  .transform(({ code, ...rest }) => ({ ...rest, linkCode: code }))

/** The link of the organisation when `code` matches it; one error for every mismatch. */
async function linkByCode(db: Db, organizationId: string, code: string) {
  const [link] = await db
    .select()
    .from(schema.orgInviteLinks)
    .where(
      and(
        eq(schema.orgInviteLinks.organizationUuid, organizationId),
        eq(schema.orgInviteLinks.joinCode, code),
      ),
    )
    .limit(1)
  if (!link) throw new ApiError(404, 'Invite link not found.')
  return link
}

const domains = (link: LinkRow) => JSON.parse(link.allowedDomains) as string[]

orgSettings.post('/api/organizations/invite-link/status', publicLimit, async (c) => {
  const body = await parseBody(c, codeSchema)
  const db = createDb(c.env.DB)
  const link = await linkByCode(db, body.organizationId, body.linkCode)
  const org = await requireOrg(db, body.organizationId)
  return c.json({
    object: 'organizationInviteLinkStatus',
    organizationName: org.name,
    linksEnabled: true,
    // Self-hosted organisations have no seat limit.
    seatsAvailable: true,
    supportsConfirmation: link.supportsConfirmation,
    // No single sign-on on this server.
    sso: null,
  })
})

orgSettings.post('/api/organizations/invite-link/policies', publicLimit, async (c) => {
  const body = await parseBody(c, codeSchema)
  const db = createDb(c.env.DB)
  await linkByCode(db, body.organizationId, body.linkCode)
  const rows = await db
    .select()
    .from(schema.policies)
    .where(
      and(
        eq(schema.policies.organizationUuid, body.organizationId),
        eq(schema.policies.enabled, true),
      ),
    )
  return c.json(list(rows.map(policyJson)))
})

orgSettings.post('/api/organizations/invite-link/validate-email-domain', publicLimit, async (c) => {
  const body = await parseBody(
    c,
    z
      .object({
        organizationId: z.string().min(1),
        code: z.string().min(1),
        email: z.string().min(3).max(256),
      })
      .transform(({ code, ...rest }) => ({ ...rest, linkCode: code })),
  )
  const link = await linkByCode(createDb(c.env.DB), body.organizationId, body.linkCode)
  const domain = body.email.trim().toLowerCase().split('@').pop() ?? ''
  return c.json({
    object: 'organizationInviteLinkValidateEmailDomain',
    isAllowed: body.email.includes('@') && domains(link).includes(domain),
  })
})

// ----- authenticated routes -----

for (const path of [
  '/api/organizations/:orgId/collection-management',
  '/api/organizations/:orgId/export',
  '/api/organizations/:orgId/invite-link',
  '/api/organizations/:orgId/invite-link/*',
  '/api/organizations/users/invite-link/*',
]) {
  orgSettings.use(path, authOnce)
}

const org = (c: Ctx) => c.req.param('orgId') ?? ''

/** Owners and admins only: the settings page of the Admin Console. */
async function requireAdmin(c: Ctx) {
  const m = await requireMember(createDb(c.env.DB), c.var.user.uuid, org(c))
  if (!isAdminRole(m)) throw FORBIDDEN()
  return m
}

const collectionManagementSchema = z.object({
  limitCollectionCreation: z.boolean(),
  limitCollectionDeletion: z.boolean(),
  limitItemDeletion: z.boolean(),
  allowAdminAccessToAllCollectionItems: z.boolean(),
})

orgSettings.put('/api/organizations/:orgId/collection-management', async (c) => {
  const body = await parseBody(c, collectionManagementSchema)
  await requireAdmin(c)
  const db = createDb(c.env.DB)
  const now = Date.now()
  await runBatch(db, [
    db
      .update(schema.organizations)
      .set({ ...body, updatedAt: now })
      .where(eq(schema.organizations.uuid, org(c))),
    eventStatement(db, c, { type: EventType.OrganizationUpdated, organizationUuid: org(c) }),
    bumpOrgRevision(db, org(c), now),
  ])
  return c.json(orgJson(await requireOrg(db, org(c))))
})

// Every collection and every live item of the organisation, as the Admin Console export reads it.
orgSettings.get('/api/organizations/:orgId/export', async (c) => {
  const db = createDb(c.env.DB)
  const m = await requireMember(db, c.var.user.uuid, org(c))
  if (!can(m, 'accessImportExport')) throw FORBIDDEN()
  if (!(await manageAll(db, m))) {
    // Without access to every item, the export holds only what the member can reach.
    const ua = await loadUserAccess(db, c.var.user.uuid)
    const rows = (await listOrgCipherRows(db, c.var.user.uuid, ua)).filter(
      (r) => r.cipher.organizationUuid === org(c) && r.cipher.deletedAt === null,
    )
    const own = await db
      .select()
      .from(schema.collections)
      .where(eq(schema.collections.organizationUuid, org(c)))
    return c.json({
      object: 'organizationExport',
      collections: own.filter((x) => collectionAccess(ua, org(c), x.uuid)).map(collectionJson),
      ciphers: rows.map((r) => orgCipherJson({ ...r, folderId: null })),
    })
  }
  const [collections, ciphers, links] = await Promise.all([
    db
      .select()
      .from(schema.collections)
      .where(eq(schema.collections.organizationUuid, org(c))),
    db
      .select()
      .from(schema.ciphers)
      .where(and(eq(schema.ciphers.organizationUuid, org(c)), isNull(schema.ciphers.deletedAt))),
    db
      .select({
        cipher: schema.ciphersCollections.cipherUuid,
        id: schema.ciphersCollections.collectionUuid,
      })
      .from(schema.ciphersCollections)
      .innerJoin(
        schema.collections,
        eq(schema.collections.uuid, schema.ciphersCollections.collectionUuid),
      )
      .where(eq(schema.collections.organizationUuid, org(c))),
  ])
  const byCipher = new Map<string, string[]>()
  for (const l of links) byCipher.set(l.cipher, [...(byCipher.get(l.cipher) ?? []), l.id])
  return c.json({
    object: 'organizationExport',
    collections: collections.map(collectionJson),
    ciphers: ciphers.map((cipher) =>
      orgCipherJson({
        cipher,
        folderId: null,
        access: {
          edit: true,
          viewPassword: true,
          manage: true,
          collectionIds: byCipher.get(cipher.uuid) ?? [],
        },
      }),
    ),
  })
})

// ----- invite links (managed by members who manage users) -----

/** Setting `supportsConfirmation` lets joiners confirm themselves, so only owners and admins may. */
function requireAdminToConfirm(m: { atype: number }, wants: boolean | null | undefined) {
  if (wants === true && m.atype !== Role.Owner && m.atype !== Role.Admin) throw FORBIDDEN()
}

async function requireUserManager(c: Ctx) {
  const m = await requireMember(createDb(c.env.DB), c.var.user.uuid, org(c))
  if (!can(m, 'manageUsers')) throw FORBIDDEN()
  return m
}

async function currentLink(db: Db, orgUuid: string) {
  const [link] = await db
    .select()
    .from(schema.orgInviteLinks)
    .where(eq(schema.orgInviteLinks.organizationUuid, orgUuid))
    .limit(1)
  return link
}

const linkJson = (l: LinkRow) => ({
  object: 'organizationInviteLink',
  id: l.uuid,
  code: l.joinCode,
  organizationId: l.organizationUuid,
  allowedDomains: domains(l),
  invite: l.invite,
  supportsConfirmation: l.supportsConfirmation,
  creationDate: new Date(l.createdAt).toISOString(),
})

const domainList = z
  .array(
    z
      .string()
      .trim()
      .toLowerCase()
      .regex(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/, 'Invalid domain.'),
  )
  .min(1)
  .max(100)
  .transform((d) => [...new Set(d)])
// The invite is an opaque string of key material the client builds and reads back; the server only stores it.
const inviteMaterial = z.string().min(1).max(16384)

async function loadLinkOr404(db: Db, orgUuid: string) {
  const link = await currentLink(db, orgUuid)
  if (!link) throw new ApiError(404, 'Invite link not found.')
  return link
}

orgSettings.get('/api/organizations/:orgId/invite-link', async (c) => {
  await requireUserManager(c)
  return c.json(linkJson(await loadLinkOr404(createDb(c.env.DB), org(c))))
})

orgSettings.post('/api/organizations/:orgId/invite-link', async (c) => {
  const body = await parseBody(
    c,
    z.object({
      allowedDomains: domainList,
      invite: inviteMaterial,
      supportsConfirmation: z.boolean().nullish(),
    }),
  )
  requireAdminToConfirm(await requireUserManager(c), body.supportsConfirmation)
  const db = createDb(c.env.DB)
  if (await currentLink(db, org(c)))
    throw new ApiError(400, 'This organization already has an invite link.')
  const now = Date.now()
  const uuid = crypto.randomUUID()
  await runBatch(db, [
    db.insert(schema.orgInviteLinks).values({
      uuid,
      organizationUuid: org(c),
      joinCode: crypto.randomUUID(),
      allowedDomains: JSON.stringify(body.allowedDomains),
      invite: body.invite,
      supportsConfirmation: body.supportsConfirmation === true,
      createdAt: now,
      updatedAt: now,
    }),
  ])
  return c.json(linkJson(await loadLinkOr404(db, org(c))))
})

orgSettings.put('/api/organizations/:orgId/invite-link', async (c) => {
  const body = await parseBody(c, z.object({ allowedDomains: domainList }))
  await requireUserManager(c)
  const db = createDb(c.env.DB)
  const link = await loadLinkOr404(db, org(c))
  await runBatch(db, [
    db
      .update(schema.orgInviteLinks)
      .set({ allowedDomains: JSON.stringify(body.allowedDomains), updatedAt: Date.now() })
      .where(eq(schema.orgInviteLinks.uuid, link.uuid)),
  ])
  return c.json(linkJson(await loadLinkOr404(db, org(c))))
})

/** A new code and key material: links shared before stop working. */
orgSettings.post('/api/organizations/:orgId/invite-link/refresh', async (c) => {
  const body = await parseBody(
    c,
    z.object({ invite: inviteMaterial, supportsConfirmation: z.boolean().nullish() }),
  )
  requireAdminToConfirm(await requireUserManager(c), body.supportsConfirmation)
  const db = createDb(c.env.DB)
  const link = await loadLinkOr404(db, org(c))
  await runBatch(db, [
    db
      .update(schema.orgInviteLinks)
      .set({
        joinCode: crypto.randomUUID(),
        invite: body.invite,
        supportsConfirmation: body.supportsConfirmation ?? link.supportsConfirmation,
        updatedAt: Date.now(),
      })
      .where(eq(schema.orgInviteLinks.uuid, link.uuid)),
  ])
  return c.json(linkJson(await loadLinkOr404(db, org(c))))
})

orgSettings.put('/api/organizations/:orgId/invite-link/support-confirm', async (c) => {
  const body = await parseBody(
    c,
    z.object({ invite: inviteMaterial, supportsConfirmation: z.boolean() }),
  )
  requireAdminToConfirm(await requireUserManager(c), body.supportsConfirmation)
  const db = createDb(c.env.DB)
  const link = await loadLinkOr404(db, org(c))
  await runBatch(db, [
    db
      .update(schema.orgInviteLinks)
      .set({
        invite: body.invite,
        supportsConfirmation: body.supportsConfirmation,
        updatedAt: Date.now(),
      })
      .where(eq(schema.orgInviteLinks.uuid, link.uuid)),
  ])
  return c.json(linkJson(await loadLinkOr404(db, org(c))))
})

orgSettings.delete('/api/organizations/:orgId/invite-link', async (c) => {
  await requireUserManager(c)
  const db = createDb(c.env.DB)
  await runBatch(db, [
    db.delete(schema.orgInviteLinks).where(eq(schema.orgInviteLinks.organizationUuid, org(c))),
  ])
  return c.body(null, 200)
})

// ----- joining through a link (the invitee is signed in) -----

const joinSchema = z.object({
  organizationId: z.string().min(1),
  code: z.string().min(1),
  resetPasswordKey: z.string().nullish(),
})

const confirmSchema = joinSchema.extend({
  orgUserKey: z.string().min(1),
  defaultUserCollectionName: z.string().nullish(),
})

/** Everything that must hold before an account joins; each failure has the message the clients match. */
async function checkJoin(
  c: Ctx,
  db: Db,
  body: z.infer<typeof joinSchema>,
  link: LinkRow,
  confirming: boolean,
) {
  const user = c.var.user
  const org = await requireOrg(db, body.organizationId)
  if (!emailVerifiedFor(c.env, user)) {
    throw new ApiError(400, 'You must verify your email address before joining an organization.')
  }
  const domain = user.email.toLowerCase().split('@').pop() ?? ''
  if (!domains(link).includes(domain)) {
    throw new ApiError(
      400,
      `You're not allowed to join the ${org.name} vault with your email domain.`,
    )
  }
  const existing = await getMember(db, user.uuid, org.uuid)
  if (existing?.status === Status.Revoked) {
    throw new ApiError(400, `Your access to the ${org.name} vault has been revoked.`)
  }
  if (existing) throw new ApiError(400, `You're already a member of ${org.name}.`)
  if (confirming && !link.supportsConfirmation) {
    throw new ApiError(400, 'This invite link does not support confirmation.')
  }
  // Joining without an administrator's confirmation needs the organisation to have opted in.
  if (confirming && !(await enabledPolicy(db, org.uuid, PolicyType.AutomaticUserConfirmation))) {
    throw new ApiError(400, 'This organization does not confirm members automatically.')
  }
  try {
    await assertTwoFactorCompliant(db, user.uuid, org.uuid)
  } catch {
    throw new ApiError(
      400,
      'You cannot join this organization vault until you enable two-step login on your user account.',
    )
  }
  const others = await db
    .select({
      orgUuid: schema.usersOrganizations.organizationUuid,
      type: schema.usersOrganizations.atype,
    })
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.userUuid, user.uuid),
        inArray(schema.usersOrganizations.status, [Status.Accepted, Status.Confirmed]),
        ne(schema.usersOrganizations.organizationUuid, org.uuid),
      ),
    )
  if (others.length > 0 && (await enabledPolicy(db, org.uuid, PolicyType.SingleOrg))) {
    throw new ApiError(
      400,
      'Member cannot join this organization vault until they leave all other organization vaults.',
    )
  }
  for (const o of others) {
    if (
      o.type !== Role.Owner &&
      o.type !== Role.Admin &&
      (await enabledPolicy(db, o.orgUuid, PolicyType.SingleOrg))
    ) {
      throw new ApiError(
        400,
        "Member cannot join this organization's vault because they are a member of another organization which forbids it.",
      )
    }
  }
  if (confirming) await assertAutoConfirmEligible(db, org.uuid, user.uuid, user.email)
  const reset = await enabledPolicy(db, org.uuid, PolicyType.ResetPassword)
  if (reset && parseData(reset.data)?.autoEnrollEnabled === true && !body.resetPasswordKey) {
    throw new ApiError(400, 'Master Password reset is required, but not provided.')
  }
  return org
}

/** The key material of the link, for a signed-in account that knows the link code. */
orgSettings.post('/api/organizations/users/invite-link/invite', publicLimit, async (c) => {
  const body = await parseBody(c, codeSchema)
  const link = await linkByCode(createDb(c.env.DB), body.organizationId, body.linkCode)
  return c.json({ object: 'organizationInvite', invite: link.invite })
})

async function join(c: Ctx, confirming: boolean) {
  const confirm = confirming
    ? await parseBody(c, confirmSchema)
    : { ...(await parseBody(c, joinSchema)), orgUserKey: '', defaultUserCollectionName: null }
  const body = confirm
  const db = createDb(c.env.DB)
  const user = c.var.user
  const { code: linkCode } = body
  const link = await linkByCode(db, body.organizationId, linkCode)
  const org = await checkJoin(c, db, body, link, confirming)
  const now = Date.now()
  const memberUuid = crypto.randomUUID()
  const key = body.orgUserKey
  const collectionName = body.defaultUserCollectionName
  const ownDefault =
    confirming &&
    collectionName &&
    (await enabledPolicy(db, org.uuid, PolicyType.PersonalOwnership))
  const collectionUuid = crypto.randomUUID()
  const member: typeof schema.usersOrganizations.$inferInsert = {
    uuid: memberUuid,
    userUuid: user.uuid,
    organizationUuid: org.uuid,
    email: user.email,
    permissions: null,
    accessAll: false,
    akey: key,
    status: confirming ? Status.Confirmed : Status.Accepted,
    atype: Role.User,
    resetPasswordKey: body.resetPasswordKey ?? null,
    externalId: null,
    accessSecretsManager: false,
    accessPam: false,
    createdAt: now,
    updatedAt: now,
  }
  try {
    await batch(db, [
      db.insert(schema.usersOrganizations).values(member),
      ...(ownDefault
        ? [
            db.insert(schema.collections).values({
              uuid: collectionUuid,
              organizationUuid: org.uuid,
              name: collectionName as string,
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
      eventStatement(db, c, {
        type: EventType.OrganizationUserConfirmed,
        organizationUuid: org.uuid,
        organizationUserUuid: memberUuid,
        userUuid: user.uuid,
      }),
      bumpOrgRevision(db, org.uuid, now),
      db.update(schema.users).set({ updatedAt: now }).where(eq(schema.users.uuid, user.uuid)),
    ])
  } catch {
    throw new ApiError(400, `You're already a member of ${org.name}.`)
  }
  if (confirming) notifyOrgKeys(c, user.uuid)
  return c.body(null, 200)
}

/** Joins as an accepted member; an administrator confirms later. */
orgSettings.post('/api/organizations/users/invite-link/accept', publicLimit, (c) => join(c, false))
/** Joins and confirms in one step, with the organisation key the client sealed to the account. */
orgSettings.post('/api/organizations/users/invite-link/confirm', publicLimit, (c) => join(c, true))
