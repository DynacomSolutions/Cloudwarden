import { and, eq, isNotNull, ne } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { authenticationData, checkNested, unlockData } from '../auth/credentials'
import { requireAuth } from '../auth/middleware'
import { hashMasterPassword } from '../auth/passwords'
import { signPurposeToken } from '../auth/purpose-token'
import { createDb, runBatch, schema } from '../db'
import type { Env, User } from '../env'
import { ApiError } from '../errors'
import {
  bumpOrgRevision,
  getMember,
  isAdminRole,
  requireOrg,
  requirePermission,
} from '../orgs/access'
import { EventType, PolicyType, Status } from '../orgs/constants'
import {
  checkDomain,
  claimedElsewhere,
  DOMAIN_MAX_CHECKS,
  domainJson,
  emailDomain,
  newDomainToken,
  normalizeDomain,
  orgClaimsEmail,
} from '../orgs/domains'
import { eventStatement } from '../orgs/events'
import { assertNotSoleOwner } from '../orgs/members'
import { parseData } from '../orgs/policies'
import { authOnce, batch } from '../orgs/util'
import { rateLimit } from '../ratelimit'
import {
  loadSsoConfig,
  MemberDecryptionType,
  orgByIdentifier,
  parseConfigData,
  type SsoConfigData,
  SsoType,
  ssoConfigSchema,
  ssoUrls,
} from '../sso/config'
import { hasMasterPassword } from '../sso/decryption'
import { SsoError } from '../sso/errors'
import { LINK_PURPOSE, LINK_TTL_SECONDS } from '../sso/flow'
import { testOidc } from '../sso/oidc'
import { testSaml } from '../sso/saml'
import { ensureSpKeys, SsoEventType } from '../sso/sp-keys'
import { kdfProblem, parseBody } from '../validation'
import { userAttachmentKeys } from '../vault/attachments'
import { deleteBlobs } from '../vault/blobs'
import { userSendKeys } from '../vault/sends'

/**
 * Organisation SSO settings, claimed domains, and the account endpoints of the SSO, trusted
 * device and key connector flows (TASKS #280 to #286).
 */

type Ctx = Context<Env>

// ----- Anonymous: SSO discovery by email (mounted before the authenticated routers) -----

export const publicSso = new Hono<Env>()

const emailBody = z.object({ email: z.string().min(3).max(256) })

async function ssoDomainsFor(c: Ctx, email: string) {
  const domain = emailDomain(email)
  if (!domain) return []
  const db = createDb(c.env.DB)
  return db
    .select({ org: schema.organizations, d: schema.organizationDomains })
    .from(schema.organizationDomains)
    .innerJoin(
      schema.organizations,
      eq(schema.organizations.uuid, schema.organizationDomains.organizationUuid),
    )
    .innerJoin(schema.ssoConfigs, eq(schema.ssoConfigs.organizationUuid, schema.organizations.uuid))
    .where(
      and(
        eq(schema.organizationDomains.domainName, domain),
        isNotNull(schema.organizationDomains.verifiedAt),
        eq(schema.ssoConfigs.enabled, true),
        isNotNull(schema.organizations.identifier),
      ),
    )
}

publicSso.post('/api/organizations/domain/sso/verified', rateLimit('sso-domain'), async (c) => {
  const { email } = await parseBody(c, emailBody)
  const rows = await ssoDomainsFor(c, email)
  return c.json({
    object: 'list',
    data: rows.map((r) => ({
      object: 'verifiedOrganizationDomainSsoDetails',
      organizationName: r.org.name,
      organizationIdentifier: r.org.identifier,
      domainName: r.d.domainName,
    })),
    continuationToken: null,
  })
})

publicSso.post('/api/organizations/domain/sso/details', rateLimit('sso-domain'), async (c) => {
  const { email } = await parseBody(c, emailBody)
  const [row] = await ssoDomainsFor(c, email)
  if (!row) throw new ApiError(404, 'Claimed domain not found.')
  return c.json({
    object: 'organizationDomainSsoDetails',
    id: row.d.uuid,
    organizationIdentifier: row.org.identifier,
    ssoAvailable: true,
    domainName: row.d.domainName,
    verifiedDate: new Date(row.d.verifiedAt ?? 0).toISOString(),
  })
})

// ----- Organisation SSO configuration -----

export const ssoAdmin = new Hono<Env>()
ssoAdmin.use('/api/organizations/*', authOnce)

const orgParam = (c: Ctx) => c.req.param('orgId') ?? ''

async function ssoJson(c: Ctx, orgUuid: string) {
  const db = createDb(c.env.DB)
  const org = await requireOrg(db, orgUuid)
  const row = await loadSsoConfig(db, orgUuid)
  const urls = ssoUrls(c.env, orgUuid)
  return {
    object: 'organizationSso',
    enabled: row?.enabled ?? false,
    identifier: org.identifier,
    data: row ? { ...parseConfigData(row) } : null,
    urls: {
      callbackPath: urls.callbackPath,
      signedOutCallbackPath: urls.signedOutCallbackPath,
      spEntityId: urls.spEntityId,
      spEntityIdStatic: urls.spEntityIdStatic,
      spMetadataUrl: urls.spMetadataUrl,
      spAcsUrl: urls.spAcsUrl,
    },
  }
}

ssoAdmin.get('/api/organizations/:orgId/sso', async (c) => {
  await requirePermission(createDb(c.env.DB), c.var.user.uuid, orgParam(c), 'manageSso')
  return c.json(await ssoJson(c, orgParam(c)))
})

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,49}$/
const saveSchema = z.object({
  enabled: z.boolean(),
  identifier: z.string().max(50).nullish(),
  data: ssoConfigSchema.nullish(),
})

const httpsUrl = (v: string | null | undefined) => {
  try {
    return new URL(v ?? '').protocol === 'https:'
  } catch {
    return false
  }
}

/** Field problems of a configuration about to be enabled. */
function configProblems(data: SsoConfigData): Record<string, string[]> {
  const errors: Record<string, string[]> = {}
  const add = (k: string, m: string) => {
    errors[k] = [...(errors[k] ?? []), m]
  }
  if (data.configType === SsoType.OpenIdConnect) {
    if (!httpsUrl(data.authority)) add('authority', 'An https authority URL is required.')
    if (!data.clientId?.trim()) add('clientId', 'The client ID is required.')
    if (data.metadataAddress && !httpsUrl(data.metadataAddress))
      add('metadataAddress', 'The metadata address must use https.')
  } else if (data.configType === SsoType.Saml2) {
    if (!data.idpEntityId?.trim())
      add('idpEntityId', 'The identity provider entity ID is required.')
    if (!httpsUrl(data.idpSingleSignOnServiceUrl))
      add('idpSingleSignOnServiceUrl', 'An https single sign-on URL is required.')
    const problems = testSaml(data).problems.filter((p) => p.includes('certificate'))
    for (const p of problems) add('idpX509PublicCert', p)
  } else {
    add('configType', 'Choose OpenID Connect or SAML 2.0.')
  }
  if (
    data.memberDecryptionType === MemberDecryptionType.KeyConnector &&
    !httpsUrl(data.keyConnectorUrl)
  ) {
    add('keyConnectorUrl', 'An https key connector URL is required.')
  }
  return errors
}

async function policyEnabled(c: Ctx, orgUuid: string, type: number) {
  const [p] = await createDb(c.env.DB)
    .select()
    .from(schema.policies)
    .where(and(eq(schema.policies.organizationUuid, orgUuid), eq(schema.policies.atype, type)))
    .limit(1)
  return p ?? null
}

const upsertPolicy = (
  c: Ctx,
  orgUuid: string,
  type: number,
  data: Record<string, unknown> | null,
  now: number,
) => {
  const db = createDb(c.env.DB)
  const json = data ? JSON.stringify(data) : null
  return db
    .insert(schema.policies)
    .values({
      uuid: crypto.randomUUID(),
      organizationUuid: orgUuid,
      atype: type,
      enabled: true,
      data: json,
      updatedAt: now,
    })
    .onConflictDoUpdate({
      target: [schema.policies.organizationUuid, schema.policies.atype],
      set: { enabled: true, ...(data ? { data: json } : {}), updatedAt: now },
    })
}

ssoAdmin.post('/api/organizations/:orgId/sso', async (c) => {
  const orgUuid = orgParam(c)
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, orgUuid, 'manageSso')
  const body = await parseBody(c, saveSchema)
  await requireOrg(db, orgUuid)
  const data: SsoConfigData = body.data ?? {}
  const identifier = body.identifier?.trim() || null

  if (identifier && !IDENTIFIER.test(identifier)) {
    throw new ApiError(400, 'The request is invalid.', {
      identifier: ['Use up to 50 letters, digits, dots, hyphens or underscores.'],
    })
  }
  if (identifier) {
    const other = await orgByIdentifier(db, identifier)
    if (other && other.uuid !== orgUuid) {
      throw new ApiError(400, 'The request is invalid.', {
        identifier: ['This identifier is already in use.'],
      })
    }
  }
  if (body.enabled) {
    if (!identifier)
      throw new ApiError(400, 'The request is invalid.', {
        identifier: ['An SSO identifier is required.'],
      })
    const problems = configProblems(data)
    if (Object.keys(problems).length > 0)
      throw new ApiError(400, 'The request is invalid.', problems)
  }

  const previous = await loadSsoConfig(db, orgUuid)
  const before = previous ? parseConfigData(previous) : null
  const wasKc =
    previous?.enabled && before?.memberDecryptionType === MemberDecryptionType.KeyConnector
  const isKc = body.enabled && data.memberDecryptionType === MemberDecryptionType.KeyConnector
  const isTde =
    body.enabled && data.memberDecryptionType === MemberDecryptionType.TrustedDeviceEncryption

  if (wasKc && !isKc) {
    const [kcUser] = await db
      .select({ uuid: schema.users.uuid })
      .from(schema.users)
      .innerJoin(
        schema.usersOrganizations,
        eq(schema.usersOrganizations.userUuid, schema.users.uuid),
      )
      .where(
        and(
          eq(schema.usersOrganizations.organizationUuid, orgUuid),
          eq(schema.users.usesKeyConnector, true),
        ),
      )
      .limit(1)
    if (kcUser) {
      throw new ApiError(
        400,
        'Key Connector cannot be turned off while members use it. They must set a master password first.',
      )
    }
  }
  if (isKc) {
    const single = await policyEnabled(c, orgUuid, PolicyType.SingleOrg)
    const requireSso = await policyEnabled(c, orgUuid, PolicyType.RequireSso)
    if (!single?.enabled || !requireSso?.enabled) {
      throw new ApiError(
        400,
        'Key Connector requires the single organization and require single sign-on policies.',
      )
    }
  }

  const now = Date.now()
  const json = JSON.stringify(ssoConfigSchema.parse(data))
  const statements: unknown[] = [
    db
      .insert(schema.ssoConfigs)
      .values({
        organizationUuid: orgUuid,
        enabled: body.enabled,
        data: json,
        createdAt: now,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: schema.ssoConfigs.organizationUuid,
        set: { enabled: body.enabled, data: json, updatedAt: now },
      }),
    db
      .update(schema.organizations)
      .set({ identifier, updatedAt: now })
      .where(eq(schema.organizations.uuid, orgUuid)),
    bumpOrgRevision(db, orgUuid, now),
  ]
  // Trusted devices need the policies that make them safe: one organisation per member, sign-in
  // through SSO, and automatic account recovery enrolment (the admin approval path).
  if (isTde) {
    const recovery = await policyEnabled(c, orgUuid, PolicyType.ResetPassword)
    statements.push(
      upsertPolicy(c, orgUuid, PolicyType.SingleOrg, null, now),
      upsertPolicy(c, orgUuid, PolicyType.RequireSso, null, now),
      upsertPolicy(
        c,
        orgUuid,
        PolicyType.ResetPassword,
        { ...(parseData(recovery?.data ?? null) ?? {}), autoEnrollEnabled: true },
        now,
      ),
    )
  }
  if (Boolean(previous?.enabled) !== body.enabled) {
    statements.push(
      eventStatement(db, c, {
        type: body.enabled
          ? SsoEventType.OrganizationEnabledSso
          : SsoEventType.OrganizationDisabledSso,
        organizationUuid: orgUuid,
      }),
    )
  }
  if (Boolean(wasKc) !== Boolean(isKc)) {
    statements.push(
      eventStatement(db, c, {
        type: isKc
          ? SsoEventType.OrganizationEnabledKeyConnector
          : SsoEventType.OrganizationDisabledKeyConnector,
        organizationUuid: orgUuid,
      }),
    )
  }
  try {
    await batch(db, statements)
  } catch {
    throw new ApiError(400, 'The request is invalid.', {
      identifier: ['This identifier is already in use.'],
    })
  }
  if (data.configType === SsoType.Saml2) {
    const row = await loadSsoConfig(db, orgUuid)
    if (row) await ensureSpKeys(db, row)
  }
  return c.json(await ssoJson(c, orgUuid))
})

/** Checks a configuration against the identity provider without saving it (admin test button). */
ssoAdmin.post('/api/organizations/:orgId/sso/test', rateLimit('sso-test'), async (c) => {
  await requirePermission(createDb(c.env.DB), c.var.user.uuid, orgParam(c), 'manageSso')
  const { data } = await parseBody(c, z.object({ data: ssoConfigSchema }))
  try {
    if (data.configType === SsoType.OpenIdConnect) {
      const r = await testOidc(data)
      return c.json({
        object: 'ssoTest',
        success: r.problems.length === 0,
        problems: r.problems,
        issuer: r.issuer,
      })
    }
    if (data.configType === SsoType.Saml2) {
      const r = testSaml(data)
      return c.json({
        object: 'ssoTest',
        success: r.problems.length === 0,
        problems: r.problems,
        issuer: data.idpEntityId ?? null,
      })
    }
    return c.json({
      object: 'ssoTest',
      success: false,
      problems: ['Choose OpenID Connect or SAML 2.0.'],
      issuer: null,
    })
  } catch (err) {
    const message =
      err instanceof SsoError ? err.message : 'The identity provider could not be reached.'
    return c.json({ object: 'ssoTest', success: false, problems: [message], issuer: null })
  }
})

// ----- Claimed domains -----

async function findDomain(c: Ctx) {
  const [row] = await createDb(c.env.DB)
    .select()
    .from(schema.organizationDomains)
    .where(
      and(
        eq(schema.organizationDomains.uuid, c.req.param('id') ?? ''),
        eq(schema.organizationDomains.organizationUuid, orgParam(c)),
      ),
    )
    .limit(1)
  if (!row) throw new ApiError(404, 'Domain not found.')
  return row
}

const listDomains = (mini: boolean) => async (c: Ctx) => {
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, orgParam(c), 'manageSso')
  const rows = await db
    .select()
    .from(schema.organizationDomains)
    .where(eq(schema.organizationDomains.organizationUuid, orgParam(c)))
  return c.json({
    object: 'list',
    data: rows.map((d) =>
      mini
        ? {
            object: 'organizationDomainMini',
            domainName: d.domainName,
            verifiedDate: domainJson(d).verifiedDate,
          }
        : domainJson(d),
    ),
    continuationToken: null,
  })
}
ssoAdmin.get('/api/organizations/:orgId/domain', listDomains(false))
ssoAdmin.get('/api/organizations/:orgId/domain/mini', listDomains(true))

ssoAdmin.get('/api/organizations/:orgId/domain/:id', async (c) => {
  await requirePermission(createDb(c.env.DB), c.var.user.uuid, orgParam(c), 'manageSso')
  return c.json(domainJson(await findDomain(c)))
})

ssoAdmin.post('/api/organizations/:orgId/domain', async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = orgParam(c)
  await requirePermission(db, c.var.user.uuid, orgUuid, 'manageSso')
  const { domainName } = await parseBody(c, z.object({ domainName: z.string().min(1).max(255) }))
  const name = normalizeDomain(domainName)
  if (!name)
    throw new ApiError(400, 'The request is invalid.', {
      domainName: ['Enter a valid domain name.'],
    })
  const [verified] = await db
    .select({ org: schema.organizationDomains.organizationUuid })
    .from(schema.organizationDomains)
    .where(
      and(
        eq(schema.organizationDomains.domainName, name),
        isNotNull(schema.organizationDomains.verifiedAt),
      ),
    )
    .limit(1)
  if (verified) throw new ApiError(409, 'The domain is already claimed by an organization.')
  const now = Date.now()
  const row = {
    uuid: crypto.randomUUID(),
    organizationUuid: orgUuid,
    domainName: name,
    txt: newDomainToken(),
    verifiedAt: null,
    lastCheckedAt: null,
    nextRunAt: now,
    jobRunCount: 0,
    createdAt: now,
  }
  try {
    await batch(db, [
      db.insert(schema.organizationDomains).values(row),
      eventStatement(db, c, {
        type: SsoEventType.OrganizationDomainAdded,
        organizationUuid: orgUuid,
      }),
    ])
  } catch {
    throw new ApiError(409, 'The domain has already been added.')
  }
  return c.json(domainJson(row))
})

ssoAdmin.post(
  '/api/organizations/:orgId/domain/:id/verify',
  rateLimit('domain-verify'),
  async (c) => {
    const db = createDb(c.env.DB)
    await requirePermission(db, c.var.user.uuid, orgParam(c), 'manageSso')
    const domain = await findDomain(c)
    if (domain.verifiedAt !== null) return c.json(domainJson(domain))
    if (await claimedElsewhere(db, domain))
      throw new ApiError(409, 'The domain is already claimed by an organization.')
    const checked = await checkDomain(db, {
      ...domain,
      jobRunCount: Math.min(domain.jobRunCount, DOMAIN_MAX_CHECKS - 1),
    })
    await batch(db, [
      eventStatement(db, c, {
        type:
          checked.verifiedAt !== null
            ? SsoEventType.OrganizationDomainVerified
            : SsoEventType.OrganizationDomainNotVerified,
        organizationUuid: domain.organizationUuid,
      }),
      ...(checked.verifiedAt !== null
        ? [bumpOrgRevision(db, domain.organizationUuid, Date.now())]
        : []),
    ])
    return c.json(domainJson(checked))
  },
)

const removeDomain = async (c: Ctx) => {
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, orgParam(c), 'manageSso')
  const domain = await findDomain(c)
  await batch(db, [
    db.delete(schema.organizationDomains).where(eq(schema.organizationDomains.uuid, domain.uuid)),
    eventStatement(db, c, {
      type: SsoEventType.OrganizationDomainRemoved,
      organizationUuid: domain.organizationUuid,
    }),
    bumpOrgRevision(db, domain.organizationUuid, Date.now()),
  ])
  return c.body(null, 200)
}
ssoAdmin.delete('/api/organizations/:orgId/domain/:id', removeDomain)
ssoAdmin.post('/api/organizations/:orgId/domain/:id/remove', removeDomain)

// ----- Members: automatic recovery enrolment status -----

/** `GET organizations/{ssoIdentifier}/auto-enroll-status`: the path carries the SSO identifier. */
ssoAdmin.get('/api/organizations/:identifier/auto-enroll-status', async (c) => {
  const db = createDb(c.env.DB)
  const org =
    (await orgByIdentifier(db, c.req.param('identifier'))) ??
    (await requireOrg(db, c.req.param('identifier')).catch(() => undefined))
  const member = org ? await getMember(db, c.var.user.uuid, org.uuid) : undefined
  if (!org || !member || member.status === Status.Revoked)
    throw new ApiError(404, 'Organization not found.')
  const [p] = await db
    .select()
    .from(schema.policies)
    .where(
      and(
        eq(schema.policies.organizationUuid, org.uuid),
        eq(schema.policies.atype, PolicyType.ResetPassword),
      ),
    )
    .limit(1)
  return c.json({
    object: 'organizationAutoEnrollStatus',
    id: org.uuid,
    resetPasswordEnabled: p?.enabled === true && parseData(p.data)?.autoEnrollEnabled === true,
  })
})

// ----- Claimed accounts: an administrator deletes a member's account -----

async function deleteClaimedAccount(
  c: Ctx,
  orgUuid: string,
  memberId: string,
): Promise<string | null> {
  const db = createDb(c.env.DB)
  const actor = await requirePermission(db, c.var.user.uuid, orgUuid, 'manageUsers')
  const [target] = await db
    .select({ m: schema.usersOrganizations, u: schema.users })
    .from(schema.usersOrganizations)
    .innerJoin(schema.users, eq(schema.users.uuid, schema.usersOrganizations.userUuid))
    .where(
      and(
        eq(schema.usersOrganizations.uuid, memberId),
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
      ),
    )
    .limit(1)
  if (!target) return 'Member not found.'
  if (target.u.uuid === c.var.user.uuid) return 'You cannot delete your own account here.'
  if (target.m.atype === 0 && actor.atype !== 0) return 'Only owners can delete owners.'
  if (isAdminRole(target.m) && !isAdminRole(actor))
    return 'Custom members cannot delete administrators.'
  if (target.m.status < Status.Accepted || !(await orgClaimsEmail(db, orgUuid, target.u.email))) {
    return 'Only accounts claimed by the organization can be deleted.'
  }
  try {
    await assertNotSoleOwner(db, target.u.uuid)
  } catch (e) {
    return (e as ApiError).message
  }
  const keys = [
    ...(await userAttachmentKeys(db, target.u.uuid)),
    ...(await userSendKeys(db, target.u.uuid)),
  ]
  await runBatch(db, [db.delete(schema.users).where(eq(schema.users.uuid, target.u.uuid))])
  deleteBlobs(c, keys)
  await batch(db, [
    eventStatement(db, c, {
      type: EventType.OrganizationUserRemoved,
      organizationUuid: orgUuid,
      organizationUserUuid: memberId,
    }),
  ])
  return null
}

ssoAdmin.delete('/api/organizations/:orgId/users/delete-account', async (c) => {
  const { ids } = await parseBody(c, z.object({ ids: z.array(z.string()).max(500) }))
  const data = []
  for (const id of ids) {
    const error = await deleteClaimedAccount(c, orgParam(c), id)
    data.push({ object: 'organizationUserBulkResponse', id, error: error ?? '' })
  }
  return c.json({ object: 'list', data, continuationToken: null })
})

const deleteOne = async (c: Ctx) => {
  const error = await deleteClaimedAccount(c, orgParam(c), c.req.param('id') ?? '')
  if (error) throw new ApiError(400, error)
  return c.body(null, 200)
}
ssoAdmin.delete('/api/organizations/:orgId/users/:id/delete-account', deleteOne)
ssoAdmin.post('/api/organizations/:orgId/users/:id/delete-account', deleteOne)

// ----- Account endpoints -----

export const ssoAccounts = new Hono<Env>()

/** A short-lived token that lets a signed-in user link their account to an organisation's SSO. */
ssoAccounts.get('/api/accounts/sso/user-identifier', requireAuth, async (c) => {
  const token = await signPurposeToken(
    c.env,
    LINK_PURPOSE,
    { sub: c.var.user.uuid, email: c.var.user.email },
    LINK_TTL_SECONDS,
  )
  return c.text(token)
})

const unlink = async (c: Ctx) => {
  const db = createDb(c.env.DB)
  const user = c.var.user
  const orgUuid = c.req.param('orgId') ?? ''
  if (!hasMasterPassword(user)) {
    throw new ApiError(400, 'Set a master password before unlinking single sign-on.')
  }
  const result = await db
    .delete(schema.ssoUsers)
    .where(
      and(eq(schema.ssoUsers.userUuid, user.uuid), eq(schema.ssoUsers.organizationUuid, orgUuid)),
    )
  if (result.meta.changes === 0) throw new ApiError(404, 'No SSO link for this organization.')
  const member = await getMember(db, user.uuid, orgUuid)
  await batch(db, [
    eventStatement(db, c, {
      type: SsoEventType.OrganizationUserUnlinkedSso,
      organizationUuid: orgUuid,
      organizationUserUuid: member?.uuid ?? null,
      userUuid: user.uuid,
    }),
    db.update(schema.users).set({ updatedAt: Date.now() }).where(eq(schema.users.uuid, user.uuid)),
  ])
  return c.body(null, 200)
}
ssoAccounts.delete('/api/accounts/sso/:orgId', requireAuth, unlink)
ssoAccounts.post('/api/accounts/sso/:orgId/delete', requireAuth, unlink)

const kdfFields = {
  kdf: z.number().int(),
  kdfIterations: z.number().int(),
  kdfMemory: z.number().int().nullish(),
  kdfParallelism: z.number().int().nullish(),
}
const keysField = z
  .object({ publicKey: z.string().min(1), encryptedPrivateKey: z.string().min(1) })
  .nullish()

/** The organisation named by an SSO identifier in a request body, if the user is a member. */
async function memberOrgByIdentifier(c: Ctx, identifier: string | null | undefined) {
  if (!identifier) return null
  const db = createDb(c.env.DB)
  const org = await orgByIdentifier(db, identifier)
  if (!org) throw new ApiError(400, 'Organization not found.')
  const member = await getMember(db, c.var.user.uuid, org.uuid)
  if (!member || member.status === Status.Revoked)
    throw new ApiError(400, 'You are not a member of this organization.')
  return { org, member }
}

function kdfColumns(k: {
  kdf: number
  kdfIterations: number
  kdfMemory?: number | null
  kdfParallelism?: number | null
}) {
  const problem = kdfProblem(k)
  if (problem) throw new ApiError(400, problem)
  const argon = k.kdf === 1
  return {
    kdfType: k.kdf,
    kdfIterations: k.kdfIterations,
    kdfMemory: argon ? (k.kdfMemory ?? null) : null,
    kdfParallelism: argon ? (k.kdfParallelism ?? null) : null,
  }
}

/** Keys may be set once; an account that has them keeps them. */
const keyColumns = (
  user: User,
  keys: { publicKey: string; encryptedPrivateKey: string } | null | undefined,
) =>
  keys && !user.publicKey && !user.privateKey
    ? { publicKey: keys.publicKey, privateKey: keys.encryptedPrivateKey }
    : {}

/**
 * `POST accounts/set-password`: the first master password of an account created by SSO (or of a
 * trusted device member who chooses one). Refused when the account already has a password.
 */
ssoAccounts.post('/api/accounts/set-password', requireAuth, async (c) => {
  const body = await parseBody(
    c,
    z.object({
      masterPasswordHash: z.string().min(1),
      key: z.string().min(1),
      masterPasswordHint: z.string().max(50).nullish(),
      orgIdentifier: z.string().nullish(),
      keys: keysField,
      ...kdfFields,
    }),
  )
  const user = c.var.user
  if (hasMasterPassword(user))
    throw new ApiError(400, 'This account already has a master password.')
  if (user.usesKeyConnector) throw new ApiError(400, 'This account unlocks with Key Connector.')
  await memberOrgByIdentifier(c, body.orgIdentifier)
  const stored = await hashMasterPassword(body.masterPasswordHash)
  await createDb(c.env.DB)
    .update(schema.users)
    .set({
      ...stored,
      akey: body.key,
      passwordHint: body.masterPasswordHint ?? null,
      ...kdfColumns(body),
      ...keyColumns(user, body.keys),
      updatedAt: Date.now(),
    })
    .where(and(eq(schema.users.uuid, user.uuid), eq(schema.users.passwordHash, '')))
  return c.body(null, 200)
})

/** `PUT accounts/update-tde-offboarding-password`: a trusted device member whose organisation left TDE. */
ssoAccounts.put('/api/accounts/update-tde-offboarding-password', requireAuth, async (c) => {
  const body = await parseBody(
    c,
    z.object({ authenticationData, unlockData, masterPasswordHint: z.string().max(50).nullish() }),
  )
  const user = c.var.user
  if (hasMasterPassword(user))
    throw new ApiError(400, 'This account already has a master password.')
  if (user.usesKeyConnector) throw new ApiError(400, 'This account unlocks with Key Connector.')
  const kdf = checkNested(body.authenticationData, body.unlockData, user.email)
  const stored = await hashMasterPassword(body.authenticationData.masterPasswordAuthenticationHash)
  await createDb(c.env.DB)
    .update(schema.users)
    .set({
      ...stored,
      akey: body.unlockData.masterKeyWrappedUserKey,
      passwordHint: body.masterPasswordHint ?? null,
      ...kdfColumns(kdf),
      updatedAt: Date.now(),
    })
    .where(and(eq(schema.users.uuid, user.uuid), eq(schema.users.passwordHash, '')))
  return c.body(null, 200)
})

async function keyConnectorOrg(c: Ctx, identifier: string | null | undefined) {
  const found = await memberOrgByIdentifier(c, identifier)
  if (!found) throw new ApiError(400, 'An organization identifier is required.')
  const row = await loadSsoConfig(createDb(c.env.DB), found.org.uuid)
  const data = row?.enabled ? parseConfigData(row) : null
  if (data?.memberDecryptionType !== MemberDecryptionType.KeyConnector) {
    throw new ApiError(400, 'This organization does not use Key Connector.')
  }
  return found
}

/**
 * `POST accounts/set-key-connector-key`: a new SSO member of a key connector organisation stores
 * the master-key-wrapped user key and account keys after enrolling with the key connector.
 */
ssoAccounts.post('/api/accounts/set-key-connector-key', requireAuth, async (c) => {
  const body = await parseBody(
    c,
    z.object({
      key: z.string().min(1),
      keys: keysField,
      orgIdentifier: z.string().min(1),
      ...kdfFields,
    }),
  )
  const user = c.var.user
  if (hasMasterPassword(user) || user.usesKeyConnector || user.akey) {
    throw new ApiError(400, 'This account already has its keys.')
  }
  await keyConnectorOrg(c, body.orgIdentifier)
  await createDb(c.env.DB)
    .update(schema.users)
    .set({
      akey: body.key,
      usesKeyConnector: true,
      ...kdfColumns(body),
      ...keyColumns(user, body.keys),
      updatedAt: Date.now(),
    })
    .where(and(eq(schema.users.uuid, user.uuid), eq(schema.users.usesKeyConnector, false)))
  return c.body(null, 200)
})

/**
 * `POST accounts/convert-to-key-connector`: a member with a master password moves to the key
 * connector (the client has already stored the master key there). The password is removed.
 * Owners and administrators keep their master password.
 */
ssoAccounts.post('/api/accounts/convert-to-key-connector', requireAuth, async (c) => {
  const db = createDb(c.env.DB)
  const user = c.var.user
  if (user.usesKeyConnector) throw new ApiError(400, 'This account already uses Key Connector.')
  if (!hasMasterPassword(user)) throw new ApiError(400, 'This account has no master password.')
  const rows = await db
    .select({ m: schema.usersOrganizations, cfg: schema.ssoConfigs })
    .from(schema.usersOrganizations)
    .innerJoin(
      schema.ssoConfigs,
      eq(schema.ssoConfigs.organizationUuid, schema.usersOrganizations.organizationUuid),
    )
    .where(
      and(
        eq(schema.usersOrganizations.userUuid, user.uuid),
        eq(schema.ssoConfigs.enabled, true),
        ne(schema.usersOrganizations.status, Status.Revoked),
      ),
    )
  const kc = rows.find(
    (r) => parseConfigData(r.cfg).memberDecryptionType === MemberDecryptionType.KeyConnector,
  )
  if (!kc) throw new ApiError(400, 'None of your organizations use Key Connector.')
  if (isAdminRole(kc.m))
    throw new ApiError(400, 'Owners and administrators keep their master password.')
  await batch(db, [
    db
      .update(schema.users)
      .set({
        passwordHash: '',
        salt: '',
        passwordIterations: 0,
        passwordHint: null,
        usesKeyConnector: true,
        updatedAt: Date.now(),
      })
      .where(eq(schema.users.uuid, user.uuid)),
    eventStatement(db, c, {
      type: SsoEventType.UserMigratedKeyToKeyConnector,
      userUuid: user.uuid,
    }),
  ])
  return c.body(null, 200)
})

ssoAccounts.get(
  '/api/accounts/key-connector/confirmation-details/:identifier',
  requireAuth,
  async (c) => {
    const { org } = await keyConnectorOrg(c, c.req.param('identifier'))
    return c.json({ object: 'keyConnectorConfirmationDetails', organizationName: org.name })
  },
)
