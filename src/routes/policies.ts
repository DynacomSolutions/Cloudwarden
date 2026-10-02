import { and, eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { verifyPurposeToken } from '../auth/purpose-token'
import { createDb, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { bumpOrgRevision, requireMember, requirePermission } from '../orgs/access'
import { EventType, PolicyType } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import {
  emptyPolicyJson,
  type PolicyRow,
  policyJson,
  revokeNonCompliantMembers,
} from '../orgs/policies'
import { savePolicy } from '../orgs/policy-save'
import { authOnce } from '../orgs/util'
import { parseBody } from '../validation'
import { INVITE_PURPOSE } from './org-users'

/** Unauthenticated: an invited person reads the policies before accepting. Mount before the rest. */
export const publicPolicies = new Hono<Env>()

publicPolicies.get('/api/organizations/:orgId/policies/token', async (c) => {
  const orgUuid = c.req.param('orgId')
  const { email, token, organizationUserId } = c.req.query()
  const claims = await verifyPurposeToken(c.env, INVITE_PURPOSE, token ?? '')
  if (
    !claims ||
    claims.ref !== orgUuid ||
    claims.sub !== organizationUserId ||
    claims.email !== (email ?? '').trim().toLowerCase()
  ) {
    throw new ApiError(400, 'Invalid token.')
  }
  const rows = await createDb(c.env.DB)
    .select()
    .from(schema.policies)
    .where(and(eq(schema.policies.organizationUuid, orgUuid), eq(schema.policies.enabled, true)))
  return c.json({ object: 'list', data: rows.map(policyJson), continuationToken: null })
})

export const policies = new Hono<Env>()
policies.use('/api/organizations/*', authOnce)

type Ctx = Context<Env>
const org = (c: Ctx) => c.req.param('orgId') ?? ''
const typeParam = (c: Ctx) => {
  const t = Number(c.req.param('type'))
  if (!Number.isInteger(t) || t < 0) throw new ApiError(400, 'Invalid policy type.')
  return t
}

async function findPolicy(c: Ctx, type: number): Promise<PolicyRow | undefined> {
  const [row] = await createDb(c.env.DB)
    .select()
    .from(schema.policies)
    .where(and(eq(schema.policies.organizationUuid, org(c)), eq(schema.policies.atype, type)))
    .limit(1)
  return row
}

policies.get('/api/organizations/:orgId/policies', async (c) => {
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, org(c), 'managePolicies')
  const rows = await db
    .select()
    .from(schema.policies)
    .where(eq(schema.policies.organizationUuid, org(c)))
  return c.json({ object: 'list', data: rows.map(policyJson), continuationToken: null })
})

policies.get('/api/organizations/:orgId/policies/master-password', async (c) => {
  await requireMember(createDb(c.env.DB), c.var.user.uuid, org(c))
  const row = await findPolicy(c, PolicyType.MasterPassword)
  return c.json(row ? policyJson(row) : emptyPolicyJson(org(c), PolicyType.MasterPassword))
})

policies.get('/api/organizations/:orgId/policies/:type', async (c) => {
  await requirePermission(createDb(c.env.DB), c.var.user.uuid, org(c), 'managePolicies')
  const type = typeParam(c)
  const row = await findPolicy(c, type)
  return c.json(row ? policyJson(row) : emptyPolicyJson(org(c), type))
})

const policyBody = z.object({
  enabled: z.boolean(),
  data: z.record(z.string(), z.unknown()).nullish(),
})
// The admin console wraps the policy as `{ policy, metadata }`; older callers send it bare.
const saveSchema = z.union([
  z.object({ policy: policyBody, metadata: z.unknown().optional() }).transform((v) => v.policy),
  policyBody,
])

const saveHandler = async (c: Ctx) => {
  const type = typeParam(c)
  const body = await parseBody(c, saveSchema)
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, org(c), 'managePolicies')
  return c.json(policyJson(await savePolicy(c, db, org(c), type, body)))
}
policies.put('/api/organizations/:orgId/policies/:type', saveHandler)
policies.put('/api/organizations/:orgId/policies/:type/vnext', saveHandler)
