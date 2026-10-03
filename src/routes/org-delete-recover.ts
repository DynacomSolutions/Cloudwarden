// Organisation deletion confirmed through email (TASKS #330). An owner asks for a link; the signed,
// expiring token goes only to the billing address. The web client's confirmation page posts the
// token without a session, so it is bound to the organisation and to the billing address it was
// issued for. Deleting the organisation spends it: a second use finds nothing to delete.
import { Hono } from 'hono'
import { z } from 'zod'
import { signPurposeToken, verifyPurposeToken } from '../auth/purpose-token'
import { createDb } from '../db'
import { createEmailTransport, deleteOrganizationEmail } from '../email'
import { sendNotice, vaultBase } from '../email/send'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { requireOrg, requireOwner } from '../orgs/access'
import { authOnce } from '../orgs/util'
import { overLimit, rateLimit, tooManyRequests } from '../ratelimit'
import { parseBody } from '../validation'
import { eraseOrganization } from './organizations'

export const orgDeleteRecover = new Hono<Env>()

const PURPOSE = 'delete-organization'
export const ORG_DELETE_TTL_SECONDS = 24 * 3600

orgDeleteRecover.post(
  '/api/organizations/:orgId/delete-recover',
  rateLimit('org-delete-recover', 5),
  authOnce,
  async (c) => {
    const orgUuid = c.req.param('orgId')
    const db = createDb(c.env.DB)
    await requireOwner(db, c.var.user.uuid, orgUuid)
    if (!createEmailTransport(c.env).configured) {
      throw new ApiError(400, 'This server cannot send email, so this feature is not available.')
    }
    if (await overLimit(c, 'org-delete-recover-org', orgUuid)) return tooManyRequests(c)
    const org = await requireOrg(db, orgUuid)
    const token = await signPurposeToken(
      c.env,
      PURPOSE,
      { sub: org.uuid, email: org.billingEmail },
      ORG_DELETE_TTL_SECONDS,
    )
    const url = `${vaultBase(c.env)}/#/verify-recover-delete-org?orgId=${encodeURIComponent(org.uuid)}&token=${encodeURIComponent(token)}&name=${encodeURIComponent(org.name)}`
    if (!(await sendNotice(c.env, org.billingEmail, deleteOrganizationEmail(org.name, url)))) {
      throw new ApiError(500, 'The email could not be sent.')
    }
    return c.body(null, 200)
  },
)

orgDeleteRecover.post(
  '/api/organizations/:orgId/delete-recover-token',
  rateLimit('org-delete-recover-token', 10),
  async (c) => {
    const orgUuid = c.req.param('orgId')
    const { token } = await parseBody(c, z.object({ token: z.string().min(1).max(4096) }))
    const claims = await verifyPurposeToken(c.env, PURPOSE, token)
    const db = createDb(c.env.DB)
    const org = claims?.sub === orgUuid ? await requireOrg(db, orgUuid).catch(() => null) : null
    // Same answer for every failure: a bad token, another organisation, a changed billing address.
    if (!claims || !org || claims.email !== org.billingEmail) {
      throw new ApiError(400, 'Invalid token.')
    }
    await eraseOrganization(db, org.uuid)
    return c.body(null, 200)
  },
)
