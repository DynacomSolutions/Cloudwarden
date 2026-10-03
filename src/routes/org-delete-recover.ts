// Organisation deletion confirmed through email (TASKS #330). An owner proves who they are (master
// password, or a code for accounts without one) and asks for a link; the signed, expiring token
// goes only to the billing address. The web client's confirmation page posts the token without a
// session, so the token is bound to the organisation, the billing address, the requesting owner
// (who must still be an owner) and a nonce that the newest request replaces. Deleting the
// organisation spends it: a second use finds nothing to delete.
import { and, eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { rateLimit as windowLimit } from '../admin/security'
import { consumeOtp } from '../auth/otp'
import { verifyMasterPassword } from '../auth/passwords'
import { signPurposeToken, verifyPurposeToken } from '../auth/purpose-token'
import { createDb, schema } from '../db'
import { createEmailTransport, deleteOrganizationEmail } from '../email'
import { sendNotice, vaultBase } from '../email/send'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { isStandInUser } from '../federation/standin'
import { requireOrg, requireOwner } from '../orgs/access'
import { Role, Status } from '../orgs/constants'
import { authOnce } from '../orgs/util'
import { overLimit, rateLimit, tooManyRequests } from '../ratelimit'
import { parseBody } from '../validation'
import { eraseOrganization } from './organizations'

export const orgDeleteRecover = new Hono<Env>()

const PURPOSE = 'delete-organization'
export const ORG_DELETE_TTL_SECONDS = 24 * 3600
/** Deletion emails per organisation per hour. */
export const ORG_DELETE_MAILS_PER_HOUR = 3

const requestSchema = z.object({
  masterPasswordHash: z.string().min(1).nullish(),
  otp: z.string().min(1).max(32).nullish(),
})

orgDeleteRecover.post(
  '/api/organizations/:orgId/delete-recover',
  rateLimit('org-delete-recover', 5),
  authOnce,
  async (c) => {
    const orgUuid = c.req.param('orgId')
    const user = c.var.user
    const body = await parseBody(c, requestSchema)
    const db = createDb(c.env.DB)
    // A stand-in account of a paired instance never deletes an organisation hosted here.
    if (isStandInUser(user)) throw new ApiError(403, 'You do not have permission to do this.')
    await requireOwner(db, user.uuid, orgUuid)
    if (!createEmailTransport(c.env).configured) {
      throw new ApiError(400, 'This server cannot send email, so this feature is not available.')
    }
    if (await overLimit(c, 'org-delete-recover-org', orgUuid)) return tooManyRequests(c)
    const proven = body.masterPasswordHash
      ? await verifyMasterPassword(user, body.masterPasswordHash)
      : body.otp
        ? !(await overLimit(c, 'verify-otp', user.uuid)) &&
          (await consumeOtp(db, user.uuid, 'user-verification', body.otp))
        : false
    if (!proven) throw new ApiError(400, 'Invalid verification.')
    // Spent after verification so a wrong password does not use up the organisation's allowance.
    if (
      !(await windowLimit(
        c.env.DB,
        `org-delete-mail:${orgUuid}`,
        ORG_DELETE_MAILS_PER_HOUR,
        3600_000,
        Date.now(),
      ))
    ) {
      return tooManyRequests(c)
    }
    const org = await requireOrg(db, orgUuid)
    const nonce = crypto.randomUUID()
    await db
      .update(schema.organizations)
      .set({ deleteNonce: nonce })
      .where(eq(schema.organizations.uuid, org.uuid))
    const token = await signPurposeToken(
      c.env,
      PURPOSE,
      { sub: org.uuid, email: org.billingEmail, ref: `${nonce}.${user.uuid}` },
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
    const [nonce, owner] = (claims?.ref ?? '').split('.')
    let ok = Boolean(claims && org && nonce && owner)
    // Same answer for every failure: a bad token, another organisation, a changed billing
    // address, a newer link, or a requester who is no longer an owner.
    if (claims && org && ok) {
      const [m] = await db
        .select({
          atype: schema.usersOrganizations.atype,
          status: schema.usersOrganizations.status,
        })
        .from(schema.usersOrganizations)
        .where(
          and(
            eq(schema.usersOrganizations.organizationUuid, org.uuid),
            eq(schema.usersOrganizations.userUuid, owner as string),
          ),
        )
        .limit(1)
      ok =
        claims.email === org.billingEmail &&
        org.deleteNonce === nonce &&
        m?.atype === Role.Owner &&
        m.status === Status.Confirmed
    }
    if (!ok || !org) throw new ApiError(400, 'Invalid token.')
    await eraseOrganization(c, db, org.uuid)
    return c.body(null, 200)
  },
)
