// Organisation connections (TASKS #344). Upstream uses them to link a self-hosted server to the
// Bitwarden cloud (billing sync, SCIM key exchange). Cloudwarden never talks to a cloud billing
// service, so it answers like a self-hosted upstream server with cloud communication switched off:
// the feature probe says false, and creating, changing or reading a connection is refused with the
// upstream wording. There is never a connection to read, update or delete.
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { createDb } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { can, getMember } from '../orgs/access'
import { Role, Status } from '../orgs/constants'
import { authOnce } from '../orgs/util'
import { parseBody } from '../validation'

export const orgConnections = new Hono<Env>()

const BASE = '/api/organizations/connections'
const SCIM = 2

orgConnections.use(BASE, authOnce)
orgConnections.use(`${BASE}/`, authOnce)
orgConnections.use(`${BASE}/*`, authOnce)

/** Upstream `EnableCloudCommunication`: always off here. */
orgConnections.get(`${BASE}/enabled`, (c) => c.json(false))

const createSchema = z.object({
  type: z.number().int(),
  organizationId: z.string().min(1),
  enabled: z.boolean().optional(),
  config: z.unknown().optional(),
})

// The web client posts to `connections/` with the trailing slash, other clients without it.
const create = async (c: Context<Env>) => {
  const body = await parseBody(c, createSchema)
  const member = await getMember(createDb(c.env.DB), c.var.user.uuid, body.organizationId)
  const allowed =
    member?.status === Status.Confirmed &&
    (body.type === SCIM ? can(member, 'manageScim') : member.atype === Role.Owner)
  if (!allowed)
    throw new ApiError(400, 'Only the owner of an organization can create a connection.')
  throw new ApiError(400, 'Cloud communication is disabled.')
}
orgConnections.post(BASE, create)
orgConnections.post(`${BASE}/`, create)

orgConnections.put(`${BASE}/:id`, async () => {
  throw new ApiError(404, 'Resource not found.')
})

orgConnections.delete(`${BASE}/:id`, async () => {
  throw new ApiError(404, 'Resource not found.')
})

/** Upstream answers an empty body (204) when the organisation has no connection of that type. */
orgConnections.get(`${BASE}/:organizationId/:type`, async (c) => {
  const member = await getMember(createDb(c.env.DB), c.var.user.uuid, c.req.param('organizationId'))
  if (member?.status !== Status.Confirmed) {
    throw new ApiError(400, 'Only the owner of an organization can view a connection.')
  }
  return c.body(null, 204)
})
