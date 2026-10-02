// Organisation API key management for the web client (TASKS #270): `POST api-key` shows (and
// creates) the key, `POST rotate-api-key` replaces it, `GET api-key-information[/{type}]` lists
// when each key was last changed. The Public API key (type 0) is owner only; the SCIM key
// (type 2) needs the `manageScim` permission.
import { eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { verifyMasterPassword } from '../auth/passwords'
import { createDb, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { requireOwner, requirePermission } from '../orgs/access'
import { ApiKeyType, issueApiKey } from '../orgs/api-keys'
import { authOnce } from '../orgs/util'
import { parseBody } from '../validation'

export const orgApiKeys = new Hono<Env>()
orgApiKeys.use('/api/organizations/*', authOnce)

type Ctx = Context<Env>

const requestSchema = z.object({
  masterPasswordHash: z.string().nullish(),
  otp: z.string().nullish(),
  type: z.number().int().nullish(),
})

async function authorise(c: Ctx, orgUuid: string, type: number) {
  const db = createDb(c.env.DB)
  if (type === ApiKeyType.Default) return requireOwner(db, c.var.user.uuid, orgUuid)
  if (type === ApiKeyType.Scim) return requirePermission(db, c.var.user.uuid, orgUuid, 'manageScim')
  throw new ApiError(400, 'Billing sync keys are not used by this server.')
}

const handler = (rotate: boolean) => async (c: Ctx) => {
  const orgUuid = c.req.param('id') ?? ''
  const body = await parseBody(c, requestSchema)
  const type = body.type ?? ApiKeyType.Default
  await authorise(c, orgUuid, type)
  if (
    !body.masterPasswordHash ||
    !(await verifyMasterPassword(c.var.user, body.masterPasswordHash))
  ) {
    throw new ApiError(400, 'Invalid password.', { masterPasswordHash: ['Invalid password.'] })
  }
  const { apiKey, revisionDate } = await issueApiKey(
    c.env,
    createDb(c.env.DB),
    orgUuid,
    type,
    rotate,
  )
  return c.json({ object: 'apiKey', apiKey, revisionDate: new Date(revisionDate).toISOString() })
}
orgApiKeys.post('/api/organizations/:id/api-key', handler(false))
orgApiKeys.post('/api/organizations/:id/rotate-api-key', handler(true))

const information = async (c: Ctx) => {
  const orgUuid = c.req.param('id') ?? ''
  const typeParam = c.req.param('type')
  const type = typeParam === undefined ? null : Number(typeParam)
  if (type !== null && !Number.isInteger(type)) throw new ApiError(400, 'Invalid key type.')
  const db = createDb(c.env.DB)
  // Listing every type needs the owner; one type needs that type's permission.
  if (type === null) await requireOwner(db, c.var.user.uuid, orgUuid)
  else await authorise(c, orgUuid, type)
  const rows = await db
    .select()
    .from(schema.organizationApiKeys)
    .where(eq(schema.organizationApiKeys.organizationUuid, orgUuid))
  return c.json({
    object: 'list',
    data: rows
      .filter((r) => type === null || r.atype === type)
      .map((r) => ({
        object: 'organizationApiKeyInformation',
        keyType: r.atype,
        revisionDate: new Date(r.revisionDate).toISOString(),
      })),
    continuationToken: null,
  })
}
orgApiKeys.get('/api/organizations/:id/api-key-information', information)
orgApiKeys.get('/api/organizations/:id/api-key-information/:type', information)
