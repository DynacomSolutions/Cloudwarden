// `POST /api/organizations/{orgId}/import` (TASKS #331): the member and group import the clients
// send with a user token (the Public API twin lives in `public-api.ts`). Same engine as the
// Directory Connector import. Members need `manageUsers`, and `manageGroups` when groups come
// along; owners and admins hold both. Bounded: body size, entries, memberships and invitations.
import { Hono } from 'hono'
import { createDb } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { requirePermission } from '../orgs/access'
import { clientImportSchema, importDirectory } from '../orgs/directory-import'
import { authOnce } from '../orgs/util'
import { rateLimit } from '../ratelimit'
import { assertBodyWithin, parseBody } from '../validation'

export const orgImport = new Hono<Env>()

/** Largest request body (about 10,000 members and groups with long ids fit well below this). */
export const MAX_IMPORT_BYTES = 5 * 1024 * 1024
const tooLarge = () => new ApiError(413, 'The import is too large.')

orgImport.post(
  '/api/organizations/:orgId/import',
  rateLimit('org-import', 10),
  authOnce,
  async (c) => {
    const orgUuid = c.req.param('orgId')
    const db = createDb(c.env.DB)
    // Permission first: a caller without it never makes the worker read the body.
    const actor = await requirePermission(db, c.var.user.uuid, orgUuid, 'manageUsers')
    await assertBodyWithin(c, MAX_IMPORT_BYTES, tooLarge)
    const body = await parseBody(c, clientImportSchema)
    if ((body.groups?.length ?? 0) > 0 || body.overwriteExisting) {
      await requirePermission(db, c.var.user.uuid, orgUuid, 'manageGroups')
    }
    await importDirectory(c, orgUuid, body, null, actor)
    return c.body(null, 200)
  },
)
