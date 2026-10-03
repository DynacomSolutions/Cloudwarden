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
import { parseBody } from '../validation'

export const orgImport = new Hono<Env>()

/** Largest request body (about 10,000 members and groups with long ids fit well below this). */
export const MAX_IMPORT_BYTES = 5 * 1024 * 1024

orgImport.post(
  '/api/organizations/:orgId/import',
  rateLimit('org-import', 10),
  authOnce,
  async (c) => {
    const declared = Number(c.req.header('Content-Length') ?? 0)
    if (declared > MAX_IMPORT_BYTES) throw new ApiError(413, 'The import is too large.')
    // Chunked bodies carry no length: measure a copy before parsing.
    if ((await c.req.raw.clone().arrayBuffer()).byteLength > MAX_IMPORT_BYTES) {
      throw new ApiError(413, 'The import is too large.')
    }
    const orgUuid = c.req.param('orgId')
    const body = await parseBody(c, clientImportSchema)
    const db = createDb(c.env.DB)
    const actor = await requirePermission(db, c.var.user.uuid, orgUuid, 'manageUsers')
    if ((body.groups?.length ?? 0) > 0 || body.overwriteExisting) {
      await requirePermission(db, c.var.user.uuid, orgUuid, 'manageGroups')
    }
    await importDirectory(c, orgUuid, body, null, actor)
    return c.body(null, 200)
  },
)
