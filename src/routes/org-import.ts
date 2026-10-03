// `POST /api/organizations/{orgId}/import` (TASKS #331): the member and group import the clients
// send with a user token (the Public API twin lives in `public-api.ts`). Same engine as the
// Directory Connector import. Members need `manageUsers`, and `manageGroups` when groups come
// along; owners and admins hold both.
import { Hono } from 'hono'
import { createDb } from '../db'
import type { Env } from '../env'
import { requirePermission } from '../orgs/access'
import { clientImportSchema, importDirectory } from '../orgs/directory-import'
import { authOnce } from '../orgs/util'
import { parseBody } from '../validation'

export const orgImport = new Hono<Env>()

orgImport.post('/api/organizations/:orgId/import', authOnce, async (c) => {
  const orgUuid = c.req.param('orgId')
  const body = await parseBody(c, clientImportSchema)
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, orgUuid, 'manageUsers')
  if ((body.groups?.length ?? 0) > 0 || body.overwriteExisting) {
    await requirePermission(db, c.var.user.uuid, orgUuid, 'manageGroups')
  }
  await importDirectory(c, orgUuid, body, null)
  return c.body(null, 200)
})
