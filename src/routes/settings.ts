import { eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { requireAuth } from '../auth/middleware'
import { createDb, runBatch, schema } from '../db'
import type { Env } from '../env'
import { PushType } from '../notifications/publish'
import { notifyUser } from '../notifications/vault-events'
import { parseBody } from '../validation'
import { bumpRevision } from '../vault/ciphers'
import { domainsJson } from '../vault/domains'

export const settings = new Hono<Env>()

settings.get('/api/settings/domains', requireAuth, (c) => c.json(domainsJson(c.var.user)))

const domainsSchema = z.object({
  equivalentDomains: z.array(z.array(z.string())).nullish(),
  excludedGlobalEquivalentDomains: z.array(z.number().int()).nullish(),
})
const update = async (c: Context<Env>) => {
  const body = await parseBody(c, domainsSchema)
  const db = createDb(c.env.DB)
  // Omitted fields keep their stored value.
  const user = c.var.user
  const equivalent = body.equivalentDomains
    ? JSON.stringify(body.equivalentDomains)
    : user.equivalentDomains
  const excluded = body.excludedGlobalEquivalentDomains
    ? JSON.stringify(body.excludedGlobalEquivalentDomains)
    : user.excludedGlobals
  const now = Date.now()
  await runBatch(db, [
    db
      .update(schema.users)
      .set({ equivalentDomains: equivalent, excludedGlobals: excluded })
      .where(eq(schema.users.uuid, user.uuid)),
    bumpRevision(db, user.uuid, now),
  ])
  notifyUser(c, PushType.SyncSettings, now)
  return c.json({
    equivalentDomains: JSON.parse(equivalent),
    globalEquivalentDomains: domainsJson({
      equivalentDomains: equivalent,
      excludedGlobals: excluded,
    }).globalEquivalentDomains,
    object: 'domains',
  })
}
settings.put('/api/settings/domains', requireAuth, update)
settings.post('/api/settings/domains', requireAuth, update)
