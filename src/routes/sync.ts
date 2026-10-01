import { eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { requireAuth } from '../auth/middleware'
import { createDb, schema } from '../db'
import type { Env } from '../env'
import { cipherJson, listCipherRows } from '../vault/ciphers'
import { domainsJson } from '../vault/domains'
import { folderJson } from '../vault/folders'
import { profileJson } from './accounts'

export const sync = new Hono<Env>()

sync.get('/api/sync', requireAuth, async (c) => {
  const db = createDb(c.env.DB)
  const user = c.var.user
  const [profile, folderRows, cipherRows] = await Promise.all([
    profileJson(c, user),
    db.select().from(schema.folders).where(eq(schema.folders.userUuid, user.uuid)),
    listCipherRows(db, user.uuid),
  ])
  const excludeDomains = c.req.query('excludeDomains') === 'true'
  return c.json({
    profile,
    folders: folderRows.map(folderJson),
    collections: [],
    ciphers: cipherRows.map(cipherJson),
    policies: [],
    sends: [],
    domains: excludeDomains ? null : domainsJson(user),
    userDecryption: {
      masterPasswordUnlock: {
        kdf: {
          kdfType: user.kdfType,
          iterations: user.kdfIterations,
          memory: user.kdfMemory,
          parallelism: user.kdfParallelism,
        },
        masterKeyEncryptedUserKey: user.akey,
        salt: user.email,
      },
    },
    object: 'sync',
  })
})
