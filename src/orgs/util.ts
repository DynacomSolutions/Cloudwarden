import type { MiddlewareHandler } from 'hono'
import { requireAuth } from '../auth/middleware'
import { type Db, runBatch } from '../db'
import type { Env } from '../env'

/** `requireAuth` that skips work when an earlier router already authenticated the request. */
export const authOnce: MiddlewareHandler<Env> = async (c, next) =>
  c.get('user') ? next() : requireAuth(c, next)

/** `runBatch` for statement lists built from mixed drizzle builders. */
export const batch = (db: Db, statements: unknown[]) => runBatch(db, statements as never)
