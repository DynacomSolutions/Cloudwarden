import { drizzle } from 'drizzle-orm/d1'
import * as schema from './schema'

export const createDb = (d1: D1Database) => drizzle(d1, { schema })
export type Db = ReturnType<typeof createDb>
export { schema }

type Stmt = Parameters<Db['batch']>[0][number]

/** Runs statements atomically (D1 batch is one implicit transaction). */
export async function runBatch(db: Db, statements: Stmt[]): Promise<void> {
  if (statements.length === 0) return
  await db.batch(statements as [Stmt, ...Stmt[]])
}
