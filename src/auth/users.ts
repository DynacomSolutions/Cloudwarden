import { eq } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'
import type { User } from '../env'

export const normalizeEmail = (email: string): string => email.trim().toLowerCase()

export async function findUserByEmail(db: Db, email: string): Promise<User | null> {
  const [user] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, normalizeEmail(email)))
    .limit(1)
  return user ?? null
}
