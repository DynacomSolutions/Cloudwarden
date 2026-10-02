export const normaliseEmail = (raw: unknown): string =>
  typeof raw === 'string' ? raw.trim().toLowerCase() : ''

export const isPlausibleEmail = (email: string): boolean =>
  email.length <= 254 && /^[^\s@<>"',;]+@[^\s@<>"',;]+\.[^\s@<>"',;]+$/.test(email)

export function isAdminEmail(list: string | undefined, email: string): boolean {
  if (!email || !list) return false
  return list
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean)
    .includes(email)
}

/**
 * Whether `user` may act as an instance admin: the admin feature is on, the address is listed in
 * ADMIN_EMAILS and the address was verified (so it cannot be claimed by registering it).
 */
export function isAdminUser(
  env: { ADMIN_ENABLED?: string; ADMIN_EMAILS?: string },
  user: { email: string; verifiedAt: number | null },
): boolean {
  return (
    env.ADMIN_ENABLED === 'true' &&
    user.verifiedAt !== null &&
    isAdminEmail(env.ADMIN_EMAILS, normaliseEmail(user.email))
  )
}

/**
 * Fixed-window counter in D1. Returns true when the call is within `limit`.
 * Old windows are pruned opportunistically.
 */
export async function rateLimit(
  db: D1Database,
  key: string,
  limit: number,
  windowMs: number,
  now: number,
): Promise<boolean> {
  const windowStart = Math.floor(now / windowMs) * windowMs
  const row = await db
    .prepare(
      `INSERT INTO admin_rate_limits (key, window_start, count) VALUES (?1, ?2, 1)
       ON CONFLICT (key, window_start) DO UPDATE SET count = count + 1
       RETURNING count`,
    )
    .bind(key, windowStart)
    .first<{ count: number }>()
  if (Math.random() < 0.05) {
    await db
      .prepare('DELETE FROM admin_rate_limits WHERE window_start < ?1')
      .bind(now - 24 * 3600_000)
      .run()
  }
  return (row?.count ?? 1) <= limit
}
