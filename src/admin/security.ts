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

export type InstanceRole = 'owner' | 'admin' | 'user'

/** Roles an owner or admin may grant. `owner` is never stored: it only comes from ADMIN_EMAILS. */
export const GRANTABLE_ROLES = ['admin', 'user'] as const
export type GrantableRole = (typeof GRANTABLE_ROLES)[number]

/**
 * The instance role of `user`: `owner` when the address is in ADMIN_EMAILS (the bootstrap set that
 * only the operator can change), otherwise the role granted in D1 (`admin` or `user`). This is the
 * label; whether the role currently confers admin rights is decided by `isAdminUser`.
 */
export function instanceRoleOf(
  env: { ADMIN_EMAILS?: string },
  user: { email: string; instanceRole?: string | null },
): InstanceRole {
  if (isAdminEmail(env.ADMIN_EMAILS, normaliseEmail(user.email))) return 'owner'
  return user.instanceRole === 'admin' ? 'admin' : 'user'
}

/**
 * Whether the account holds an instance role (owner address, or a stored `admin` role), whatever
 * the state of the admin feature. Account recovery and emergency takeover refuse such accounts, so
 * an organisation admin or emergency contact can never inherit instance admin rights.
 */
export const holdsInstanceRole = (
  env: { ADMIN_EMAILS?: string },
  user: { email: string; instanceRole?: string | null },
): boolean => instanceRoleOf(env, user) !== 'user'

/**
 * Whether `user` may act as an instance admin: the admin feature is on, the address was verified
 * (so it cannot be claimed by registering it) and the user is an owner (address in ADMIN_EMAILS)
 * or was granted the `admin` role in D1.
 */
export function isAdminUser(
  env: { ADMIN_ENABLED?: string; ADMIN_EMAILS?: string },
  user: { email: string; verifiedAt: number | null; instanceRole?: string | null },
): boolean {
  return (
    env.ADMIN_ENABLED === 'true' && user.verifiedAt !== null && instanceRoleOf(env, user) !== 'user'
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
