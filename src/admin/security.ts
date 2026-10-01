const encoder = new TextEncoder()

const toHex = (buf: ArrayBuffer | Uint8Array) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')

export async function sha256Hex(input: string): Promise<string> {
  return toHex(await crypto.subtle.digest('SHA-256', encoder.encode(input)))
}

/** 32 random bytes, base64url without padding. */
export function randomToken(bytes = 32): string {
  const buf = crypto.getRandomValues(new Uint8Array(bytes))
  let bin = ''
  for (const b of buf) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Constant-time string comparison. Compares fixed-length digests so length does not leak. */
export async function safeEqual(a: string, b: string): Promise<boolean> {
  const [da, db] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(a)),
    crypto.subtle.digest('SHA-256', encoder.encode(b)),
  ])
  const x = new Uint8Array(da)
  const y = new Uint8Array(db)
  let diff = 0
  for (let i = 0; i < x.length; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0)
  return diff === 0
}

/** Workers cap PBKDF2 at 100000 iterations. */
const MAX_PBKDF2_ITERATIONS = 100_000

const fromHex = (hex: string): Uint8Array<ArrayBuffer> => {
  const out = new Uint8Array(new ArrayBuffer(hex.length / 2))
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

/**
 * Verifies a presented admin token against ADMIN_TOKEN_HASH. Accepted formats:
 *  - 64 hex characters: SHA-256 of the token.
 *  - `pbkdf2$<iterations>$<salt hex>$<hash hex>`: PBKDF2-HMAC-SHA-256, 32 byte output,
 *    iterations at most 100000.
 */
export async function verifyAdminToken(
  token: string,
  stored: string | undefined,
): Promise<boolean> {
  if (!stored || !token) return false
  const value = stored.trim()
  if (/^[0-9a-fA-F]{64}$/.test(value)) {
    return safeEqual(await sha256Hex(token), value.toLowerCase())
  }
  const m = /^pbkdf2\$(\d{1,6})\$([0-9a-fA-F]{2,128})\$([0-9a-fA-F]{64})$/.exec(value)
  if (!m) return false
  const iterations = Number(m[1])
  const saltHex = m[2] as string
  if (iterations < 1 || iterations > MAX_PBKDF2_ITERATIONS || saltHex.length % 2 !== 0) return false
  const key = await crypto.subtle.importKey('raw', encoder.encode(token), 'PBKDF2', false, [
    'deriveBits',
  ])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromHex(saltHex), iterations },
    key,
    256,
  )
  return safeEqual(toHex(bits), (m[3] as string).toLowerCase())
}

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
