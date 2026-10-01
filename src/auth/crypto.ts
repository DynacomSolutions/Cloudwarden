const encoder = new TextEncoder()

export const utf8 = (s: string): Uint8Array => encoder.encode(s)

export function toB64u(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Decodes base64 or base64url. Returns null on malformed input. */
export function fromB64u(s: string): Uint8Array | null {
  try {
    const std = s.replace(/-/g, '+').replace(/_/g, '/')
    const bin = atob(std + '='.repeat((4 - (std.length % 4)) % 4))
    return Uint8Array.from(bin, (ch) => ch.charCodeAt(0))
  } catch {
    return null
  }
}

export const randomB64u = (bytes = 32): string =>
  toB64u(crypto.getRandomValues(new Uint8Array(bytes)))

/** Constant-time comparison; the work done depends only on the longer input. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let diff = a.length ^ b.length
  const n = Math.max(a.length, b.length)
  for (let i = 0; i < n; i++) diff |= (a[i % (a.length || 1)] ?? 0) ^ (b[i % (b.length || 1)] ?? 0)
  return diff === 0
}

export const safeEqualStrings = (a: string, b: string): boolean => timingSafeEqual(utf8(a), utf8(b))

export async function sha256B64u(s: string): Promise<string> {
  return toB64u(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(s))))
}

export async function pbkdf2Sha256(
  secret: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', utf8(secret), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    key,
    256,
  )
  return new Uint8Array(bits)
}
