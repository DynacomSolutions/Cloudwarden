import { utf8 } from './crypto'

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export const TOTP_PERIOD_SECONDS = 30
export const TOTP_DIGITS = 6

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0
  let value = 0
  let out = ''
  for (const b of bytes) {
    value = (value << 8) | b
    bits += 8
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31]
      bits -= 5
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31]
  return out
}

/** Decodes RFC 4648 base32, ignoring spaces, hyphens, padding and case. Null on bad input. */
export function base32Decode(input: string): Uint8Array | null {
  const clean = input.replace(/[\s=-]/g, '').toUpperCase()
  if (clean.length === 0) return null
  const out: number[] = []
  let bits = 0
  let value = 0
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch)
    if (idx < 0) return null
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return Uint8Array.from(out)
}

/** A fresh 160 bit secret, base32 encoded (32 characters). */
export const generateTotpKey = (): string =>
  base32Encode(crypto.getRandomValues(new Uint8Array(20)))

export const totpStep = (timeMs: number): number => Math.floor(timeMs / 1000 / TOTP_PERIOD_SECONDS)

/** RFC 4226 HOTP with HMAC-SHA1. */
export async function hotp(secret: Uint8Array, counter: number, digits = TOTP_DIGITS) {
  const msg = new Uint8Array(8)
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter))
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-1' }, false, [
    'sign',
  ])
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg))
  const offset = (mac[mac.length - 1] as number) & 0x0f
  const bin =
    (((mac[offset] as number) & 0x7f) << 24) |
    (((mac[offset + 1] as number) & 0xff) << 16) |
    (((mac[offset + 2] as number) & 0xff) << 8) |
    ((mac[offset + 3] as number) & 0xff)
  return String(bin % 10 ** digits).padStart(digits, '0')
}

export async function totpAt(base32Key: string, timeMs: number): Promise<string | null> {
  const secret = base32Decode(base32Key)
  return secret ? hotp(secret, totpStep(timeMs)) : null
}

/**
 * Checks a code against the steps `now - 1 .. now + 1`. Only steps strictly greater than
 * `lastStep` are accepted, so a code cannot be used twice. Returns the matching step or null.
 */
export async function verifyTotp(
  base32Key: string,
  code: string,
  timeMs: number,
  lastStep: number,
): Promise<number | null> {
  const secret = base32Decode(base32Key)
  const candidate = code.replace(/\s/g, '')
  if (!secret || !/^\d{6}$/.test(candidate)) return null
  const current = totpStep(timeMs)
  let match: number | null = null
  // Evaluate every step so timing does not reveal which one matched.
  for (let step = current - 1; step <= current + 1; step++) {
    const expected = await hotp(secret, step)
    const same = timingEqual(expected, candidate)
    if (same && step > lastStep && match === null) match = step
  }
  return match
}

function timingEqual(a: string, b: string): boolean {
  const x = utf8(a)
  const y = utf8(b)
  let diff = x.length ^ y.length
  for (let i = 0; i < x.length; i++) diff |= (x[i] as number) ^ (y[i] ?? 0)
  return diff === 0
}
