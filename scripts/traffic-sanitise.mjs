// Deterministic sanitiser and identifier check for recorded client traffic (TASKS #367).
// No Node imports on purpose: the Vitest replay test runs this inside workerd.
//
// Every real value is replaced by a placeholder that is stable for the whole fixture:
//   UUIDs            00000000-0000-0000-0000-00000000000N (N counts distinct ids by first sight)
//   secrets, tokens  __NAME__, __NAME_2__ ... (one placeholder per distinct value)
//   emails           user@example.com
//   hosts and ports  vault.example.com
//   dates            2099-01-01T00:00:00.000Z
//   ciphertext       the EncString type and shape kept, every base64 character zeroed

export const FIXED_DATE = '2099-01-01T00:00:00.000Z'
export const FIXED_EMAIL = 'user@example.com'
export const FIXED_HOST = 'vault.example.com'

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g
const JWT = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/
/** A JWT anywhere in a string, e.g. wrapped in literal quotes or embedded in a longer value. */
const JWT_ANYWHERE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g
const JWT_PREFIX = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\./
const DATE = /\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?/g
const IPV4 = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
const LOCAL_URL = /(?:https?:\/\/)?(?:127\.0\.0\.1|localhost)(?::\d+)?/g
const ENC_STRING = /^[0-9]\.[A-Za-z0-9+/=_-]+(?:\|[A-Za-z0-9+/=_-]+){0,2}$/
const WHOLE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const LONG_B64 = /^[A-Za-z0-9+/_-]{32,}={0,2}$/
const isLongB64 = (s) => LONG_B64.test(s) && !WHOLE_UUID.test(s)
const PLACEHOLDER_SRC = '__[A-Z0-9]+(?:_[A-Z0-9]+)*__|00000000-0000-0000-0000-0000000000[0-9a-f]{2}'
/** Matches placeholders inside a string (global) and as a whole string. */
export const PLACEHOLDER = new RegExp(PLACEHOLDER_SRC, 'g')
export const WHOLE_PLACEHOLDER = new RegExp(`^(?:${PLACEHOLDER_SRC})$`)
const SENSITIVE_KEYS = new Set([
  'password',
  'masterpasswordhash',
  'masterpasswordauthenticationhash',
  'newmasterpasswordhash',
  'password_hash_b64',
  'client_secret',
  'apikey',
  'access_token',
  'refresh_token',
  'send_id',
  'accessid',
  'token',
  'code',
  'securitystamp',
  'pushtoken',
  'emailverificationtoken',
])

/** Keeps the shape of a base64-ish string and zeroes every data character. */
const zero = (s) => s.replace(/[A-Za-z0-9+/_-]/g, 'A')
/** Zeroes the data of an EncString but keeps its type prefix and part structure. */
const zeroEnc = (s) => s.slice(0, 2) + zero(s.slice(2))
const isEnc = (s) => ENC_STRING.test(s) && (s.includes('|') || s.length >= 24)

const uuidPlaceholder = (n) => `00000000-0000-0000-0000-${n.toString(16).padStart(12, '0')}`

/** A sanitiser instance holds the value to placeholder tables of one fixture. */
export function createSanitiser() {
  const ids = new Map()
  const secrets = new Map()
  const counts = new Map()

  const uuid = (real) => {
    const k = real.toLowerCase()
    if (/^0{8}-0{4}-0{4}-0{4}-[0-9a-f]{12}$/.test(k)) return k // already a placeholder (or nil)
    if (!ids.has(k)) ids.set(k, uuidPlaceholder(ids.size + 1))
    return ids.get(k)
  }
  const secret = (real, key) => {
    if (WHOLE_PLACEHOLDER.test(real)) return real
    if (!secrets.has(real)) {
      const base = key.toUpperCase().replace(/[^A-Z0-9]/g, '_')
      const n = (counts.get(base) ?? 0) + 1
      counts.set(base, n)
      secrets.set(real, n === 1 ? `__${base}__` : `__${base}_${n}__`)
    }
    return secrets.get(real)
  }

  /** Sanitises one string found under `key` (use '' when it has no key). */
  const string = (s, key = '') => {
    const k = key.toLowerCase()
    if (s === '') return s
    if (JWT.test(s)) return secret(s, k === 'refresh_token' ? 'refresh_token' : 'access_token')
    if (JWT_PREFIX.test(s)) s = s.replace(JWT_ANYWHERE, (m) => secret(m, 'access_token'))
    if (SENSITIVE_KEYS.has(k)) return new RegExp(PLACEHOLDER_SRC).test(s) ? s : secret(s, key)
    if (isEnc(s)) return zeroEnc(s)
    if (k !== '' && k !== 'path' && isLongB64(s)) return zero(s)
    return s
      .replace(EMAIL, FIXED_EMAIL)
      .replace(LOCAL_URL, (m) => (m.startsWith('http') ? `https://${FIXED_HOST}` : FIXED_HOST))
      .replace(UUID, uuid)
      .replace(DATE, FIXED_DATE)
  }

  const value = (v, key = '') => {
    if (typeof v === 'string') return string(v, key)
    if (Array.isArray(v)) return v.map((x) => value(x, key))
    if (v && typeof v === 'object') {
      return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, value(x, k)]))
    }
    return v
  }
  return { string, value }
}

/**
 * Finds anything in `data` that still looks like real data. Returns `{ path, reason }` entries; an
 * empty list means the fixture is clean.
 */
export function findIdentifying(data) {
  const out = []
  const scan = (v, path, key) => {
    if (typeof v === 'string') {
      const bad = (reason) => out.push({ path, reason })
      if (WHOLE_PLACEHOLDER.test(v) || v === FIXED_DATE || v === FIXED_EMAIL) return
      if (JWT_PREFIX.test(v)) bad('JWT')
      for (const m of v.match(EMAIL) ?? []) if (!m.endsWith('@example.com')) bad(`email ${m}`)
      for (const m of v.match(UUID) ?? [])
        if (!/^0{8}-0{4}-0{4}-0{4}-[0-9a-f]{12}$/i.test(m)) bad('UUID')
      for (const m of v.match(DATE) ?? []) if (m !== FIXED_DATE) bad(`date ${m}`)
      if (IPV4.test(v)) bad('IP address')
      if (/(?:127\.0\.0\.1|localhost):\d+/.test(v)) bad('local host and port')
      for (const m of v.matchAll(/https?:\/\/([^/\s:?#]+)/g)) {
        const host = m[1] ?? ''
        if (host !== FIXED_HOST && host !== 'example.com' && !host.endsWith('.example.com'))
          bad(`host ${host}`)
      }
      if (isEnc(v) && v !== zeroEnc(v)) bad('ciphertext')
      if (key !== '' && key !== 'path' && isLongB64(v) && v !== zero(v)) bad('long base64 value')
      if (
        SENSITIVE_KEYS.has(key.toLowerCase()) &&
        v.replace(PLACEHOLDER, '').replace(/["'\s]/g, '') !== ''
      )
        bad(`secret in ${key}`)
    } else if (Array.isArray(v)) {
      for (const [i, x] of v.entries()) scan(x, `${path}[${i}]`, key)
    } else if (v && typeof v === 'object') {
      for (const [k, x] of Object.entries(v)) scan(x, path ? `${path}.${k}` : k, k)
    }
  }
  scan(data, '', '')
  return out
}
