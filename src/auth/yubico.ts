import { fromB64u, safeEqualStrings, utf8 } from './crypto'

/**
 * Yubico OTP validation against YubiCloud (validation protocol version 2.0). Requests and
 * responses are signed with HMAC-SHA1 using the client's API key. Written from Yubico's
 * published protocol description.
 */

export interface YubicoConfig {
  clientId: string
  /** Base64 API key from the Yubico key portal. */
  secretKey: string
  /** Override of the validation endpoint, for example a self-hosted validation server. */
  server?: string
}

const OTP_RE = /^[cbdefghijklnrtuv]{32,48}$/

/** A full OTP is 44 characters: a 12 character public id and a 32 character token. */
export const isOtp = (s: string): boolean => s.length === 44 && OTP_RE.test(s)
export const isPublicId = (s: string): boolean => /^[cbdefghijklnrtuv]{12}$/.test(s)
export const publicIdOf = (otp: string): string => otp.slice(0, 12)

const DEFAULT_SERVERS = [
  'https://api.yubico.com/wsapi/2.0/verify',
  'https://api2.yubico.com/wsapi/2.0/verify',
  'https://api3.yubico.com/wsapi/2.0/verify',
  'https://api4.yubico.com/wsapi/2.0/verify',
  'https://api5.yubico.com/wsapi/2.0/verify',
]

/** Network seam. Tests replace `fetch` to answer as YubiCloud. */
export const yubicoNet = { fetch: (input: string, init?: RequestInit) => fetch(input, init) }

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))

/** Canonical form signed by both sides: `k=v` pairs sorted by key, joined with `&`, `h` excluded. */
export const signingString = (params: Record<string, string>): string =>
  Object.keys(params)
    .filter((k) => k !== 'h')
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join('&')

export async function signParams(
  params: Record<string, string>,
  secretKey: string,
): Promise<string> {
  const raw = fromB64u(secretKey)
  if (!raw) throw new Error('Invalid Yubico secret key')
  const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-1' }, false, [
    'sign',
  ])
  return b64(new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(signingString(params)))))
}

const nonce = () =>
  [...crypto.getRandomValues(new Uint8Array(16))]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')

export function parseResponse(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of text.split(/\r?\n/)) {
    const i = line.indexOf('=')
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 1)
  }
  return out
}

/** True only when YubiCloud answers `OK` with a genuine signature for this exact OTP and nonce. */
export async function verifyOtp(cfg: YubicoConfig, otp: string): Promise<boolean> {
  if (!isOtp(otp)) return false
  const params: Record<string, string> = { id: cfg.clientId, otp, nonce: nonce(), timestamp: '1' }
  let query: string
  try {
    params.h = await signParams(params, cfg.secretKey)
    query = new URLSearchParams(params).toString()
  } catch {
    return false
  }
  for (const server of cfg.server ? [cfg.server] : DEFAULT_SERVERS) {
    try {
      const res = await yubicoNet.fetch(`${server}?${query}`, { redirect: 'error' })
      if (!res.ok) continue
      const body = parseResponse(await res.text())
      return await responseValid(body, params, cfg.secretKey)
    } catch {
      // Try the next validation server.
    }
  }
  return false
}

export async function responseValid(
  body: Record<string, string>,
  request: Record<string, string>,
  secretKey: string,
): Promise<boolean> {
  if (!body.h || !body.status) return false
  if (!safeEqualStrings(body.h, await signParams(body, secretKey))) return false
  if (body.otp !== request.otp || body.nonce !== request.nonce) return false
  return body.status === 'OK'
}
