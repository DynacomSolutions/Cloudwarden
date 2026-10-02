import { fromB64u, safeEqualStrings, toB64u, utf8 } from './crypto'

/**
 * Duo Universal Prompt (Web SDK v4), a plain OIDC code flow with HS512 signed JWTs:
 *  1. the server builds an authorize URL carrying a signed `request` JWT,
 *  2. the user completes Duo in a popup, which redirects to the vault's duo-redirect connector
 *     with `code` and `state`,
 *  3. the client sends `code|state` as the two-factor token, the server exchanges the code at
 *     the Duo token endpoint (client assertion JWT) and verifies the returned `id_token`.
 * Written from Duo's published protocol description.
 */

export interface DuoConfig {
  host: string
  clientId: string
  clientSecret: string
}

/** Duo API hosts are `api-<id>.duosecurity.com` or `api-<id>.duofederal.com`, nothing else. */
const HOST_RE = /^api-[a-z0-9]+\.(duosecurity|duofederal)\.com$/i
export const isDuoHost = (host: string): boolean => HOST_RE.test(host)

export const DUO_CLIENT_ID_RE = /^[A-Za-z0-9]{20}$/
export const DUO_CLIENT_SECRET_RE = /^[A-Za-z0-9]{40}$/

const JWT_LIFETIME_S = 300

/** Network seam. Tests replace `fetch` to answer as Duo. */
export const duoNet = { fetch: (input: string, init?: RequestInit) => fetch(input, init) }

const b64uJson = (v: unknown) => toB64u(utf8(JSON.stringify(v)))

async function hs512Key(secret: string, usage: 'sign' | 'verify') {
  return crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash: 'SHA-512' }, false, [
    usage,
  ])
}

export async function signHs512(payload: object, secret: string): Promise<string> {
  const body = `${b64uJson({ alg: 'HS512', typ: 'JWT' })}.${b64uJson(payload)}`
  const sig = await crypto.subtle.sign('HMAC', await hs512Key(secret, 'sign'), utf8(body))
  return `${body}.${toB64u(new Uint8Array(sig))}`
}

/** Verifies an HS512 token's signature and `exp`. Returns the claims or null. */
export async function verifyHs512(
  token: string,
  secret: string,
  nowS = Math.floor(Date.now() / 1000),
): Promise<Record<string, unknown> | null> {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const [h, p, s] = parts as [string, string, string]
  try {
    const header = JSON.parse(new TextDecoder().decode(fromB64u(h) ?? new Uint8Array()))
    if (header?.alg !== 'HS512') return null
    const sig = fromB64u(s)
    if (!sig) return null
    const ok = await crypto.subtle.verify(
      'HMAC',
      await hs512Key(secret, 'verify'),
      sig,
      utf8(`${h}.${p}`),
    )
    if (!ok) return null
    const claims = JSON.parse(new TextDecoder().decode(fromB64u(p) ?? new Uint8Array()))
    if (!claims || typeof claims !== 'object') return null
    if (typeof claims.exp === 'number' && claims.exp <= nowS) return null
    if (typeof claims.nbf === 'number' && claims.nbf > nowS + 60) return null
    return claims as Record<string, unknown>
  } catch {
    return null
  }
}

const endpoint = (host: string, path: string) => `https://${host}/oauth/v1/${path}`

const jti = () => toB64u(crypto.getRandomValues(new Uint8Array(24)))

async function clientAssertion(cfg: DuoConfig, audience: string, nowS: number): Promise<string> {
  return signHs512(
    {
      iss: cfg.clientId,
      sub: cfg.clientId,
      aud: audience,
      exp: nowS + JWT_LIFETIME_S,
      jti: jti(),
    },
    cfg.clientSecret,
  )
}

const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

/** Asks Duo whether the configuration (host, client id and secret) is valid. */
export async function duoHealthCheck(cfg: DuoConfig, nowS = Math.floor(Date.now() / 1000)) {
  if (!isDuoHost(cfg.host)) return false
  try {
    const res = await duoNet.fetch(endpoint(cfg.host, 'health_check'), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: cfg.clientId,
        client_assertion: await clientAssertion(cfg, endpoint(cfg.host, 'health_check'), nowS),
      }),
      redirect: 'error',
    })
    if (!res.ok) return false
    const body = (await res.json()) as { stat?: string }
    return body.stat === 'OK'
  } catch {
    return false
  }
}

/** The authorize URL the user opens to complete Duo. */
export async function duoAuthUrl(
  cfg: DuoConfig,
  username: string,
  state: string,
  redirectUri: string,
  nowS = Math.floor(Date.now() / 1000),
): Promise<string> {
  const request = await signHs512(
    {
      scope: 'openid',
      client_id: cfg.clientId,
      redirect_uri: redirectUri,
      state,
      response_type: 'code',
      duo_uname: username,
      iss: cfg.clientId,
      aud: `https://${cfg.host}`,
      exp: nowS + JWT_LIFETIME_S,
      use_duo_code_attribute: true,
    },
    cfg.clientSecret,
  )
  const q = new URLSearchParams({
    response_type: 'code',
    client_id: cfg.clientId,
    request,
  })
  return `${endpoint(cfg.host, 'authorize')}?${q}`
}

/** Checks a decoded `id_token` against the expected issuer, audience and user. */
export function idTokenValid(
  claims: Record<string, unknown>,
  cfg: DuoConfig,
  username: string,
): boolean {
  if (claims.iss !== endpoint(cfg.host, 'token')) return false
  const aud = claims.aud
  if (!(aud === cfg.clientId || (Array.isArray(aud) && aud.includes(cfg.clientId)))) return false
  const user = String(claims.preferred_username ?? '').toLowerCase()
  if (!safeEqualStrings(user, username.toLowerCase())) return false
  const result = (claims.auth_result as { result?: string } | undefined)?.result
  return result === 'allow'
}

/** Exchanges the authorisation code and verifies the identity token. True only on `allow`. */
export async function duoVerifyCode(
  cfg: DuoConfig,
  code: string,
  username: string,
  redirectUri: string,
  nowS = Math.floor(Date.now() / 1000),
): Promise<boolean> {
  if (!isDuoHost(cfg.host) || !code) return false
  try {
    const url = endpoint(cfg.host, 'token')
    const res = await duoNet.fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: cfg.clientId,
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await clientAssertion(cfg, url, nowS),
      }),
      redirect: 'error',
    })
    if (!res.ok) return false
    const body = (await res.json()) as { id_token?: string }
    if (!body.id_token) return false
    const claims = await verifyHs512(body.id_token, cfg.clientSecret, nowS)
    return claims !== null && idTokenValid(claims, cfg, username)
  } catch {
    return false
  }
}

/** Masks a stored secret for display; the clients send the mask back when it is unchanged. */
export const maskSecret = (secret: string): string =>
  secret ? `${'*'.repeat(10)}${secret.slice(-4)}` : ''

export const isMasked = (value: string): boolean => value.includes('*')
