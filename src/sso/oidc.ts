import * as oauth from 'oauth4webapi'
import { fromB64u, safeEqualStrings, utf8 } from '../auth/crypto'
import type { Bindings } from '../env'
import { type SsoConfigData, ssoUrls } from './config'
import { SsoError } from './errors'

/**
 * OpenID Connect relying party towards an organisation's identity provider (TASKS #281), built on
 * `oauth4webapi`: discovery, authorization code flow with PKCE, state and nonce, ID token
 * validation (issuer, audience, expiry, nonce and, for asymmetric algorithms, the signature against
 * the provider's JWKS), optional UserInfo.
 */

export interface OidcClaims {
  externalId: string
  email: string | null
  name: string | null
  /** `email_verified === true`, or the administrator accepts unverified addresses. */
  emailVerified: boolean
}

const DISCOVERY_TIMEOUT_MS = 10_000

/**
 * Local development and the end-to-end run only (`SSO_ALLOW_INSECURE_LOOPBACK=true`, declared only
 * with `LOCAL_DEV_SECRETS`): an `http://127.0.0.1` or `http://localhost` provider is accepted so a
 * mock provider can run without TLS. Never set in production.
 */
export const insecureLoopback = (env?: Bindings) => env?.SSO_ALLOW_INSECURE_LOOPBACK === 'true'

const isLoopbackHttp = (u: URL) =>
  u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost')

/** `oauth4webapi` option allowing plain http, only for a loopback provider in development. */
const httpOk = (insecure: boolean) =>
  insecure ? { [oauth.allowInsecureRequests]: true as const } : {}

/** The authority as an issuer URL; https only (see `insecureLoopback`). */
function issuerUrl(data: SsoConfigData, insecure = false): URL {
  const raw = (data.authority ?? '').trim()
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new SsoError('The OpenID Connect authority is not a valid URL.')
  }
  if (url.protocol !== 'https:' && !(insecure && isLoopbackHttp(url))) {
    throw new SsoError('The OpenID Connect authority must use https.')
  }
  return url
}

/**
 * Loads the provider metadata. A custom metadata address is fetched directly; otherwise the
 * standard `/.well-known/openid-configuration` under the authority. The issuer in the document
 * must equal the authority.
 */
const DISCOVERY_TTL_MS = 5 * 60 * 1000
const discoveryCache = new Map<string, { as: oauth.AuthorizationServer; at: number }>()
/** JWKS per issuer, reused by `oauth4webapi` between logins in the same isolate. */
const jwksCaches = new Map<string, oauth.JWKSCacheInput>()

export async function discover(
  data: SsoConfigData,
  insecure = false,
): Promise<oauth.AuthorizationServer> {
  const key = `${data.authority ?? ''}|${data.metadataAddress ?? ''}`
  const hit = discoveryCache.get(key)
  if (hit && Date.now() - hit.at < DISCOVERY_TTL_MS) return hit.as
  const as = await discoverUncached(data, insecure)
  discoveryCache.set(key, { as, at: Date.now() })
  return as
}

async function discoverUncached(
  data: SsoConfigData,
  insecure: boolean,
): Promise<oauth.AuthorizationServer> {
  const issuer = issuerUrl(data, insecure)
  const signal = AbortSignal.timeout(DISCOVERY_TIMEOUT_MS)
  let response: Response
  if (data.metadataAddress?.trim()) {
    let meta: URL
    try {
      meta = new URL(data.metadataAddress.trim())
    } catch {
      throw new SsoError('The OpenID Connect metadata address is not a valid URL.')
    }
    if (meta.protocol !== 'https:' && !(insecure && isLoopbackHttp(meta)))
      throw new SsoError('The metadata address must use https.')
    if (meta.host !== issuer.host) {
      throw new SsoError('The metadata address must be on the same host as the authority.')
    }
    response = await fetch(meta, { headers: { Accept: 'application/json' }, signal })
  } else {
    response = await oauth.discoveryRequest(issuer, {
      algorithm: 'oidc',
      signal,
      ...httpOk(insecure),
    })
  }
  try {
    return await oauth.processDiscoveryResponse(issuer, response)
  } catch (err) {
    throw new SsoError('The identity provider metadata could not be loaded.', err)
  }
}

const client = (data: SsoConfigData): oauth.Client => ({
  client_id: (data.clientId ?? '').trim(),
  // The default allowance (30 s) for clock differences with the provider.
  [oauth.clockTolerance]: 30,
})

/** Client authentication: secret in the body when the provider only allows that, else Basic. */
function clientAuth(as: oauth.AuthorizationServer, data: SsoConfigData): oauth.ClientAuth {
  const secret = data.clientSecret ?? ''
  if (!secret) return oauth.None()
  const methods = as.token_endpoint_auth_methods_supported
  if (
    methods &&
    !methods.includes('client_secret_basic') &&
    methods.includes('client_secret_post')
  ) {
    return oauth.ClientSecretPost(secret)
  }
  return oauth.ClientSecretBasic(secret)
}

export function oidcScopes(data: SsoConfigData): string {
  const scopes = new Set(['openid', 'profile', 'email'])
  for (const s of (data.additionalScopes ?? '').split(/[,\s]+/)) if (s.trim()) scopes.add(s.trim())
  return [...scopes].join(' ')
}

/** URL of the provider's authorization endpoint for this flow. */
export async function oidcAuthorizationUrl(
  env: Bindings,
  orgUuid: string,
  data: SsoConfigData,
  params: { state: string; nonce: string; codeVerifier: string; loginHint?: string },
): Promise<URL> {
  if (!data.clientId?.trim()) throw new SsoError('The OpenID Connect client ID is not set.')
  const as = await discover(data, insecureLoopback(env))
  if (!as.authorization_endpoint) throw new SsoError('The provider has no authorization endpoint.')
  const url = new URL(as.authorization_endpoint)
  url.searchParams.set('client_id', data.clientId.trim())
  url.searchParams.set('redirect_uri', ssoUrls(env, orgUuid).callbackPath)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('scope', oidcScopes(data))
  url.searchParams.set('state', params.state)
  url.searchParams.set('nonce', params.nonce)
  url.searchParams.set(
    'code_challenge',
    await oauth.calculatePKCECodeChallenge(params.codeVerifier),
  )
  url.searchParams.set('code_challenge_method', 'S256')
  if (data.redirectBehavior === 1) url.searchParams.set('response_mode', 'form_post')
  if (data.acrValues?.trim()) url.searchParams.set('acr_values', data.acrValues.trim())
  if (params.loginHint) url.searchParams.set('login_hint', params.loginHint)
  return url
}

/** HS256/384/512 ID tokens are signed with the client secret; verify those here. */
async function verifySymmetricIdToken(idToken: string, secret: string): Promise<void> {
  const [h, p, s] = idToken.split('.')
  if (!h || !p || !s) throw new SsoError('The ID token is malformed.')
  const header = JSON.parse(new TextDecoder().decode(fromB64u(h) ?? new Uint8Array())) as {
    alg?: string
  }
  const hash = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' }[header.alg ?? '']
  if (!hash || !secret) throw new SsoError('The ID token algorithm is not supported.')
  const key = await crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash }, false, [
    'verify',
  ])
  const sig = fromB64u(s)
  if (!sig || !(await crypto.subtle.verify('HMAC', key, sig, utf8(`${h}.${p}`)))) {
    throw new SsoError('The ID token signature is invalid.')
  }
}

const firstString = (claims: Record<string, unknown>, names: string[]): string | null => {
  for (const n of names) {
    const v = claims[n]
    if (typeof v === 'string' && v.trim()) return v.trim()
    if (typeof v === 'number') return String(v)
  }
  return null
}

const extra = (s: string | null | undefined) =>
  (s ?? '')
    .split(/[,\s]+/)
    .map((v) => v.trim())
    .filter(Boolean)

/** Maps provider claims to the account fields, honouring the additional claim type settings. */
export function mapOidcClaims(data: SsoConfigData, claims: Record<string, unknown>): OidcClaims {
  const externalId = firstString(claims, [...extra(data.additionalUserIdClaimTypes), 'sub'])
  if (!externalId) throw new SsoError('The identity provider did not return a subject.')
  // Only the standard `email` claim and claim types the administrator named. Usernames (`upn`,
  // `preferred_username`) are not email addresses the provider vouches for.
  const email = firstString(claims, [...extra(data.additionalEmailClaimTypes), 'email'])
  const name = firstString(claims, [
    ...extra(data.additionalNameClaimTypes),
    'name',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
    'given_name',
  ])
  return {
    externalId,
    email: email?.includes('@') ? email : null,
    name,
    emailVerified: claims.email_verified === true || data.allowUnverifiedEmail === true,
  }
}

/**
 * Completes the authorization code flow from the callback parameters: checks `state`, redeems the
 * code with the PKCE verifier, validates the ID token (and its nonce), optionally merges UserInfo
 * claims, and checks the returned `acr` when one is expected.
 */
export async function completeOidc(
  env: Bindings,
  orgUuid: string,
  data: SsoConfigData,
  params: URLSearchParams,
  expected: { state: string; nonce: string; codeVerifier: string },
): Promise<OidcClaims> {
  const insecure = insecureLoopback(env)
  const as = await discover(data, insecure)
  const c = client(data)
  let callback: URLSearchParams
  try {
    callback = oauth.validateAuthResponse(as, c, params, expected.state)
  } catch (err) {
    throw new SsoError('The identity provider returned an error or an invalid response.', err)
  }
  let result: oauth.TokenEndpointResponse
  let tokenResponse: Response
  try {
    tokenResponse = await oauth.authorizationCodeGrantRequest(
      as,
      c,
      clientAuth(as, data),
      callback,
      ssoUrls(env, orgUuid).callbackPath,
      expected.codeVerifier,
      { signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS), ...httpOk(insecure) },
    )
    result = await oauth.processAuthorizationCodeResponse(as, c, tokenResponse, {
      expectedNonce: expected.nonce,
      requireIdToken: true,
    })
  } catch (err) {
    throw new SsoError('The authorization code could not be redeemed.', err)
  }
  // The token arrived over TLS from the token endpoint, but verify the signature as well.
  const idToken = result.id_token ?? ''
  const alg = (() => {
    try {
      const header = JSON.parse(
        new TextDecoder().decode(fromB64u(idToken.split('.')[0] ?? '') ?? new Uint8Array()),
      ) as { alg?: string }
      return header.alg ?? ''
    } catch {
      return ''
    }
  })()
  if (alg === 'none' || !alg) throw new SsoError('Unsigned ID tokens are not accepted.')
  if (alg.startsWith('HS')) {
    await verifySymmetricIdToken(idToken, data.clientSecret ?? '')
  } else {
    try {
      let cache = jwksCaches.get(as.issuer)
      if (!cache) {
        cache = {}
        jwksCaches.set(as.issuer, cache)
      }
      await oauth.validateApplicationLevelSignature(as, tokenResponse, {
        [oauth.jwksCache]: cache,
        ...httpOk(insecure),
      })
    } catch (err) {
      throw new SsoError('The ID token signature is invalid.', err)
    }
  }
  const idClaims = oauth.getValidatedIdTokenClaims(result)
  if (!idClaims) throw new SsoError('The identity provider did not return an ID token.')
  let claims: Record<string, unknown> = { ...idClaims }

  if (data.expectedReturnAcrValue?.trim()) {
    const acr = typeof idClaims.acr === 'string' ? idClaims.acr : ''
    if (!safeEqualStrings(acr, data.expectedReturnAcrValue.trim())) {
      throw new SsoError('The identity provider did not return the expected acr value.')
    }
  }

  if (data.getClaimsFromUserInfoEndpoint && as.userinfo_endpoint) {
    try {
      const response = await oauth.userInfoRequest(as, c, result.access_token, {
        signal: AbortSignal.timeout(DISCOVERY_TIMEOUT_MS),
        ...httpOk(insecure),
      })
      const info = await oauth.processUserInfoResponse(as, c, idClaims.sub, response)
      claims = { ...claims, ...info, sub: idClaims.sub }
    } catch (err) {
      throw new SsoError('The UserInfo endpoint returned an invalid response.', err)
    }
  }
  return mapOidcClaims(data, claims)
}

/** Fetches discovery and checks the client settings look usable. Used by the admin test button. */
export async function testOidc(data: SsoConfigData, env?: Bindings) {
  const as = await discover(data, insecureLoopback(env))
  const problems: string[] = []
  if (!data.clientId?.trim()) problems.push('Client ID is not set.')
  if (!as.authorization_endpoint) problems.push('No authorization endpoint in the metadata.')
  if (!as.token_endpoint) problems.push('No token endpoint in the metadata.')
  if (!as.jwks_uri) problems.push('No JWKS URI in the metadata.')
  if (as.code_challenge_methods_supported && !as.code_challenge_methods_supported.includes('S256'))
    problems.push('The provider does not advertise PKCE S256 support.')
  return { issuer: as.issuer, problems }
}
