import { env } from 'cloudflare:workers'
import { vi } from 'vitest'
import { createDb, schema } from '../src/db'
import { BASE } from './helpers'
import { OidcIdp } from './oidc-idp'
import type { Actor } from './org-helpers'

/** Helpers shared by the SSO tests: in-process calls, a mock provider on `fetch`, PKCE. */

const ctx = {
  waitUntil: () => {},
  passThroughOnException: () => {},
  props: {},
} as unknown as ExecutionContext

/** Calls the app in-process (so a stubbed global `fetch` serves the identity provider). */
export async function call(
  path: string,
  init: RequestInit = {},
  overrides: Record<string, unknown> = {},
) {
  const { default: app } = await import('../src/index')
  const url = path.startsWith('http') ? path : `${BASE}${path}`
  return app.fetch(new Request(url, { redirect: 'manual', ...init }), { ...env, ...overrides }, ctx)
}

export type FetchHandler = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response | null>

const handlers: FetchHandler[] = []
let installed = false

/** Routes outbound `fetch` through test handlers (identity provider, DNS over HTTPS). */
export function interceptFetch(handler: FetchHandler) {
  handlers.push(handler)
  if (installed) return
  installed = true
  const real = globalThis.fetch
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    for (const h of handlers) {
      const r = await h(input, init)
      if (r) return r
    }
    return real(input, init)
  })
}

export async function startIdp(opts: ConstructorParameters<typeof OidcIdp>[0] = {}) {
  const idp = await new OidcIdp(opts).init()
  interceptFetch((i, init) => idp.handle(i, init))
  return idp
}

const b64u = (bytes: ArrayBuffer | Uint8Array) => {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let s = ''
  for (const b of u) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export async function pkce() {
  const verifier = b64u(crypto.getRandomValues(new Uint8Array(48)))
  const challenge = b64u(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
  return { verifier, challenge }
}

/**
 * Marks `domain` verified for the organisation directly in the database (the DNS flow has its own
 * tests). New SSO accounts are provisioned only for claimed domains or invited addresses.
 */
export async function claimDomain(orgId: string, domain = 'example.com') {
  const db = createDb(env.DB)
  await db
    .insert(schema.organizationDomains)
    .values({
      uuid: crypto.randomUUID(),
      organizationUuid: orgId,
      domainName: domain,
      txt: 'bw=test',
      verifiedAt: Date.now(),
      lastCheckedAt: Date.now(),
      nextRunAt: Date.now(),
      jobRunCount: 0,
      createdAt: Date.now(),
    })
    .onConflictDoNothing()
}

export async function configureOidc(
  owner: Actor,
  orgId: string,
  identifier: string,
  idp: OidcIdp,
  data: Record<string, unknown> = {},
  claim = true,
) {
  if (claim) await claimDomain(orgId)
  const res = await owner.call(`/api/organizations/${orgId}/sso`, 'POST', {
    enabled: true,
    identifier,
    data: {
      configType: 1,
      memberDecryptionType: 0,
      authority: idp.issuer,
      clientId: idp.clientId,
      clientSecret: idp.clientSecret,
      redirectBehavior: 0,
      getClaimsFromUserInfoEndpoint: false,
      ...data,
    },
  })
  if (res.status !== 200) throw new Error(`sso config failed: ${res.status} ${await res.text()}`)
  return res.json()
}

export interface StartOptions {
  identifier: string
  clientId?: string
  redirectUri?: string
  state?: string
  userIdentifier?: string
}

/** Prevalidate and authorize; returns the provider URL and the flow cookie. */
export async function startSso(o: StartOptions) {
  const pre = await call(`/identity/sso/prevalidate?domainHint=${encodeURIComponent(o.identifier)}`)
  if (pre.status !== 200) throw new Error(`prevalidate ${pre.status} ${await pre.text()}`)
  const { token } = (await pre.json()) as { token: string }
  const { verifier, challenge } = await pkce()
  const clientId = o.clientId ?? 'web'
  const redirectUri = o.redirectUri ?? `${BASE}/sso-connector.html`
  const state = o.state ?? `clientstate123_identifier=${o.identifier}`
  const q = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'api offline_access',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    response_mode: 'query',
    domain_hint: o.identifier,
    ssoToken: token,
    ...(o.userIdentifier ? { user_identifier: o.userIdentifier } : {}),
  })
  const res = await call(`/identity/connect/authorize?${q}`)
  const location = res.headers.get('Location') ?? ''
  const cookie = (res.headers.get('Set-Cookie') ?? '').split(';')[0] ?? ''
  return { res, location, cookie, verifier, challenge, clientId, redirectUri, state }
}

/** Follows the provider's redirect back to us; returns our response. */
export const callback = (url: string, cookie: string) => call(url, { headers: { Cookie: cookie } })

export const codeFrom = (location: string) => new URL(location).searchParams.get('code') ?? ''

export async function redeem(
  code: string,
  verifier: string,
  extra: Record<string, string> = {},
  redirectUri = `${BASE}/sso-connector.html`,
) {
  return call('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      redirect_uri: redirectUri,
      client_id: 'web',
      scope: 'api offline_access',
      deviceType: '9',
      deviceName: 'chrome',
      deviceIdentifier: 'sso-device-1',
      ...extra,
    }).toString(),
  })
}

/** A whole OIDC login for `user`; returns the token response. */
export async function oidcLogin(
  idp: OidcIdp,
  identifier: string,
  user: Parameters<OidcIdp['authorize']>[1],
  extra: Record<string, string> = {},
) {
  const s = await startSso({ identifier })
  if (s.res.status !== 302) throw new Error(`authorize ${s.res.status} ${await s.res.text()}`)
  const back = await callback(idp.authorize(s.location, user), s.cookie)
  if (back.status !== 302) return { back, token: null as Response | null, body: null as any }
  const token = await redeem(codeFrom(back.headers.get('Location') ?? ''), s.verifier, extra)
  return { back, token, body: (await token.json()) as any }
}

export const bearer = (accessToken: string) => ({ Authorization: `Bearer ${accessToken}` })

export const authedCall = (accessToken: string, path: string, method = 'GET', body?: unknown) =>
  call(path, {
    method,
    headers: {
      ...bearer(accessToken),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
