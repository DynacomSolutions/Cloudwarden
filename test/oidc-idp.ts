/**
 * A small OpenID Connect provider for tests: discovery, authorization (driven by the test, no
 * login page), token endpoint with client authentication and PKCE, RS256 ID tokens, JWKS and
 * UserInfo. It answers through a fetch handler, so nothing leaves the test process.
 */

const enc = new TextEncoder()
const b64u = (bytes: Uint8Array | ArrayBuffer) => {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let s = ''
  for (const b of u) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
const json = (v: unknown, status = 200) =>
  new Response(JSON.stringify(v), { status, headers: { 'Content-Type': 'application/json' } })

export interface IdpUser {
  sub: string
  email?: string
  name?: string
  [claim: string]: unknown
}

interface PendingCode {
  clientId: string
  redirectUri: string
  nonce: string | null
  challenge: string | null
  user: IdpUser
  used: boolean
}

export interface OidcIdpOptions {
  issuer?: string
  clientId?: string
  clientSecret?: string
}

export class OidcIdp {
  readonly issuer: string
  readonly clientId: string
  readonly clientSecret: string
  private keys!: CryptoKeyPair
  private kid = 'test-key-1'
  private codes = new Map<string, PendingCode>()
  /** Tweaks for negative tests: change claims of the next ID token or sign with another key. */
  tamper: {
    idToken?: (claims: Record<string, unknown>) => Record<string, unknown>
    otherKey?: CryptoKeyPair
    alg?: string
  } = {}
  readonly calls: string[] = []

  constructor(o: OidcIdpOptions = {}) {
    this.issuer = o.issuer ?? 'https://idp.example.com'
    this.clientId = o.clientId ?? 'cloudwarden'
    this.clientSecret = o.clientSecret ?? 'idp-client-secret'
  }

  async init() {
    this.keys = (await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair
    return this
  }

  /** Simulates the user signing in at the authorization endpoint; returns the redirect URL. */
  authorize(authorizationUrl: string, user: IdpUser): string {
    const u = new URL(authorizationUrl)
    if (`${u.origin}${u.pathname}` !== `${this.issuer}/authorize`)
      throw new Error(`unexpected authorize URL ${u}`)
    const q = u.searchParams
    if (q.get('client_id') !== this.clientId) throw new Error('bad client_id')
    if (q.get('response_type') !== 'code') throw new Error('bad response_type')
    const code = b64u(crypto.getRandomValues(new Uint8Array(16)))
    this.codes.set(code, {
      clientId: q.get('client_id') ?? '',
      redirectUri: q.get('redirect_uri') ?? '',
      nonce: q.get('nonce'),
      challenge: q.get('code_challenge_method') === 'S256' ? q.get('code_challenge') : null,
      user,
      used: false,
    })
    const back = new URL(q.get('redirect_uri') ?? '')
    back.searchParams.set('code', code)
    back.searchParams.set('state', q.get('state') ?? '')
    back.searchParams.set('iss', this.issuer)
    return back.toString()
  }

  private async sign(claims: Record<string, unknown>) {
    const alg = this.tamper.alg ?? 'RS256'
    const header = b64u(enc.encode(JSON.stringify({ alg, kid: this.kid, typ: 'JWT' })))
    const payload = b64u(enc.encode(JSON.stringify(claims)))
    if (alg === 'none') return `${header}.${payload}.`
    const key = (this.tamper.otherKey ?? this.keys).privateKey
    const sig = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      key,
      enc.encode(`${header}.${payload}`),
    )
    return `${header}.${payload}.${b64u(sig)}`
  }

  /** The fetch handler; returns null for URLs outside the provider. */
  async handle(input: RequestInfo | URL, init?: RequestInit): Promise<Response | null> {
    const req = new Request(input as RequestInfo, init)
    const url = new URL(req.url)
    if (url.origin !== new URL(this.issuer).origin) return null
    this.calls.push(`${req.method} ${url.pathname}`)
    switch (url.pathname) {
      case '/.well-known/openid-configuration':
        return json({
          issuer: this.issuer,
          authorization_endpoint: `${this.issuer}/authorize`,
          token_endpoint: `${this.issuer}/token`,
          jwks_uri: `${this.issuer}/jwks`,
          userinfo_endpoint: `${this.issuer}/userinfo`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        })
      case '/jwks': {
        const jwk = (await crypto.subtle.exportKey('jwk', this.keys.publicKey)) as JsonWebKey
        return json({
          keys: [{ kty: jwk.kty, n: jwk.n, e: jwk.e, kid: this.kid, alg: 'RS256', use: 'sig' }],
        })
      }
      case '/token':
        return this.token(req)
      case '/userinfo': {
        const auth = req.headers.get('Authorization') ?? ''
        const user = this.accessTokens.get(auth.replace(/^Bearer /, ''))
        if (!user) return json({ error: 'invalid_token' }, 401)
        return json({ ...user, userinfo: true })
      }
      default:
        return new Response('not found', { status: 404 })
    }
  }

  private accessTokens = new Map<string, IdpUser>()

  private async token(req: Request): Promise<Response> {
    const form = new URLSearchParams(new TextDecoder().decode(await req.arrayBuffer()))
    const basic = req.headers.get('Authorization') ?? ''
    let id = form.get('client_id')
    let secret = form.get('client_secret')
    if (basic.startsWith('Basic ')) {
      const [u, p] = atob(basic.slice(6)).split(':')
      id = decodeURIComponent(u ?? '')
      secret = decodeURIComponent(p ?? '')
    }
    if (id !== this.clientId || secret !== this.clientSecret)
      return json({ error: 'invalid_client' }, 401)
    if (form.get('grant_type') !== 'authorization_code')
      return json({ error: 'unsupported_grant_type' }, 400)
    const pending = this.codes.get(form.get('code') ?? '')
    if (!pending || pending.used) return json({ error: 'invalid_grant' }, 400)
    pending.used = true
    if (pending.redirectUri !== form.get('redirect_uri'))
      return json({ error: 'invalid_grant' }, 400)
    if (pending.challenge) {
      const digest = await crypto.subtle.digest(
        'SHA-256',
        enc.encode(form.get('code_verifier') ?? ''),
      )
      if (b64u(digest) !== pending.challenge)
        return json({ error: 'invalid_grant', error_description: 'pkce' }, 400)
    }
    const now = Math.floor(Date.now() / 1000)
    let claims: Record<string, unknown> = {
      iss: this.issuer,
      aud: this.clientId,
      iat: now,
      exp: now + 300,
      ...(pending.nonce ? { nonce: pending.nonce } : {}),
      // Like most providers, vouch for the address unless the test says otherwise.
      ...(pending.user.email && !('email_verified' in pending.user)
        ? { email_verified: true }
        : {}),
      ...pending.user,
    }
    if (this.tamper.idToken) claims = this.tamper.idToken(claims)
    const accessToken = b64u(crypto.getRandomValues(new Uint8Array(16)))
    this.accessTokens.set(accessToken, pending.user)
    return json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 300,
      id_token: await this.sign(claims),
    })
  }
}
