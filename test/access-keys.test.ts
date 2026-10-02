import { env } from 'cloudflare:workers'
import { beforeAll, describe, expect, it } from 'vitest'
import { signAccessJwt, verifyAccessJwt } from '../src/auth/access-keys'
import { signJwt } from '../src/auth/jwt'
import { BASE, registerUser } from './helpers'
import { call } from './sso-helpers'

/** A P-256 key as the operator would set it: base64 PKCS#8. */
async function newKey() {
  const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  const der = new Uint8Array((await crypto.subtle.exportKey('pkcs8', kp.privateKey)) as ArrayBuffer)
  return btoa(String.fromCharCode(...der))
}

let current: string
let previous: string
beforeAll(async () => {
  current = await newKey()
  previous = await newKey()
})

const now = () => Math.floor(Date.now() / 1000)
const claims = () => ({ sub: 'x', nbf: now() - 1, exp: now() + 60 })

describe('ES256 access tokens and JWKS', () => {
  it('signs ES256 with a kid and verifies it, rejecting tampering and unknown keys', async () => {
    const e = { ...env, JWT_SIGNING_KEY: current }
    const token = await signAccessJwt(e, claims())
    const header = JSON.parse(atob(token.split('.')[0] ?? ''))
    expect(header).toMatchObject({ alg: 'ES256', typ: 'JWT' })
    expect(header.kid).toBeTruthy()
    expect(await verifyAccessJwt(e, token)).toMatchObject({ sub: 'x' })
    const [h, , s] = token.split('.')
    const forged = `${h}.${btoa(JSON.stringify({ ...claims(), sub: 'y' })).replace(/=+$/, '')}.${s}`
    expect(await verifyAccessJwt(e, forged)).toBeNull()
    expect(await verifyAccessJwt({ ...env, JWT_SIGNING_KEY: previous }, token)).toBeNull()
  })

  it('keeps accepting HS256 tokens and previous-key tokens during rotation', async () => {
    const hs = await signJwt(claims(), env.JWT_SECRET as string)
    const old = await signAccessJwt({ ...env, JWT_SIGNING_KEY: previous }, claims())
    const rotated = { ...env, JWT_SIGNING_KEY: current, JWT_SIGNING_KEY_PREVIOUS: previous }
    expect(await verifyAccessJwt(rotated, hs)).toMatchObject({ sub: 'x' })
    expect(await verifyAccessJwt(rotated, old)).toMatchObject({ sub: 'x' })
    expect(await verifyAccessJwt({ ...env, JWT_SIGNING_KEY: current }, old)).toBeNull()
  })

  it('rejects expired and alg none tokens', async () => {
    const e = { ...env, JWT_SIGNING_KEY: current }
    const expired = await signAccessJwt(e, { sub: 'x', exp: now() - 10 })
    expect(await verifyAccessJwt(e, expired)).toBeNull()
    const none = `${btoa(JSON.stringify({ alg: 'none' }))}.${btoa(JSON.stringify(claims()))}.`
    expect(await verifyAccessJwt(e, none)).toBeNull()
  })

  it('publishes discovery and a JWKS whose key verifies issued access tokens', async () => {
    const overrides = { JWT_SIGNING_KEY: current, JWT_SIGNING_KEY_PREVIOUS: previous }
    const disc = (await (
      await call('/identity/.well-known/openid-configuration', {}, overrides)
    ).json()) as any
    expect(disc.issuer).toBe(BASE)
    expect(disc.jwks_uri).toBe(`${BASE}/identity/.well-known/openid-configuration/jwks`)
    const set = (await (await call(new URL(disc.jwks_uri).pathname, {}, overrides)).json()) as any
    expect(set.keys).toHaveLength(2)

    await registerUser('es256@example.com')
    const login = await call(
      '/identity/connect/token',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'password',
          username: 'es256@example.com',
          password: 'client-derived-hash',
          scope: 'api offline_access',
          client_id: 'web',
          deviceType: '9',
          deviceName: 'chrome',
          deviceIdentifier: 'es-device',
        }).toString(),
      },
      overrides,
    )
    const body = (await login.json()) as any
    const [h, p, s] = (body.access_token as string).split('.') as [string, string, string]
    const header = JSON.parse(atob(h.replace(/-/g, '+').replace(/_/g, '/')))
    const jwk = set.keys.find((k: any) => k.kid === header.kid)
    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    )
    const sig = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (ch) =>
      ch.charCodeAt(0),
    )
    expect(
      await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        sig,
        new TextEncoder().encode(`${h}.${p}`),
      ),
    ).toBe(true)
    // The token works against the API.
    const profile = await call(
      '/api/accounts/profile',
      { headers: { Authorization: `Bearer ${body.access_token}` } },
      overrides,
    )
    expect(profile.status).toBe(200)
  })

  it('serves an empty JWKS without a signing key', async () => {
    const set = (await (
      await call('/identity/.well-known/openid-configuration/jwks')
    ).json()) as any
    expect(set.keys).toEqual([])
  })
})
