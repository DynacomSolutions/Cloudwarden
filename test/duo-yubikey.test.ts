import { env } from 'cloudflare:workers'
import { afterEach, describe, expect, it } from 'vitest'
import { duoNet, nonceFor, signHs512, verifyHs512 } from '../src/auth/duo'
import { isLater, signingString, signParams, yubicoNet } from '../src/auth/yubico'
import { BASE, createSession, login } from './helpers'
import { actor, addMember, createOrg } from './org-helpers'

const PW = 'client-derived-hash'
const HOST = 'api-abc12345.duosecurity.com'
const CLIENT_ID = 'DIABCDEFGHIJKLMNOPQR'
const SECRET = 'a'.repeat(40)

const realDuo = duoNet.fetch
const realYubico = yubicoNet.fetch
afterEach(() => {
  duoNet.fetch = realDuo
  yubicoNet.fetch = realYubico
})

const call = async (token: string, path: string, body: unknown, method = 'POST') => {
  const res = await fetchApp(path, method, token, body)
  const text = await res.text()
  return { status: res.status, body: text ? (JSON.parse(text) as any) : null }
}

const yubiEnv = {
  YUBICO_CLIENT_ID: '4242',
  YUBICO_SECRET_KEY: btoa('yubico-test-secret!'),
}
async function fetchApp(path: string, method: string, token: string, body?: unknown) {
  const { default: app } = await import('../src/index')
  return app.fetch(
    new Request(`${BASE}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }),
    { ...env, ...yubiEnv },
  )
}

describe('fixed vectors', () => {
  it('signs Yubico requests with HMAC-SHA1 over the sorted parameters', async () => {
    const params = {
      id: '1234',
      otp: 'c'.repeat(44),
      nonce: '0123456789abcdef0123456789abcdef',
      timestamp: '1',
    }
    expect(signingString({ ...params, h: 'ignored' })).toBe(
      `id=1234&nonce=0123456789abcdef0123456789abcdef&otp=${'c'.repeat(44)}&timestamp=1`,
    )
    // Computed independently with Python hmac.
    expect(await signParams(params, btoa('yubico-test-secret!'))).toBe(
      'YKqZFnwXfD3dET7Vyj3t1q8klhU=',
    )
  })

  it('orders OTP positions and accepts only standard base64 keys', async () => {
    expect(isLater({ counter: 5, use: 2 }, { counter: 5, use: 1 })).toBe(true)
    expect(isLater({ counter: 6, use: 1 }, { counter: 5, use: 9 })).toBe(true)
    expect(isLater({ counter: 5, use: 1 }, { counter: 5, use: 1 })).toBe(false)
    expect(isLater({ counter: 4, use: 9 }, { counter: 5, use: 1 })).toBe(false)
    expect(isLater({ counter: 1, use: 1 }, undefined)).toBe(true)
    const params = { id: '1' }
    await expect(signParams(params, 'eXViaWNvLXRlc3Qtc2VjcmV0IQ')).rejects.toThrow()
    await expect(signParams(params, 'eXViaWNvLXRlc3Qt_2VjcmV0IQ==')).rejects.toThrow()
  })

  it('produces and verifies HS512 JWTs', async () => {
    const vector = [
      'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9',
      'eyJhIjoxLCJpc3MiOiJ4In0',
      'VEgAwixa34uPd3Rl1GvxiIGc_8O84_OqcH7RJl2j-huZyRi8ky4ZEwr-Tz5v0Uc9lrEVO4S45cl5nY3w4Av2PA',
    ].join('.')
    expect(await signHs512({ a: 1, iss: 'x' }, 'duo-secret')).toBe(vector)
    expect(await verifyHs512(vector, 'duo-secret', undefined, false)).toEqual({ a: 1, iss: 'x' })
    expect(await verifyHs512(vector, 'duo-secret')).toBeNull() // no exp
    expect(await verifyHs512(vector, 'other-secret', undefined, false)).toBeNull()
    expect(await verifyHs512(`${vector.slice(0, -2)}AA`, 'duo-secret', undefined, false)).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// YubiKey
// ---------------------------------------------------------------------------

const otp = (id: string, n: number) =>
  `${id}${'cbdefghijklnrtuv'
    .repeat(2)
    .slice(n % 16, (n % 16) + 32)
    .padEnd(32, 'c')}`
const ID_A = 'ccccccccccbb'
const ID_B = 'ccccccccccdd'

/** Answers like YubiCloud: signed, and each OTP works once. */
function fakeYubiCloud(valid: Set<string>) {
  const used = new Set<string>()
  let uses = 0
  const seen: URLSearchParams[] = []
  yubicoNet.fetch = async (input) => {
    const q = new URL(input).searchParams
    seen.push(q)
    const request = Object.fromEntries(q.entries())
    const expected = await signParams(request, yubiEnv.YUBICO_SECRET_KEY)
    let status = 'OK'
    if (expected !== request.h) status = 'BAD_SIGNATURE'
    else if (used.has(request.otp as string)) status = 'REPLAYED_OTP'
    else if (!valid.has(request.otp as string)) status = 'BAD_OTP'
    else used.add(request.otp as string)
    const body: Record<string, string> = {
      otp: request.otp as string,
      nonce: request.nonce as string,
      t: '2026-01-01T00:00:00Z0000',
      sessioncounter: '5',
      sessionuse: String(++uses),
      status,
    }
    body.h = await signParams(body, yubiEnv.YUBICO_SECRET_KEY)
    return new Response(
      `${Object.entries(body)
        .map(([k, v]) => `${k}=${v}`)
        .join('\r\n')}\r\n`,
    )
  }
  return seen
}

const tokenLogin = async (email: string, extra: Record<string, string>) => {
  const { default: app } = await import('../src/index')
  const res = await app.fetch(
    new Request(`${BASE}/identity/connect/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        username: email,
        password: PW,
        scope: 'api offline_access',
        client_id: 'web',
        deviceType: '9',
        deviceName: 'chrome',
        deviceIdentifier: 'device-1',
        ...extra,
      }).toString(),
    }),
    { ...env, ...yubiEnv },
  )
  return { status: res.status, body: (await res.json()) as any }
}

describe('YubiKey OTP', () => {
  it('registers keys, challenges and verifies one-time passwords', async () => {
    const email = 'yk-flow@example.com'
    const s = await createSession(email)
    const first = otp(ID_A, 1)
    const second = otp(ID_B, 2)
    const seen = fakeYubiCloud(new Set([first, second, otp(ID_A, 3), otp(ID_A, 4)]))

    const got = await call(s.access_token, '/api/two-factor/get-yubikey', {
      masterPasswordHash: PW,
    })
    expect(got.body.yubiKey.enabled).toBe(false)
    const bad = await call(
      s.access_token,
      '/api/two-factor/yubikey',
      { key1: otp(ID_A, 9), userVerificationToken: got.body.userVerificationToken },
      'PUT',
    )
    expect(bad.status).toBe(400)
    const put = await call(
      s.access_token,
      '/api/two-factor/yubikey',
      {
        key1: first,
        key2: second,
        nfc: true,
        userVerificationToken: got.body.userVerificationToken,
      },
      'PUT',
    )
    expect(put.status).toBe(200)
    expect(put.body.yubiKey).toMatchObject({
      enabled: true,
      key1: ID_A,
      key2: ID_B,
      key3: null,
      nfc: true,
    })
    expect(seen.length).toBeGreaterThan(0)
    expect(seen.every((q) => q.get('id') === '4242' && q.get('h'))).toBe(true)

    const list = await call(s.access_token, '/api/two-factor', undefined, 'GET')
    expect(list.body.data).toContainEqual({ enabled: true, type: 3, object: 'twoFactorProvider' })

    const ch = await tokenLogin(email, {})
    expect(ch.status).toBe(400)
    expect(ch.body.TwoFactorProviders).toEqual(['3'])
    expect(ch.body.TwoFactorProviders2['3']).toEqual({ Nfc: true })

    // Wrong id, malformed, replayed and unknown OTPs are all refused.
    for (const token of [otp('ccccccccccee', 5), 'short', first, otp(ID_A, 77)]) {
      const res = await tokenLogin(email, { twoFactorProvider: '3', twoFactorToken: token })
      expect(res.status).toBe(400)
      expect(res.body.access_token).toBeUndefined()
    }
    const ok = await tokenLogin(email, {
      twoFactorProvider: '3',
      twoFactorToken: otp(ID_A, 3).toUpperCase(),
    })
    expect(ok.status).toBe(200)
    expect(ok.body.access_token).toBeTruthy()

    // The same OTP cannot be replayed.
    const replay = await tokenLogin(email, { twoFactorProvider: '3', twoFactorToken: otp(ID_A, 3) })
    expect(replay.status).toBe(400)

    // Keeping existing keys by id needs no validation call, and removing disables the provider.
    const keep = await call(
      s.access_token,
      '/api/two-factor/yubikey',
      { key1: ID_A, nfc: false, userVerificationToken: got.body.userVerificationToken },
      'PUT',
    )
    expect(keep.body.yubiKey).toMatchObject({ key1: ID_A, key2: null, nfc: false })
    const del = await call(
      s.access_token,
      '/api/two-factor/yubikey',
      { userVerificationToken: got.body.userVerificationToken },
      'DELETE',
    )
    expect(del.status).toBe(200)
    expect((await login(email)).status).toBe(200)
  })

  it('rejects a forged YubiCloud answer and a missing configuration', async () => {
    const email = 'yk-forged@example.com'
    const s = await createSession(email)
    const key = otp(ID_A, 1)
    yubicoNet.fetch = async (input) => {
      const q = new URL(input).searchParams
      // Unsigned "OK" without a valid signature.
      return new Response(`otp=${q.get('otp')}\nnonce=${q.get('nonce')}\nstatus=OK\nh=AAAA\n`)
    }
    const forged = await call(
      s.access_token,
      '/api/two-factor/yubikey',
      {
        key1: key,
        masterPasswordHash: PW,
      },
      'PUT',
    )
    expect(forged.status).toBe(400)

    const { default: app } = await import('../src/index')
    const res = await app.fetch(
      new Request(`${BASE}/api/two-factor/yubikey`, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${s.access_token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ key1: key, masterPasswordHash: PW }),
      }),
      { ...env, YUBICO_CLIENT_ID: undefined, YUBICO_SECRET_KEY: undefined },
    )
    expect(res.status).toBe(400)
    expect(((await res.json()) as any).message).toContain('YUBICO_CLIENT_ID')
  })
})

// ---------------------------------------------------------------------------
// Duo
// ---------------------------------------------------------------------------

/** A Duo that approves any user for the authorize request it issued. */
function fakeDuo(opts: { result?: string; secret?: string; nonce?: string } = {}) {
  const secret = opts.secret ?? SECRET
  const calls: string[] = []
  duoNet.fetch = async (url, init) => {
    calls.push(url)
    const params = new URLSearchParams(String(init?.body))
    const assertion = await verifyHs512(params.get('client_assertion') ?? '', secret)
    if (!assertion || assertion.iss !== CLIENT_ID || assertion.aud !== url) {
      return new Response('{}', { status: 401 })
    }
    if (url.endsWith('/health_check')) return Response.json({ stat: 'OK' })
    if (params.get('grant_type') !== 'authorization_code' || !params.get('code')) {
      return new Response('{}', { status: 400 })
    }
    const [, user, nonce] = (params.get('code') ?? '').split(':')
    return Response.json({
      id_token: await signHs512(
        {
          iss: `https://${HOST}/oauth/v1/token`,
          aud: CLIENT_ID,
          preferred_username: user,
          nonce: opts.nonce ?? nonce,
          iat: Math.floor(Date.now() / 1000),
          auth_result: { result: opts.result ?? 'allow' },
          exp: Math.floor(Date.now() / 1000) + 300,
        },
        secret,
      ),
    })
  }
  return calls
}

const duoToken = async (user: string, state: string) =>
  `x:${user}:${await nonceFor(state)}|${state}`

const duoBody = { host: HOST, clientId: CLIENT_ID, clientSecret: SECRET }

describe('Duo', () => {
  it('configures Duo, issues an AuthUrl and verifies code and state', async () => {
    const email = 'duo-user@example.com'
    const s = await createSession(email)
    const calls = fakeDuo()
    const got = await call(s.access_token, '/api/two-factor/get-duo', { masterPasswordHash: PW })
    expect(got.body.duo.enabled).toBe(false)

    // Validation: foreign hosts and bad ids never reach the network.
    for (const bad of [
      { ...duoBody, host: 'evil.example.com' },
      { ...duoBody, host: 'api-1.duosecurity.com.evil.com' },
      { ...duoBody, clientId: 'short' },
    ]) {
      const res = await call(
        s.access_token,
        '/api/two-factor/duo',
        { ...bad, userVerificationToken: got.body.userVerificationToken },
        'PUT',
      )
      expect(res.status).toBe(400)
    }
    expect(calls).toHaveLength(0)
    const wrong = await call(
      s.access_token,
      '/api/two-factor/duo',
      {
        ...duoBody,
        clientSecret: 'b'.repeat(40),
        masterPasswordHash: PW,
      },
      'PUT',
    )
    expect(wrong.status).toBe(400)

    const put = await call(
      s.access_token,
      '/api/two-factor/duo',
      {
        ...duoBody,
        userVerificationToken: got.body.userVerificationToken,
      },
      'PUT',
    )
    expect(put.status).toBe(200)
    expect(put.body.duo.enabled).toBe(true)
    expect(put.body.duo.clientSecret).toMatch(/^\*+aaaa$/)
    // The masked secret survives a re-save from the clients.
    const resave = await call(
      s.access_token,
      '/api/two-factor/duo',
      {
        ...duoBody,
        clientSecret: put.body.duo.clientSecret,
        masterPasswordHash: PW,
      },
      'PUT',
    )
    expect(resave.status).toBe(200)

    const ch = await tokenLogin(email, {})
    expect(ch.status).toBe(400)
    expect(ch.body.TwoFactorProviders).toEqual(['2'])
    const { Host, AuthUrl } = ch.body.TwoFactorProviders2['2']
    expect(Host).toBe(HOST)
    const url = new URL(AuthUrl)
    expect(url.origin + url.pathname).toBe(`https://${HOST}/oauth/v1/authorize`)
    expect(url.searchParams.get('client_id')).toBe(CLIENT_ID)
    const request = (await verifyHs512(url.searchParams.get('request') as string, SECRET)) as any
    expect(request).toMatchObject({
      scope: 'openid',
      response_type: 'code',
      duo_uname: email,
      use_duo_code_attribute: true,
      redirect_uri: `${BASE}/duo-redirect-connector.html?client=web`,
    })
    expect(request.state.length).toBeGreaterThan(22)

    const accept = await tokenLogin(email, {
      twoFactorProvider: '2',
      twoFactorToken: await duoToken(email, request.state),
    })
    expect(accept.status).toBe(200)
    expect(accept.body.access_token).toBeTruthy()

    // A state works once.
    const replay = await tokenLogin(email, {
      twoFactorProvider: '2',
      twoFactorToken: await duoToken(email, request.state),
    })
    expect(replay.status).toBe(400)

    // Garbage, a code approved for another user, a wrong nonce and another device all fail.
    const fresh = async (device = 'device-1') => {
      const ch2 = await tokenLogin(email, { deviceIdentifier: device })
      const u = new URL(ch2.body.TwoFactorProviders2['2'].AuthUrl)
      return ((await verifyHs512(u.searchParams.get('request') as string, SECRET)) as any).state
    }
    const state = await fresh()
    const attempts: [string, string][] = [
      [`x:${email}:n|garbage`, 'device-1'],
      ['nopipe', 'device-1'],
      [await duoToken('other@example.com', state), 'device-1'],
      [`x:${email}:wrong|${state}`, 'device-1'],
      [await duoToken(email, state), 'device-2'],
    ]
    for (const [token, device] of attempts) {
      const res = await tokenLogin(email, {
        twoFactorProvider: '2',
        twoFactorToken: token,
        deviceIdentifier: device,
      })
      expect(res.status).toBe(400)
      expect(res.body.access_token).toBeUndefined()
    }
    // After the failed attempts that reached Duo burned the state, a new one still works.
    const again = await tokenLogin(email, {
      twoFactorProvider: '2',
      twoFactorToken: await duoToken(email, await fresh()),
    })
    expect(again.status).toBe(200)

    const del = await call(
      s.access_token,
      '/api/two-factor/duo',
      {
        userVerificationToken: got.body.userVerificationToken,
      },
      'DELETE',
    )
    expect(del.status).toBe(200)
    expect((await login(email)).status).toBe(200)
  })

  it('refuses when Duo does not allow the user', async () => {
    const email = 'duo-deny@example.com'
    const s = await createSession(email)
    fakeDuo()
    await call(s.access_token, '/api/two-factor/duo', { ...duoBody, masterPasswordHash: PW }, 'PUT')
    fakeDuo({ result: 'deny' })
    const ch = await tokenLogin(email, {})
    const url = new URL(ch.body.TwoFactorProviders2['2'].AuthUrl)
    const request = (await verifyHs512(url.searchParams.get('request') as string, SECRET)) as any
    const res = await tokenLogin(email, {
      twoFactorProvider: '2',
      twoFactorToken: await duoToken(email, request.state),
    })
    expect(res.status).toBe(400)
    expect(res.body.access_token).toBeUndefined()
  })

  it('enforces organisation Duo for confirmed members', async () => {
    const owner = await actor('duo-owner@example.com')
    const member = await actor('duo-member@example.com')
    const outsider = await actor('duo-outsider@example.com')
    const org = await createOrg(owner)
    await addMember(owner, org.id, member)
    fakeDuo()

    const denied = await member.call(`/api/organizations/${org.id}/two-factor/get-duo`, 'POST', {
      masterPasswordHash: PW,
    })
    expect(denied.status).toBe(403)
    expect((await outsider.call(`/api/organizations/${org.id}/two-factor`, 'GET')).status).toBe(404)

    const got = await owner.json(`/api/organizations/${org.id}/two-factor/get-duo`, 'POST', {
      masterPasswordHash: PW,
    })
    expect(got.duo.enabled).toBe(false)
    const put = await owner.call(`/api/organizations/${org.id}/two-factor/duo`, 'PUT', {
      ...duoBody,
      userVerificationToken: got.userVerificationToken,
    })
    expect(put.status).toBe(200)
    const list = await owner.json(`/api/organizations/${org.id}/two-factor`)
    expect(list.data).toEqual([{ enabled: true, type: 6, object: 'twoFactorProvider' }])

    // The member now needs Duo (provider 6); the outsider does not.
    const ch = await tokenLogin(member.email, {})
    expect(ch.status).toBe(400)
    expect(ch.body.TwoFactorProviders).toEqual(['6'])
    const url = new URL(ch.body.TwoFactorProviders2['6'].AuthUrl)
    const request = (await verifyHs512(url.searchParams.get('request') as string, SECRET)) as any
    expect(request.duo_uname).toBe(member.email)
    const ok = await tokenLogin(member.email, {
      twoFactorProvider: '6',
      twoFactorToken: await duoToken(member.email, request.state),
    })
    expect(ok.status).toBe(200)
    expect((await tokenLogin(outsider.email, {})).status).toBe(200)

    const del = await owner.call(`/api/organizations/${org.id}/two-factor/duo`, 'DELETE', {
      masterPasswordHash: PW,
    })
    expect(del.status).toBe(200)
    expect((await tokenLogin(member.email, {})).status).toBe(200)
  })
})
