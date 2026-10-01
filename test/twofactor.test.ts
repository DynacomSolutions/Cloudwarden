import { env } from 'cloudflare:workers'
import { afterEach, describe, expect, it } from 'vitest'
import { generateTotpKey, totpAt } from '../src/auth/totp'
import { clock } from '../src/auth/twofactor'
import { assert as assertion, newAuthenticator, register } from './authenticator'
import { authed, createSession, form, json, login, type Session, withEnv } from './helpers'

const PW = 'client-derived-hash'
const RP_ID = 'vault.example.com'
const ORIGIN = 'https://vault.example.com'
const FIXED = 1_800_000_000_000

afterEach(() => {
  clock.now = () => Date.now()
})

const call = async (s: Session, path: string, body: unknown, method = 'POST') => {
  const res = await authed(path, s.access_token, method, body)
  const text = await res.text()
  return { status: res.status, body: text ? (JSON.parse(text) as any) : null }
}

async function enableTotp(s: Session, key = generateTotpKey()) {
  const got = await call(s, '/api/two-factor/get-authenticator', { masterPasswordHash: PW })
  const code = (await totpAt(key, clock.now())) as string
  const put = await call(
    s,
    '/api/two-factor/authenticator',
    { key, token: code, userVerificationToken: got.body.userVerificationToken },
    'PUT',
  )
  return { key, put, got }
}

const challenge = async (email: string, extra: Record<string, string> = {}) => {
  const res = await login(email, PW, extra)
  return { status: res.status, body: (await res.json()) as any }
}

const mailbox = () => {
  const sent: { to: string; subject: string; text: string }[] = []
  return {
    sent,
    overrides: {
      EMAIL: {
        send: async (m: { to: string; subject: string; text: string }) => void sent.push(m),
      },
      MAIL_FROM: 'noreply@example.com',
    },
  }
}
const codeFrom = (text: string) => /\b(\d{6})\b/.exec(text)?.[1] as string

describe('provider listing', () => {
  it('lists nothing by default and requires auth', async () => {
    const s = await createSession('tf-none@example.com')
    const res = await call(s, '/api/two-factor', undefined, 'GET')
    expect(res.status).toBe(200)
    expect(res.body).toEqual({ data: [], continuationToken: null, object: 'list' })
    expect((await authed('/api/two-factor', 'bogus')).status).toBe(401)
    const profile = await call(s, '/api/accounts/profile', undefined, 'GET')
    expect(profile.body.twoFactorEnabled).toBe(false)
  })

  it('requires the master password or a verification token', async () => {
    const s = await createSession('tf-auth@example.com')
    expect(
      (await call(s, '/api/two-factor/get-authenticator', { masterPasswordHash: 'no' })).status,
    ).toBe(400)
    expect((await call(s, '/api/two-factor/get-authenticator', {})).status).toBe(400)
    const other = await createSession('tf-auth2@example.com')
    const tok = (await call(other, '/api/two-factor/get-authenticator', { masterPasswordHash: PW }))
      .body.userVerificationToken
    const stolen = await call(s, '/api/two-factor/get-authenticator', {
      userVerificationToken: tok,
    })
    expect(stolen.status).toBe(400)
    const own = await call(other, '/api/two-factor/get-authenticator', {
      userVerificationToken: tok,
    })
    expect(own.status).toBe(200)
  })
})

describe('authenticator (TOTP)', () => {
  it('sets up, challenges, accepts a code once and rejects replays', async () => {
    clock.now = () => FIXED
    const email = 'tf-totp@example.com'
    const s = await createSession(email)
    const { key, put } = await enableTotp(s)
    expect(put.status).toBe(200)
    expect(put.body).toEqual({ authenticator: { enabled: true, key } })

    const list = await call(s, '/api/two-factor', undefined, 'GET')
    expect(list.body.data).toEqual([{ enabled: true, type: 0, object: 'twoFactorProvider' }])
    expect((await call(s, '/api/accounts/profile', undefined, 'GET')).body.twoFactorEnabled).toBe(
      true,
    )

    const first = await challenge(email)
    expect(first.status).toBe(400)
    expect(first.body).toMatchObject({
      error: 'invalid_grant',
      error_description: 'Two factor required.',
      TwoFactorProviders: ['0'],
      TwoFactorProviders2: { '0': null },
      ErrorModel: { Message: 'Two factor required.', Object: 'error' },
    })
    expect(first.body.access_token).toBeUndefined()

    // The code used during setup is burned.
    const setupCode = (await totpAt(key, FIXED)) as string
    const burned = await challenge(email, { twoFactorProvider: '0', twoFactorToken: setupCode })
    expect(burned.status).toBe(400)
    expect(burned.body.error_description).toBe('Two-step token is invalid. Try again.')

    // A code one step ahead (within the window) works once.
    clock.now = () => FIXED + 30_000
    const code = (await totpAt(key, clock.now())) as string
    const ok = await challenge(email, { twoFactorProvider: '0', twoFactorToken: code })
    expect(ok.status).toBe(200)
    expect(ok.body.access_token).toBeTruthy()
    expect(ok.body.TwoFactorToken).toBeUndefined()

    const replay = await challenge(email, { twoFactorProvider: '0', twoFactorToken: code })
    expect(replay.status).toBe(400)

    // Earlier steps stay dead even though they are still inside the window.
    clock.now = () => FIXED + 40_000
    const old = (await totpAt(key, FIXED)) as string
    const stale = await challenge(email, { twoFactorProvider: '0', twoFactorToken: old })
    expect(stale.status).toBe(400)
  })

  it('rejects wrong codes, bad setup tokens and codes outside the window', async () => {
    clock.now = () => FIXED
    const email = 'tf-totp2@example.com'
    const s = await createSession(email)
    const key = generateTotpKey()
    const bad = await call(
      s,
      '/api/two-factor/authenticator',
      { key, token: '000000', masterPasswordHash: PW },
      'PUT',
    )
    expect(bad.status).toBe(400)
    const far = (await totpAt(key, FIXED + 90_000)) as string
    const outside = await call(
      s,
      '/api/two-factor/authenticator',
      { key, token: far, masterPasswordHash: PW },
      'PUT',
    )
    expect(outside.status).toBe(400)
    const short = await call(
      s,
      '/api/two-factor/authenticator',
      { key: 'ABC', token: '123456', masterPasswordHash: PW },
      'PUT',
    )
    expect(short.status).toBe(400)
    expect((await call(s, '/api/two-factor', undefined, 'GET')).body.data).toEqual([])

    await enableTotp(s, key)
    clock.now = () => FIXED + 60_000
    const wrong = await challenge(email, { twoFactorProvider: '0', twoFactorToken: '000000' })
    expect(wrong.status).toBe(400)
    // Unknown provider type for this account falls back to the challenge or an error, never a token.
    const unknown = await challenge(email, { twoFactorProvider: '1', twoFactorToken: '123456' })
    expect(unknown.status).toBe(400)
    expect(unknown.body.access_token).toBeUndefined()
  })

  it('shows the existing key once enabled and disables with a verification token', async () => {
    clock.now = () => FIXED
    const email = 'tf-totp3@example.com'
    const s = await createSession(email)
    const { key } = await enableTotp(s)
    const got = await call(s, '/api/two-factor/get-authenticator', { masterPasswordHash: PW })
    expect(got.body.authenticator).toEqual({ enabled: true, key })
    const del = await call(
      s,
      '/api/two-factor/authenticator',
      { key, userVerificationToken: got.body.userVerificationToken },
      'DELETE',
    )
    expect(del.status).toBe(200)
    expect((await login(email)).status).toBe(200)
    expect((await call(s, '/api/two-factor', undefined, 'GET')).body.data).toEqual([])
  })

  it('does not require 2FA for API key logins', async () => {
    clock.now = () => FIXED
    const s = await createSession('tf-api@example.com')
    await enableTotp(s)
    const key = await call(s, '/api/accounts/api-key', { masterPasswordHash: PW })
    expect(key.status).toBe(200)
    const user = await env.DB.prepare('select uuid from users where email = ?')
      .bind('tf-api@example.com')
      .first<{ uuid: string }>()
    const res = await form('/identity/connect/token', {
      grant_type: 'client_credentials',
      client_id: `user.${user?.uuid}`,
      client_secret: key.body.apiKey,
      scope: 'api',
      deviceIdentifier: 'cli',
      deviceType: '8',
      deviceName: 'cli',
    })
    expect(res.status).toBe(200)
  })
})

describe('remember token', () => {
  it('is issued on remember=1 and bypasses the challenge for that device only', async () => {
    clock.now = () => FIXED
    const email = 'tf-remember@example.com'
    const s = await createSession(email)
    const { key } = await enableTotp(s)
    clock.now = () => FIXED + 30_000
    const code = (await totpAt(key, clock.now())) as string
    const ok = await challenge(email, {
      twoFactorProvider: '0',
      twoFactorToken: code,
      twoFactorRemember: '1',
    })
    expect(ok.status).toBe(200)
    const remember = ok.body.TwoFactorToken as string
    expect(typeof remember).toBe('string')

    const again = await challenge(email, { twoFactorProvider: '5', twoFactorToken: remember })
    expect(again.status).toBe(200)
    expect(again.body.TwoFactorToken).toBeUndefined()

    const otherDevice = await challenge(email, {
      twoFactorProvider: '5',
      twoFactorToken: remember,
      deviceIdentifier: 'device-2',
    })
    expect(otherDevice.status).toBe(400)
    expect(otherDevice.body.TwoFactorProviders2).toBeDefined()

    const forged = await challenge(email, { twoFactorProvider: '5', twoFactorToken: 'nope' })
    expect(forged.status).toBe(400)
    expect(forged.body.error_description).toBe('Two factor required.')
  })

  it('does not issue a token without remember=1 and expires after 30 days', async () => {
    clock.now = () => FIXED
    const email = 'tf-remember2@example.com'
    const s = await createSession(email)
    const { key } = await enableTotp(s)
    clock.now = () => FIXED + 30_000
    const plain = await challenge(email, {
      twoFactorProvider: '0',
      twoFactorToken: (await totpAt(key, clock.now())) as string,
    })
    expect(plain.body.TwoFactorToken).toBeUndefined()

    clock.now = () => FIXED + 60_000
    const withRemember = await challenge(email, {
      twoFactorProvider: '0',
      twoFactorToken: (await totpAt(key, clock.now())) as string,
      twoFactorRemember: '1',
    })
    const token = withRemember.body.TwoFactorToken as string
    clock.now = () => FIXED + 31 * 24 * 3600 * 1000
    const expired = await challenge(email, { twoFactorProvider: '5', twoFactorToken: token })
    expect(expired.status).toBe(400)
  })

  it('is revoked when the provider is disabled', async () => {
    clock.now = () => FIXED
    const email = 'tf-remember3@example.com'
    const s = await createSession(email)
    const { key } = await enableTotp(s)
    clock.now = () => FIXED + 30_000
    const ok = await challenge(email, {
      twoFactorProvider: '0',
      twoFactorToken: (await totpAt(key, clock.now())) as string,
      twoFactorRemember: '1',
    })
    const token = ok.body.TwoFactorToken as string
    await call(s, '/api/two-factor/disable', { type: 0, masterPasswordHash: PW })
    const row = await env.DB.prepare('select twofactor_remember r from devices').first<{
      r: string | null
    }>()
    expect(row?.r ?? null).toBeNull()
    // Re-enable: the old token must not bypass the new challenge.
    await enableTotp(s, key)
    const res = await challenge(email, { twoFactorProvider: '5', twoFactorToken: token })
    expect(res.status).toBe(400)
  })
})

describe('recovery code', () => {
  it('returns a stable code, disables every provider and rotates the code', async () => {
    clock.now = () => FIXED
    const email = 'tf-recover@example.com'
    const s = await createSession(email)
    await enableTotp(s)
    const got = await call(s, '/api/two-factor/get-recover', { masterPasswordHash: PW })
    expect(got.status).toBe(200)
    expect(got.body.code).toMatch(/^[A-Z2-7]{32}$/)
    const again = await call(s, '/api/two-factor/get-recover', { masterPasswordHash: PW })
    expect(again.body.code).toBe(got.body.code)

    const wrongCode = await json('/api/two-factor/recover', {
      email,
      masterPasswordHash: PW,
      recoveryCode: 'A'.repeat(32),
    })
    expect(wrongCode.status).toBe(400)
    const wrongPw = await json('/api/two-factor/recover', {
      email,
      masterPasswordHash: 'nope',
      recoveryCode: got.body.code,
    })
    expect(wrongPw.status).toBe(400)
    expect((await challenge(email)).status).toBe(400)

    const ok = await json('/identity/accounts/two-factor/recover', {
      email: email.toUpperCase(),
      masterPasswordHash: PW,
      recoveryCode: `${(got.body.code as string).toLowerCase()}`,
    })
    expect(ok.status).toBe(200)

    expect((await login(email)).status).toBe(200)
    expect((await call(s, '/api/two-factor', undefined, 'GET')).body.data).toEqual([])
    const rotated = await call(s, '/api/two-factor/get-recover', { masterPasswordHash: PW })
    expect(rotated.body.code).not.toBe(got.body.code)

    const reuse = await json('/api/two-factor/recover', {
      email,
      masterPasswordHash: PW,
      recoveryCode: got.body.code,
    })
    expect(reuse.status).toBe(400)
  })

  it('does not reveal whether the account exists', async () => {
    const res = await json('/api/two-factor/recover', {
      email: 'ghost-recover@example.com',
      masterPasswordHash: PW,
      recoveryCode: 'A'.repeat(32),
    })
    expect(res.status).toBe(400)
    expect(((await res.json()) as any).message).toBe('Recovery code is incorrect. Try again.')
  })
})

describe('email provider', () => {
  it('refuses setup without a mail transport', async () => {
    const s = await createSession('tf-nomail@example.com')
    const res = await call(s, '/api/two-factor/send-email', {
      email: 'tf-nomail@example.com',
      masterPasswordHash: PW,
    })
    expect(res.status).toBe(400)
  })

  async function setupEmail(email: string, mail = mailbox()) {
    const s = await createSession(email)
    const sendRes = await withEnv(mail.overrides, '/api/two-factor/send-email', {
      method: 'POST',
      headers: { Authorization: `Bearer ${s.access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, masterPasswordHash: PW }),
    })
    expect(sendRes.status).toBe(200)
    const code = codeFrom(mail.sent.at(-1)?.text ?? '')
    return { s, mail, code }
  }

  const sendLogin = (mail: ReturnType<typeof mailbox>, email: string, extra: object = {}) =>
    withEnv(mail.overrides, '/api/two-factor/send-email-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, masterPasswordHash: PW, ...extra }),
    })

  it('verifies the setup code, then challenges and logs in with a mailed code', async () => {
    clock.now = () => FIXED
    const email = 'tf-email@example.com'
    const { s, mail, code } = await setupEmail(email)
    expect(mail.sent[0]?.to).toBe(email)
    expect(code).toMatch(/^\d{6}$/)
    expect((await call(s, '/api/two-factor', undefined, 'GET')).body.data).toEqual([])

    const wrong = await call(
      s,
      '/api/two-factor/email',
      { email, token: '000000', masterPasswordHash: PW },
      'PUT',
    )
    expect(wrong.status).toBe(400)
    const put = await call(
      s,
      '/api/two-factor/email',
      { email, token: code, masterPasswordHash: PW },
      'PUT',
    )
    expect(put.status).toBe(200)
    expect(put.body).toEqual({ email: { enabled: true, email } })
    const reuse = await call(
      s,
      '/api/two-factor/email',
      { email, token: code, masterPasswordHash: PW },
      'PUT',
    )
    expect(reuse.status).toBe(400)

    const first = await challenge(email)
    expect(first.body.TwoFactorProviders).toEqual(['1'])
    expect(first.body.TwoFactorProviders2).toEqual({ '1': { Email: 't***@example.com' } })

    const sent = await sendLogin(mail, email)
    expect(sent.status).toBe(200)
    expect(mail.sent).toHaveLength(2)
    const loginCode = codeFrom(mail.sent[1]?.text ?? '')
    const ok = await challenge(email, { twoFactorProvider: '1', twoFactorToken: loginCode })
    expect(ok.status).toBe(200)
    // Single use.
    const again = await challenge(email, { twoFactorProvider: '1', twoFactorToken: loginCode })
    expect(again.status).toBe(400)

    const info = await call(s, '/api/two-factor/get-email', { masterPasswordHash: PW })
    expect(info.body.email).toEqual({ enabled: true, email })
  })

  it('expires codes after ten minutes', async () => {
    clock.now = () => FIXED
    const email = 'tf-email-exp@example.com'
    const { s, mail, code } = await setupEmail(email)
    await call(s, '/api/two-factor/email', { email, token: code, masterPasswordHash: PW }, 'PUT')
    await sendLogin(mail, email)
    const loginCode = codeFrom(mail.sent[1]?.text ?? '')
    clock.now = () => FIXED + 10 * 60 * 1000 + 1
    const res = await challenge(email, { twoFactorProvider: '1', twoFactorToken: loginCode })
    expect(res.status).toBe(400)
    expect(res.body.access_token).toBeUndefined()
  })

  it('locks a code after five wrong guesses', async () => {
    clock.now = () => FIXED
    const email = 'tf-email-lock@example.com'
    const { s, mail, code } = await setupEmail(email)
    await call(s, '/api/two-factor/email', { email, token: code, masterPasswordHash: PW }, 'PUT')
    await sendLogin(mail, email)
    const loginCode = codeFrom(mail.sent[1]?.text ?? '')
    const wrong = loginCode === '111111' ? '222222' : '111111'
    for (let i = 0; i < 5; i++) {
      const r = await challenge(email, { twoFactorProvider: '1', twoFactorToken: wrong })
      expect(r.status).toBe(400)
    }
    const locked = await challenge(email, { twoFactorProvider: '1', twoFactorToken: loginCode })
    expect(locked.status).toBe(400)
    // A new code resets the counter.
    await sendLogin(mail, email)
    const fresh = codeFrom(mail.sent[2]?.text ?? '')
    const ok = await challenge(email, { twoFactorProvider: '1', twoFactorToken: fresh })
    expect(ok.status).toBe(200)
  })

  it('send-email-login needs the password and an enabled provider', async () => {
    const mail = mailbox()
    await createSession('tf-email-guard@example.com')
    const noProvider = await sendLogin(mail, 'tf-email-guard@example.com')
    expect(noProvider.status).toBe(400)
    const badPw = await sendLogin(mail, 'tf-email-guard@example.com', {
      masterPasswordHash: 'nope',
    })
    expect(badPw.status).toBe(400)
    const ghost = await sendLogin(mail, 'ghost-guard@example.com')
    expect(ghost.status).toBe(400)
    expect(mail.sent).toHaveLength(0)
  })

  it('disables with a verification token', async () => {
    clock.now = () => FIXED
    const email = 'tf-email-off@example.com'
    const { s, code } = await setupEmail(email)
    await call(s, '/api/two-factor/email', { email, token: code, masterPasswordHash: PW }, 'PUT')
    const info = await call(s, '/api/two-factor/get-email', { masterPasswordHash: PW })
    const del = await call(
      s,
      '/api/two-factor/email',
      { userVerificationToken: info.body.userVerificationToken },
      'DELETE',
    )
    expect(del.status).toBe(200)
    expect((await login(email)).status).toBe(200)
  })
})

describe('webauthn', () => {
  async function registerKey(s: Session, slot: number, alg: -7 | -257, name = 'Key') {
    const auth = await newAuthenticator(alg)
    const ch = await call(s, '/api/two-factor/get-webauthn-challenge', { masterPasswordHash: PW })
    expect(ch.status).toBe(200)
    const options = ch.body.options
    const deviceResponse = await register(auth, options.challenge, RP_ID, ORIGIN)
    const put = await call(
      s,
      '/api/two-factor/webauthn',
      { deviceResponse, name, id: slot, masterPasswordHash: PW },
      'PUT',
    )
    return { auth, options, put, deviceResponse }
  }

  const loginAssertion = async (
    email: string,
    auth: Awaited<ReturnType<typeof newAuthenticator>>,
    opts: Parameters<typeof assertion>[4] = {},
    ch?: string,
  ) => {
    const c = ch ?? ((await challenge(email)).body.TwoFactorProviders2['7'].challenge as string)
    const response = await assertion(auth, c, RP_ID, ORIGIN, opts)
    return challenge(email, { twoFactorProvider: '7', twoFactorToken: JSON.stringify(response) })
  }

  it('registers an ES256 key and logs in with an assertion', async () => {
    const email = 'tf-wa@example.com'
    const s = await createSession(email)
    const { options, put, auth } = await registerKey(s, 1, -7, 'Laptop')
    expect(options).toMatchObject({
      rp: { id: RP_ID },
      attestation: 'none',
      user: { name: email },
    })
    expect(options.pubKeyCredParams.map((p: any) => p.alg)).toEqual([-7, -257])
    expect(put.status).toBe(200)
    expect(put.body.webAuthn).toEqual({
      enabled: true,
      keys: [{ name: 'Laptop', id: 1, migrated: false }],
    })

    const list = await call(s, '/api/two-factor', undefined, 'GET')
    expect(list.body.data).toEqual([{ enabled: true, type: 7, object: 'twoFactorProvider' }])

    const first = await challenge(email)
    expect(first.body.TwoFactorProviders).toEqual(['7'])
    const opts = first.body.TwoFactorProviders2['7']
    expect(opts).toMatchObject({
      rpId: RP_ID,
      allowCredentials: [{ type: 'public-key' }],
    })
    expect(opts.challenge).toBeTruthy()

    const ok = await loginAssertion(email, auth, {}, opts.challenge)
    expect(ok.status).toBe(200)
    expect(ok.body.access_token).toBeTruthy()

    // The same challenge cannot be used again, even with a fresh counter.
    const replay = await loginAssertion(email, auth, {}, opts.challenge)
    expect(replay.status).toBe(400)
  })

  it('accepts RS256 keys and supports several keys', async () => {
    const email = 'tf-wa-rs@example.com'
    const s = await createSession(email)
    const a = await registerKey(s, 1, -7, 'ec')
    const b = await registerKey(s, 2, -257, 'rsa')
    expect(b.put.body.webAuthn.keys).toHaveLength(2)
    const opts = (await challenge(email)).body.TwoFactorProviders2['7']
    expect(opts.allowCredentials).toHaveLength(2)
    expect((await loginAssertion(email, b.auth)).status).toBe(200)
    expect((await loginAssertion(email, a.auth)).status).toBe(200)
  })

  it('rejects bad assertions', async () => {
    const email = 'tf-wa-bad@example.com'
    const s = await createSession(email)
    const { auth } = await registerKey(s, 1, -7)
    const other = await newAuthenticator(-7)
    other.credentialId = auth.credentialId

    expect((await loginAssertion(email, other)).status).toBe(400)
    expect((await loginAssertion(email, auth, { rpId: 'evil.example.org' })).status).toBe(400)
    expect((await loginAssertion(email, auth, { origin: 'https://evil.example.org' })).status).toBe(
      400,
    )
    expect((await loginAssertion(email, auth, { flags: 0 })).status).toBe(400)
    expect((await loginAssertion(email, auth, {}, 'A'.repeat(75))).status).toBe(400)
    const junk = await challenge(email, { twoFactorProvider: '7', twoFactorToken: 'not json' })
    expect(junk.status).toBe(400)

    // Counter must advance: a good login, then a replayed lower counter fails.
    expect((await loginAssertion(email, auth, { signCount: 10 })).status).toBe(200)
    expect((await loginAssertion(email, auth, { signCount: 10 })).status).toBe(400)
    expect((await loginAssertion(email, auth, { signCount: 5 })).status).toBe(400)
    expect((await loginAssertion(email, auth, { signCount: 11 })).status).toBe(200)
  })

  it('rejects registrations with a bad challenge, origin, rp or credential', async () => {
    const s = await createSession('tf-wa-reg@example.com')
    const ch = await call(s, '/api/two-factor/get-webauthn-challenge', { masterPasswordHash: PW })
    const reg = async (challengeValue: string, o: Parameters<typeof register>[4] = {}) =>
      call(
        s,
        '/api/two-factor/webauthn',
        {
          deviceResponse: await register(
            await newAuthenticator(-7),
            challengeValue,
            RP_ID,
            ORIGIN,
            o,
          ),
          name: 'x',
          id: 1,
          masterPasswordHash: PW,
        },
        'PUT',
      )
    const c = ch.body.options.challenge
    expect((await reg('A'.repeat(75))).status).toBe(400)
    expect((await reg(c, { origin: 'https://evil.example.org' })).status).toBe(400)
    expect((await reg(c, { rpId: 'evil.example.org' })).status).toBe(400)
    expect((await reg(c, { flags: 0x40 })).status).toBe(400)
    // A challenge minted for another user is rejected.
    const other = await createSession('tf-wa-reg2@example.com')
    const foreign = await call(other, '/api/two-factor/get-webauthn-challenge', {
      masterPasswordHash: PW,
    })
    expect((await reg(foreign.body.options.challenge)).status).toBe(400)
    const malformed = await call(
      s,
      '/api/two-factor/webauthn',
      { deviceResponse: { id: 'x', response: {} }, name: 'x', id: 1, masterPasswordHash: PW },
      'PUT',
    )
    expect(malformed.status).toBe(400)
    expect((await call(s, '/api/two-factor', undefined, 'GET')).body.data).toEqual([])
  })

  it('rejects an expired challenge and a duplicate credential', async () => {
    clock.now = () => FIXED
    const s = await createSession('tf-wa-exp@example.com')
    const ch = await call(s, '/api/two-factor/get-webauthn-challenge', { masterPasswordHash: PW })
    clock.now = () => FIXED + 6 * 60 * 1000
    const auth = await newAuthenticator(-7)
    const late = await call(
      s,
      '/api/two-factor/webauthn',
      {
        deviceResponse: await register(auth, ch.body.options.challenge, RP_ID, ORIGIN),
        name: 'late',
        id: 1,
        masterPasswordHash: PW,
      },
      'PUT',
    )
    expect(late.status).toBe(400)

    clock.now = () => FIXED
    const first = await registerKey(s, 1, -7)
    expect(first.put.status).toBe(200)
    const ch2 = await call(s, '/api/two-factor/get-webauthn-challenge', { masterPasswordHash: PW })
    expect(ch2.body.options.excludeCredentials).toHaveLength(1)
    const dup = await call(
      s,
      '/api/two-factor/webauthn',
      {
        deviceResponse: await register(first.auth, ch2.body.options.challenge, RP_ID, ORIGIN),
        name: 'dup',
        id: 2,
        masterPasswordHash: PW,
      },
      'PUT',
    )
    expect(dup.status).toBe(400)
  })

  it('removes single keys and all keys', async () => {
    const email = 'tf-wa-del@example.com'
    const s = await createSession(email)
    await registerKey(s, 1, -7, 'a')
    await registerKey(s, 2, -257, 'b')
    const got = await call(s, '/api/two-factor/get-webauthn', { masterPasswordHash: PW })
    expect(got.body.webAuthn.keys).toHaveLength(2)
    const del1 = await call(
      s,
      '/api/two-factor/webauthn',
      { id: 1, masterPasswordHash: PW },
      'DELETE',
    )
    expect(del1.body.webAuthn.keys).toEqual([{ name: 'b', id: 2, migrated: false }])
    expect(
      (await call(s, '/api/two-factor/webauthn', { id: 9, masterPasswordHash: PW }, 'DELETE'))
        .status,
    ).toBe(400)
    const del2 = await call(
      s,
      '/api/two-factor/webauthn',
      { id: 2, masterPasswordHash: PW },
      'DELETE',
    )
    expect(del2.body.webAuthn).toEqual({ enabled: false, keys: [] })
    expect((await login(email)).status).toBe(200)

    await registerKey(s, 3, -7)
    const all = await call(s, '/api/two-factor/webauthn/all', { masterPasswordHash: PW }, 'DELETE')
    expect(all.status).toBe(200)
    expect((await login(email)).status).toBe(200)
  })
})

describe('disable and unsupported providers', () => {
  it('disables a provider through the generic endpoint', async () => {
    clock.now = () => FIXED
    const email = 'tf-disable@example.com'
    const s = await createSession(email)
    await enableTotp(s)
    const bad = await call(s, '/api/two-factor/disable', { type: 0, masterPasswordHash: 'nope' })
    expect(bad.status).toBe(400)
    const res = await call(s, '/api/two-factor/disable', { type: 0, masterPasswordHash: PW })
    expect(res.body).toEqual({ enabled: false, type: 0, object: 'twoFactorProvider' })
    expect((await login(email)).status).toBe(200)
  })

  it('answers Duo and YubiKey with a clear 400', async () => {
    const s = await createSession('tf-unsupported@example.com')
    for (const [path, method] of [
      ['/api/two-factor/get-duo', 'POST'],
      ['/api/two-factor/get-yubikey', 'POST'],
      ['/api/two-factor/duo', 'PUT'],
      ['/api/two-factor/yubikey', 'PUT'],
      ['/api/two-factor/yubikey', 'DELETE'],
    ] as const) {
      const res = await call(s, path, { masterPasswordHash: PW }, method)
      expect(res.status).toBe(400)
      expect(res.body.message).toContain('not supported')
    }
  })
})

describe('rate limiting', () => {
  const limiter = (allowed: number) => {
    const keys: string[] = []
    return {
      keys,
      limit: async ({ key }: { key: string }) => {
        keys.push(key)
        return { success: keys.length <= allowed }
      },
    }
  }

  it('throttles management, recovery and email endpoints', async () => {
    for (const path of [
      '/api/two-factor/recover',
      '/api/two-factor/send-email-login',
      '/api/two-factor/get-authenticator',
    ]) {
      const res = await withEnv({ LOGIN_LIMITER: limiter(0) }, path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      })
      expect(res.status).toBe(429)
    }
  })

  it('throttles second factor attempts per user at the token endpoint', async () => {
    clock.now = () => FIXED
    const email = 'tf-limit@example.com'
    const s = await createSession(email)
    await enableTotp(s)
    // Allow the first-step limiter (1 call) but trip the per-user 2FA limiter.
    const l = limiter(1)
    const res = await withEnv({ LOGIN_LIMITER: l }, '/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        username: email,
        password: PW,
        deviceIdentifier: 'device-1',
        deviceType: '9',
        twoFactorProvider: '0',
        twoFactorToken: '123456',
      }).toString(),
    })
    expect(res.status).toBe(429)
    expect(l.keys.some((k) => k.startsWith('two-factor:'))).toBe(true)
  })
})

describe('security hardening', () => {
  const sqlOne = (q: string, ...b: unknown[]) =>
    env.DB.prepare(q)
      .bind(...b)
      .run()

  it('recover refuses a null stored code and malformed input', async () => {
    clock.now = () => FIXED
    const email = 'tf-sec-null@example.com'
    const s = await createSession(email)
    await enableTotp(s)
    await sqlOne('update users set totp_recover = null where email = ?', email)
    for (const code of ['\u0000', '', ' ', 'A'.repeat(31), `${'A'.repeat(31)}1`, 'a'.repeat(33)]) {
      const res = await json('/api/two-factor/recover', {
        email,
        masterPasswordHash: PW,
        recoveryCode: code || ' ',
      })
      expect(res.status).toBe(400)
    }
    const rows = await env.DB.prepare('select count(*) n from twofactor').first<{ n: number }>()
    expect(rows?.n).toBeGreaterThan(0)
    expect((await challenge(email)).status).toBe(400)
  })

  it('fails closed for unsupported providers and lets the recovery code (provider 8) in', async () => {
    const email = 'tf-sec-duo@example.com'
    const s = await createSession(email)
    const user = await env.DB.prepare('select uuid, totp_recover r from users where email = ?')
      .bind(email)
      .first<{ uuid: string }>()
    await sqlOne(
      'insert into twofactor (uuid, user_uuid, atype, enabled, data, last_used) values (?, ?, 3, 1, ?, 0)',
      crypto.randomUUID(),
      user?.uuid,
      '{}',
    )
    const first = await challenge(email)
    expect(first.status).toBe(400)
    expect(first.body.access_token).toBeUndefined()
    expect(first.body.TwoFactorProviders2).toBeUndefined()
    const guess = await challenge(email, { twoFactorProvider: '3', twoFactorToken: 'cccccc' })
    expect(guess.status).toBe(400)
    expect(guess.body.access_token).toBeUndefined()

    const code = (await call(s, '/api/two-factor/get-recover', { masterPasswordHash: PW })).body
      .code
    const bad = await challenge(email, { twoFactorProvider: '8', twoFactorToken: 'A'.repeat(32) })
    expect(bad.status).toBe(400)
    const ok = await challenge(email, { twoFactorProvider: '8', twoFactorToken: code })
    expect(ok.status).toBe(200)
    expect(ok.body.access_token).toBeTruthy()
    // Spent: all providers gone, code rotated, cannot be reused.
    expect((await login(email)).status).toBe(200)
    const left = await env.DB.prepare(
      'select count(*) n from twofactor where atype = 3 and enabled = 1',
    ).first<{ n: number }>()
    expect(left?.n).toBe(0)
    const rotated = (await call(s, '/api/two-factor/get-recover', { masterPasswordHash: PW })).body
      .code
    expect(rotated).not.toBe(code)
  })

  it('provider 8 works for accounts with a supported provider and rejects reuse', async () => {
    clock.now = () => FIXED
    const email = 'tf-sec-p8@example.com'
    const s = await createSession(email)
    await enableTotp(s)
    const code = (await call(s, '/api/two-factor/get-recover', { masterPasswordHash: PW })).body
      .code
    const ok = await challenge(email, { twoFactorProvider: '8', twoFactorToken: code })
    expect(ok.status).toBe(200)
    const newCode = (await call(s, '/api/two-factor/get-recover', { masterPasswordHash: PW })).body
      .code
    expect(newCode).not.toBe(code)
    // Re-enable 2FA: the spent code must not work as provider 8 any more.
    clock.now = () => FIXED + 120_000
    await enableTotp(s)
    const reuse = await challenge(email, { twoFactorProvider: '8', twoFactorToken: code })
    expect(reuse.status).toBe(400)
    expect(reuse.body.access_token).toBeUndefined()
  })

  it('binds verification tokens to the security stamp', async () => {
    const email = 'tf-sec-stamp@example.com'
    const s = await createSession(email)
    const tok = (await call(s, '/api/two-factor/get-authenticator', { masterPasswordHash: PW }))
      .body.userVerificationToken
    await sqlOne('update users set security_stamp = ? where email = ?', crypto.randomUUID(), email)
    const fresh = (await (await login(email)).json()) as Session
    const res = await call(fresh, '/api/two-factor/get-authenticator', {
      userVerificationToken: tok,
    })
    expect(res.status).toBe(400)
  })

  it('caps email attempts under parallel guesses', async () => {
    clock.now = () => FIXED
    const email = 'tf-sec-par@example.com'
    const mail = mailbox()
    const s = await createSession(email)
    await withEnv(mail.overrides, '/api/two-factor/send-email', {
      method: 'POST',
      headers: { Authorization: `Bearer ${s.access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, masterPasswordHash: PW }),
    })
    const code = codeFrom(mail.sent[0]?.text ?? '')
    const wrong = code === '123456' ? '654321' : '123456'
    await Promise.all(
      Array.from({ length: 12 }, () =>
        call(s, '/api/two-factor/email', { email, token: wrong, masterPasswordHash: PW }, 'PUT'),
      ),
    )
    const row = await env.DB.prepare(
      "select json_extract(data, '$.attempts') a from twofactor where atype = 1",
    ).first<{ a: number }>()
    expect(row?.a).toBeLessThanOrEqual(5)
    const good = await call(
      s,
      '/api/two-factor/email',
      { email, token: code, masterPasswordHash: PW },
      'PUT',
    )
    expect(good.status).toBe(400)
  })

  it('falls back to a D1 window when the limiter binding is missing', async () => {
    // Seed the fixed-window counters directly (previous, current and next window) so the
    // outcome does not depend on request volume or on where a window boundary falls.
    const seed = async (key: string) => {
      const base = Math.floor(Date.now() / 60_000) * 60_000
      for (const w of [base - 60_000, base, base + 60_000]) {
        await env.DB.prepare(
          'insert or replace into admin_rate_limits (key, window_start, count) values (?, ?, 1000)',
        )
          .bind(key, w)
          .run()
      }
    }
    const recover = (ip: string) =>
      withEnv({}, '/api/two-factor/recover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
        body: JSON.stringify({
          email: 'x@example.com',
          masterPasswordHash: 'a',
          recoveryCode: 'b',
        }),
      })
    await seed('two-factor-manage:198.51.100.77')
    expect((await recover('198.51.100.77')).status).toBe(429)
    expect((await recover('198.51.100.78')).status).toBe(400)

    clock.now = () => FIXED
    const email = 'tf-sec-d1@example.com'
    const s = await createSession(email)
    await enableTotp(s)
    const user = await env.DB.prepare('select uuid from users where email = ?')
      .bind(email)
      .first<{ uuid: string }>()
    const attempt = () => login(email, PW, { twoFactorProvider: '0', twoFactorToken: '000000' })
    expect((await attempt()).status).toBe(400)
    await seed(`two-factor:${user?.uuid}`)
    expect((await attempt()).status).toBe(429)
  })
})
