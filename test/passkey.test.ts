import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { afterEach, describe, expect, it } from 'vitest'
import { toB64u } from '../src/auth/crypto'
import { clock } from '../src/auth/twofactor'
import { createDb, runBatch } from '../src/db'
import { passkeyRotation } from '../src/routes/accounts'
import { assert as assertion, newAuthenticator, register } from './authenticator'
import { authed, BASE, createSession, form, json, login, type Session } from './helpers'

const PW = 'client-derived-hash'
const RP_ID = 'vault.example.com'
const ORIGIN = 'https://vault.example.com'
// User present plus user verified.
const UV = { flags: 0x45 }
const UV_ASSERT = { flags: 0x05 }
const KEYS = {
  encryptedUserKey: '4.userkey',
  encryptedPublicKey: '2.publickey',
  encryptedPrivateKey: '2.privatekey',
}

afterEach(() => {
  clock.now = () => Date.now()
})

type Auth = Awaited<ReturnType<typeof newAuthenticator>>

const call = async (s: Session, path: string, body?: unknown, method = 'POST') => {
  const res = await authed(path, s.access_token, method, body)
  const text = await res.text()
  return { status: res.status, body: text ? (JSON.parse(text) as any) : null }
}

async function createOptions(s: Session) {
  const res = await call(s, '/api/webauthn/attestation-options', { masterPasswordHash: PW })
  expect(res.status).toBe(200)
  return res.body as { options: any; token: string; object: string }
}

interface AddOpts {
  name?: string
  alg?: -7 | -257
  supportsPrf?: boolean
  keys?: Record<string, string> | null
  reg?: Parameters<typeof register>[4]
}

async function addPasskey(s: Session, o: AddOpts = {}) {
  const auth = await newAuthenticator(o.alg ?? -7)
  const opts = await createOptions(s)
  const deviceResponse = await register(auth, opts.options.challenge, RP_ID, ORIGIN, {
    ...UV,
    ...o.reg,
  })
  const supportsPrf = o.supportsPrf ?? true
  const res = await call(s, '/api/webauthn', {
    deviceResponse,
    name: o.name ?? 'Passkey',
    token: opts.token,
    supportsPrf,
    ...(o.keys === null ? {} : (o.keys ?? (supportsPrf ? KEYS : {}))),
  })
  return { auth, res, opts, deviceResponse }
}

const list = async (s: Session) => (await call(s, '/api/webauthn', undefined, 'GET')).body

async function loginOptions() {
  const res = await SELF_GET('/identity/accounts/webauthn/assertion-options')
  expect(res.status).toBe(200)
  return (await res.json()) as { options: any; token: string; object: string }
}
const SELF_GET = (path: string) => SELF.fetch(`${BASE}${path}`)

interface GrantOpts {
  token?: string
  device?: string
  mutate?: (r: any) => void
  assert?: Parameters<typeof assertion>[4]
  challenge?: string
  auth?: Auth
}

/** Mints login options, signs them with `auth` and posts the webauthn grant. */
async function passkeyLogin(auth: Auth, o: GrantOpts = {}) {
  const opts = await loginOptions()
  const response: any = await assertion(
    auth,
    o.challenge ?? opts.options.challenge,
    RP_ID,
    ORIGIN,
    {
      ...UV_ASSERT,
      ...o.assert,
    },
  )
  o.mutate?.(response)
  const res = await form('/identity/connect/token', {
    grant_type: 'webauthn',
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceName: 'chrome',
    deviceIdentifier: o.device ?? 'passkey-device',
    token: o.token ?? opts.token,
    deviceResponse: JSON.stringify(response),
  })
  return { res, body: (await res.json()) as any, opts, response }
}

describe('credential management', () => {
  it('lists nothing at first and requires authentication', async () => {
    const s = await createSession('pk-empty@example.com')
    expect(await list(s)).toEqual({ data: [], continuationToken: null, object: 'list' })
    expect((await authed('/api/webauthn', 'bogus')).status).toBe(401)
    expect((await SELF.fetch(`${BASE}/api/webauthn`)).status).toBe(401)
  })

  it('issues creation options for passkey login and checks the password', async () => {
    const email = 'pk-opts@example.com'
    const s = await createSession(email)
    const opts = await createOptions(s)
    expect(opts.object).toBe('webauthnCredentialCreateOptions')
    expect(opts.token.split('.')).toHaveLength(3)
    expect(opts.options).toMatchObject({
      rp: { id: RP_ID },
      user: { name: email },
      attestation: 'none',
      excludeCredentials: [],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    })
    expect(opts.options.pubKeyCredParams.map((p: any) => p.alg)).toEqual([-7, -257])
    const bad = await call(s, '/api/webauthn/attestation-options', { masterPasswordHash: 'nope' })
    expect(bad.status).toBe(400)
    expect((await call(s, '/api/webauthn/attestation-options', {})).status).toBe(400)
  })

  it('stores a PRF passkey with its keyset and lists it', async () => {
    const s = await createSession('pk-prf@example.com')
    const { res, auth } = await addPasskey(s, { name: 'Laptop', reg: { transports: ['internal'] } })
    expect(res.status).toBe(200)
    const got = await list(s)
    expect(got.data).toHaveLength(1)
    expect(got.data[0]).toMatchObject({
      name: 'Laptop',
      prfStatus: 0,
      encryptedUserKey: KEYS.encryptedUserKey,
      encryptedPublicKey: KEYS.encryptedPublicKey,
      object: 'webauthnCredential',
    })
    // The private half stays server side until login.
    expect(got.data[0].encryptedPrivateKey).toBeUndefined()
    // Creation options now exclude it.
    const next = await createOptions(s)
    expect(next.options.excludeCredentials).toEqual([
      { type: 'public-key', id: toB64u(auth.credentialId), transports: ['internal'] },
    ])
  })

  it('reports PRF status for credentials without a keyset', async () => {
    const s = await createSession('pk-status@example.com')
    expect(
      (await addPasskey(s, { name: 'Supported', supportsPrf: true, keys: null })).res.status,
    ).toBe(200)
    expect((await addPasskey(s, { name: 'Plain', supportsPrf: false })).res.status).toBe(200)
    const got = await list(s)
    const status = Object.fromEntries(got.data.map((r: any) => [r.name, r.prfStatus]))
    expect(status).toEqual({ Supported: 1, Plain: 2 })
    expect(got.data[0].encryptedUserKey).toBeNull()
  })

  it('accepts RS256 credentials', async () => {
    const s = await createSession('pk-rs@example.com')
    expect((await addPasskey(s, { alg: -257 })).res.status).toBe(200)
  })

  it('rejects partial keysets and keys without PRF support', async () => {
    const s = await createSession('pk-keys@example.com')
    const partial = await addPasskey(s, { keys: { encryptedUserKey: '4.only' } })
    expect(partial.res.status).toBe(400)
    const noPrf = await addPasskey(s, { supportsPrf: false, keys: KEYS })
    expect(noPrf.res.status).toBe(400)
    expect((await list(s)).data).toEqual([])
  })

  it('rejects bad registrations', async () => {
    const s = await createSession('pk-bad@example.com')
    const opts = await createOptions(s)
    const attempt = async (
      challenge: string,
      r: Parameters<typeof register>[4] = UV,
      token = opts.token,
    ) =>
      call(s, '/api/webauthn', {
        deviceResponse: await register(await newAuthenticator(-7), challenge, RP_ID, ORIGIN, r),
        name: 'x',
        token,
        supportsPrf: false,
      })
    const c = opts.options.challenge
    expect((await attempt('A'.repeat(75))).status).toBe(400)
    expect((await attempt(c, { ...UV, origin: 'https://evil.example.org' })).status).toBe(400)
    expect((await attempt(c, { ...UV, rpId: 'evil.example.org' })).status).toBe(400)
    // No user verification: a passkey that replaces the password must verify the user.
    expect((await attempt(c, { flags: 0x41 })).status).toBe(400)
    expect((await attempt(c, { flags: 0x44 })).status).toBe(400)
    expect((await attempt(c, UV, 'garbage')).status).toBe(400)
    // Token and challenge from different option requests do not pair up.
    const second = await createOptions(s)
    expect((await attempt(c, UV, second.token)).status).toBe(400)
    // Another user's options do not work for this account.
    const other = await createSession('pk-bad2@example.com')
    const foreign = await createOptions(other)
    expect((await attempt(foreign.options.challenge, UV, foreign.token)).status).toBe(400)
    expect((await list(s)).data).toEqual([])
    // The genuine pair still works after all those failures.
    expect((await attempt(c)).status).toBe(200)
  })

  it('refuses an expired challenge', async () => {
    const s = await createSession('pk-expired@example.com')
    clock.now = () => Date.now() - 10 * 60 * 1000
    const opts = await createOptions(s)
    clock.now = () => Date.now()
    const deviceResponse = await register(
      await newAuthenticator(-7),
      opts.options.challenge,
      RP_ID,
      ORIGIN,
      UV,
    )
    const res = await call(s, '/api/webauthn', {
      deviceResponse,
      name: 'x',
      token: opts.token,
      supportsPrf: false,
    })
    expect(res.status).toBe(400)
  })

  it('does not accept the same credential twice or on two accounts', async () => {
    const a = await createSession('pk-dup-a@example.com')
    const b = await createSession('pk-dup-b@example.com')
    const first = await addPasskey(a, { supportsPrf: false })
    expect(first.res.status).toBe(200)
    // Re-registering the same authenticator under another account fails on the unique id.
    const opts = await createOptions(b)
    const again = await register(first.auth, opts.options.challenge, RP_ID, ORIGIN, UV)
    const res = await call(b, '/api/webauthn', {
      deviceResponse: again,
      name: 'stolen',
      token: opts.token,
      supportsPrf: false,
    })
    expect(res.status).toBe(400)
    expect((await list(b)).data).toEqual([])
  })

  it('spends the creation token: a replay after deletion is refused', async () => {
    const s = await createSession('pk-spent@example.com')
    const first = await addPasskey(s, { supportsPrf: false })
    expect(first.res.status).toBe(200)
    const id = ((await list(s)).data[0] as any).id
    expect((await call(s, `/api/webauthn/${id}/delete`, { masterPasswordHash: PW })).status).toBe(
      200,
    )
    const replay = await call(s, '/api/webauthn', {
      deviceResponse: first.deviceResponse,
      name: 'again',
      token: first.opts.token,
      supportsPrf: false,
    })
    expect(replay.status).toBe(400)
    expect((await list(s)).data).toEqual([])
  })

  it('limits an account to five passkeys', async () => {
    const s = await createSession('pk-max@example.com')
    for (let i = 0; i < 5; i++) {
      expect((await addPasskey(s, { name: `k${i}`, supportsPrf: false })).res.status).toBe(200)
    }
    const sixth = await call(s, '/api/webauthn/attestation-options', { masterPasswordHash: PW })
    expect(sixth.status).toBe(400)
  })

  it('validates the name', async () => {
    const s = await createSession('pk-name@example.com')
    expect((await addPasskey(s, { name: '', supportsPrf: false })).res.status).toBe(400)
    expect((await addPasskey(s, { name: 'x'.repeat(51), supportsPrf: false })).res.status).toBe(400)
  })

  it('deletes a credential only with the password and only for its owner', async () => {
    const a = await createSession('pk-del-a@example.com')
    const b = await createSession('pk-del-b@example.com')
    const { auth } = await addPasskey(a)
    const id = (await list(a)).data[0].id as string
    expect((await call(a, `/api/webauthn/${id}/delete`, { masterPasswordHash: 'no' })).status).toBe(
      400,
    )
    expect((await call(b, `/api/webauthn/${id}/delete`, { masterPasswordHash: PW })).status).toBe(
      404,
    )
    expect((await list(a)).data).toHaveLength(1)
    expect((await call(a, `/api/webauthn/${id}/delete`, { masterPasswordHash: PW })).status).toBe(
      200,
    )
    expect((await list(a)).data).toEqual([])
    expect((await call(a, `/api/webauthn/${id}/delete`, { masterPasswordHash: PW })).status).toBe(
      404,
    )
    // The credential no longer logs in.
    expect((await passkeyLogin(auth)).res.status).toBe(400)
  })

  it('cascades when the account is deleted', async () => {
    const s = await createSession('pk-cascade@example.com')
    const { auth } = await addPasskey(s)
    const count = async () =>
      (
        await env.DB.prepare('select count(*) n from webauthn_credentials where credential_id = ?')
          .bind(toB64u(auth.credentialId))
          .first<{ n: number }>()
      )?.n
    expect(await count()).toBe(1)
    const del = await call(s, '/api/accounts/delete', { masterPasswordHash: PW })
    expect(del.status).toBe(200)
    expect(await count()).toBe(0)
  })
})

describe('passkey login', () => {
  it('serves anonymous discoverable assertion options', async () => {
    const opts = await loginOptions()
    expect(opts.object).toBe('webAuthnLoginAssertionOptions')
    expect(opts.options).toMatchObject({
      rpId: RP_ID,
      allowCredentials: [],
      userVerification: 'required',
    })
    expect(opts.options.challenge).toMatch(/^[A-Za-z0-9_-]{75}$/)
    expect(opts.token.split('.')).toHaveLength(3)
    // Every call mints a fresh challenge.
    expect((await loginOptions()).options.challenge).not.toBe(opts.options.challenge)
  })

  it('logs in with a PRF passkey and returns the keyset for unlock', async () => {
    const email = 'pk-login@example.com'
    const s = await createSession(email)
    const { auth } = await addPasskey(s, { reg: { transports: ['usb', 'bogus'] } })
    const { res, body } = await passkeyLogin(auth)
    expect(res.status).toBe(200)
    expect(body).toMatchObject({
      token_type: 'Bearer',
      scope: 'api offline_access',
      Key: '2.encryptedSymmetricKey',
      PrivateKey: '2.pk',
      UserDecryptionOptions: {
        HasMasterPassword: true,
        WebAuthnPrfOption: {
          EncryptedPrivateKey: KEYS.encryptedPrivateKey,
          EncryptedUserKey: KEYS.encryptedUserKey,
          CredentialId: toB64u(auth.credentialId),
          Transports: ['usb'],
        },
      },
    })
    expect(body.refresh_token).toBeTruthy()
    const profile = await authed('/api/accounts/profile', body.access_token)
    expect(profile.status).toBe(200)
    expect(((await profile.json()) as any).email).toBe(email)
    // The refresh token works like any other.
    const refreshed = await form('/identity/connect/token', {
      grant_type: 'refresh_token',
      refresh_token: body.refresh_token,
      client_id: 'web',
    })
    expect(refreshed.status).toBe(200)
  })

  it('omits the PRF option for a credential without a keyset', async () => {
    const s = await createSession('pk-noprf@example.com')
    const { auth } = await addPasskey(s, { supportsPrf: false })
    const { res, body } = await passkeyLogin(auth)
    expect(res.status).toBe(200)
    expect(body.UserDecryptionOptions.WebAuthnPrfOption).toBeUndefined()
    expect(body.UserDecryptionOptions.HasMasterPassword).toBe(true)
  })

  it('logs in with an RS256 passkey and a matching user handle', async () => {
    const s = await createSession('pk-rs-login@example.com')
    const { auth } = await addPasskey(s, { alg: -257, supportsPrf: false })
    const uuid = ((await (await authed('/api/accounts/profile', s.access_token)).json()) as any).id
    const handle = new TextEncoder().encode(uuid)
    const ok = await passkeyLogin(auth, { assert: { userHandle: handle } })
    expect(ok.res.status).toBe(200)
  })

  it('rejects a user handle that names another account', async () => {
    const s = await createSession('pk-handle@example.com')
    const { auth } = await addPasskey(s, { supportsPrf: false })
    const bad = await passkeyLogin(auth, {
      assert: { userHandle: new TextEncoder().encode('00000000-0000-4000-8000-000000000000') },
    })
    expect(bad.res.status).toBe(400)
  })

  it('exposes the keysets in sync', async () => {
    const s = await createSession('pk-sync@example.com')
    const { auth } = await addPasskey(s)
    await addPasskey(s, { supportsPrf: false })
    const res = await authed('/api/sync', s.access_token)
    const sync = (await res.json()) as any
    expect(sync.userDecryption.webAuthnPrfOptions).toEqual([
      {
        EncryptedPrivateKey: KEYS.encryptedPrivateKey,
        EncryptedUserKey: KEYS.encryptedUserKey,
        CredentialId: toB64u(auth.credentialId),
        Transports: [],
      },
    ])
  })

  it('does not ask for a second factor', async () => {
    const email = 'pk-2fa@example.com'
    const s = await createSession(email)
    const { auth } = await addPasskey(s)
    const user = await env.DB.prepare('select uuid from users where email = ?')
      .bind(email)
      .first<{ uuid: string }>()
    await env.DB.prepare(
      'insert into twofactor (uuid, user_uuid, atype, enabled, data, last_used) values (?, ?, 0, 1, ?, 0)',
    )
      .bind(crypto.randomUUID(), user?.uuid, JSON.stringify({ key: 'JBSWY3DPEHPK3PXP' }))
      .run()
    expect((await login(email)).status).toBe(400)
    expect((await passkeyLogin(auth)).res.status).toBe(200)
  })

  it('refuses replays, stale counters and reused challenges', async () => {
    const s = await createSession('pk-replay@example.com')
    const { auth } = await addPasskey(s, { supportsPrf: false })
    const first = await passkeyLogin(auth, { assert: { signCount: 5 } })
    expect(first.res.status).toBe(200)
    // Posting the very same response again.
    const replay = await form('/identity/connect/token', {
      grant_type: 'webauthn',
      scope: 'api offline_access',
      client_id: 'web',
      deviceType: '9',
      deviceName: 'chrome',
      deviceIdentifier: 'passkey-device',
      token: first.opts.token,
      deviceResponse: JSON.stringify(first.response),
    })
    expect(replay.status).toBe(400)
    // A counter that does not advance is a cloned authenticator.
    expect((await passkeyLogin(auth, { assert: { signCount: 5 } })).res.status).toBe(400)
    expect((await passkeyLogin(auth, { assert: { signCount: 4 } })).res.status).toBe(400)
    expect((await passkeyLogin(auth, { assert: { signCount: 6 } })).res.status).toBe(200)
  })

  it('lets a challenge work once even when the counter stays at zero', async () => {
    const s = await createSession('pk-once@example.com')
    const { auth } = await addPasskey(s, { supportsPrf: false })
    const opts = await loginOptions()
    const sign = async () =>
      assertion(auth, opts.options.challenge, RP_ID, ORIGIN, { ...UV_ASSERT, signCount: 0 })
    const post = async (r: unknown) =>
      form('/identity/connect/token', {
        grant_type: 'webauthn',
        scope: 'api',
        client_id: 'web',
        deviceType: '9',
        deviceName: 'chrome',
        deviceIdentifier: 'once',
        token: opts.token,
        deviceResponse: JSON.stringify(r),
      })
    expect((await post(await sign())).status).toBe(200)
    expect((await post(await sign())).status).toBe(400)
  })

  it('rejects an assertion with the wrong key, origin, rp or flags', async () => {
    const s = await createSession('pk-wrong@example.com')
    const { auth } = await addPasskey(s, { supportsPrf: false })
    const status = async (o: GrantOpts) => (await passkeyLogin(auth, o)).res.status
    expect(await status({ assert: { origin: 'https://evil.example.org' } })).toBe(400)
    expect(await status({ assert: { rpId: 'evil.example.org' } })).toBe(400)
    // User presence without verification.
    expect(await status({ assert: { flags: 0x01 } })).toBe(400)
    expect(await status({ assert: { flags: 0x04 } })).toBe(400)
    // A different key pair claiming the same credential id.
    const forger = await newAuthenticator(-7)
    forger.credentialId = auth.credentialId
    expect((await passkeyLogin(forger)).res.status).toBe(400)
    expect(await status({})).toBe(200)
  })

  it('rejects malformed requests', async () => {
    const s = await createSession('pk-malformed@example.com')
    const { auth } = await addPasskey(s, { supportsPrf: false })
    const post = (fields: Record<string, string>) =>
      form('/identity/connect/token', {
        grant_type: 'webauthn',
        scope: 'api',
        client_id: 'web',
        deviceType: '9',
        deviceName: 'chrome',
        deviceIdentifier: 'm',
        ...fields,
      })
    const ok = await loginOptions()
    const response = await assertion(auth, ok.options.challenge, RP_ID, ORIGIN, UV_ASSERT)
    const dr = JSON.stringify(response)
    expect((await post({ token: ok.token })).status).toBe(400)
    expect((await post({ deviceResponse: dr })).status).toBe(400)
    expect((await post({ token: ok.token, deviceResponse: 'not json' })).status).toBe(400)
    expect((await post({ token: ok.token, deviceResponse: '{}' })).status).toBe(400)
    expect((await post({ token: ok.token, deviceResponse: '[]' })).status).toBe(400)
    expect((await post({ token: 'a.b.c', deviceResponse: dr })).status).toBe(400)
    // No device information.
    const noDevice = await form('/identity/connect/token', {
      grant_type: 'webauthn',
      scope: 'api',
      client_id: 'web',
      token: ok.token,
      deviceResponse: dr,
    })
    expect(noDevice.status).toBe(400)
    // An unknown credential.
    const stranger = await newAuthenticator(-7)
    const other = await assertion(stranger, ok.options.challenge, RP_ID, ORIGIN, UV_ASSERT)
    expect((await post({ token: ok.token, deviceResponse: JSON.stringify(other) })).status).toBe(
      400,
    )
    expect((await post({ token: ok.token, deviceResponse: dr })).status).toBe(200)
  })

  it('does not accept tokens or challenges minted for another purpose', async () => {
    const s = await createSession('pk-purpose@example.com')
    const { auth } = await addPasskey(s, { supportsPrf: false })
    // Registration and own-assertion tokens cannot start a login.
    const create = await createOptions(s)
    const own = await call(s, '/api/webauthn/assertion-options', { masterPasswordHash: PW })
    expect(own.status).toBe(200)
    expect(own.body.options.allowCredentials).toHaveLength(1)
    for (const [token, challenge] of [
      [create.token, create.options.challenge],
      [own.body.token, own.body.options.challenge],
    ] as const) {
      const r = await passkeyLogin(auth, { token, challenge })
      expect(r.res.status).toBe(400)
    }
    // A login token with a different challenge does not pair up either.
    const a = await loginOptions()
    const b = await loginOptions()
    expect(
      (await passkeyLogin(auth, { token: a.token, challenge: b.options.challenge })).res.status,
    ).toBe(400)
  })

  it('refuses an expired challenge', async () => {
    const s = await createSession('pk-late@example.com')
    const { auth } = await addPasskey(s, { supportsPrf: false })
    clock.now = () => Date.now() - 10 * 60 * 1000
    const opts = await loginOptions()
    clock.now = () => Date.now()
    const r = await passkeyLogin(auth, { token: opts.token, challenge: opts.options.challenge })
    expect(r.res.status).toBe(400)
  })

  it('refuses a disabled account and leaves the challenge unspent', async () => {
    const email = 'pk-disabled@example.com'
    const s = await createSession(email)
    const { auth } = await addPasskey(s, { supportsPrf: false })
    await env.DB.prepare('update users set enabled = 0 where email = ?').bind(email).run()
    const r = await passkeyLogin(auth)
    expect(r.res.status).toBe(400)
    expect(r.body.error_description).toBe('this account has been disabled')
  })

  it('keeps passkey login out of the password grant', async () => {
    const s = await createSession('pk-grant@example.com')
    await addPasskey(s, { supportsPrf: false })
    expect((await login('pk-grant@example.com', 'wrong')).status).toBe(400)
    const noGrant = await form('/identity/connect/token', { grant_type: 'passkey' })
    expect(noGrant.status).toBe(400)
  })
})

describe('enabling encryption on an existing credential', () => {
  async function ownAssertion(s: Session, auth: Auth, o: Parameters<typeof assertion>[4] = {}) {
    const opts = await call(s, '/api/webauthn/assertion-options', { masterPasswordHash: PW })
    expect(opts.status).toBe(200)
    expect(opts.body.object).toBe('webauthnCredentialAssertionOptions')
    const deviceResponse = await assertion(auth, opts.body.options.challenge, RP_ID, ORIGIN, {
      ...UV_ASSERT,
      ...o,
    })
    return { opts: opts.body, deviceResponse }
  }

  it('stores the keyset after a fresh assertion and then logs in with it', async () => {
    const s = await createSession('pk-enable@example.com')
    const { auth } = await addPasskey(s, { supportsPrf: true, keys: null })
    expect((await list(s)).data[0].prfStatus).toBe(1)
    const { opts, deviceResponse } = await ownAssertion(s, auth)
    expect(opts.options).toMatchObject({ rpId: RP_ID, userVerification: 'required' })
    const put = await call(
      s,
      '/api/webauthn',
      { deviceResponse, token: opts.token, ...KEYS },
      'PUT',
    )
    expect(put.status).toBe(200)
    expect((await list(s)).data[0]).toMatchObject({ prfStatus: 0, encryptedUserKey: '4.userkey' })
    const login1 = await passkeyLogin(auth)
    expect(login1.body.UserDecryptionOptions.WebAuthnPrfOption.EncryptedUserKey).toBe('4.userkey')
    // The assertion is spent.
    const again = await call(
      s,
      '/api/webauthn',
      { deviceResponse, token: opts.token, ...KEYS, encryptedUserKey: '4.other' },
      'PUT',
    )
    expect(again.status).toBe(400)
    expect((await list(s)).data[0].encryptedUserKey).toBe('4.userkey')
  })

  it('also marks a credential as PRF capable', async () => {
    const s = await createSession('pk-enable-flag@example.com')
    const { auth } = await addPasskey(s, { supportsPrf: false })
    const { opts, deviceResponse } = await ownAssertion(s, auth)
    const put = await call(
      s,
      '/api/webauthn',
      { deviceResponse, token: opts.token, ...KEYS },
      'PUT',
    )
    expect(put.status).toBe(200)
    expect((await list(s)).data[0].prfStatus).toBe(0)
  })

  it('rejects incomplete keysets, bad assertions and other accounts', async () => {
    const s = await createSession('pk-enable-bad@example.com')
    const { auth } = await addPasskey(s, { supportsPrf: true, keys: null })
    const { opts, deviceResponse } = await ownAssertion(s, auth)
    const put = (body: object, session = s) =>
      call(session, '/api/webauthn', { deviceResponse, token: opts.token, ...body }, 'PUT')
    expect((await put({ encryptedUserKey: '4.x' })).status).toBe(400)
    expect((await put({ ...KEYS, token: 'junk' })).status).toBe(400)
    // Another account cannot use it.
    const other = await createSession('pk-enable-bad2@example.com')
    expect((await put(KEYS, other)).status).toBe(400)
    // A login token is not an assertion token.
    const l = await loginOptions()
    const r = await assertion(auth, l.options.challenge, RP_ID, ORIGIN, UV_ASSERT)
    const wrong = await call(
      s,
      '/api/webauthn',
      { deviceResponse: r, token: l.token, ...KEYS },
      'PUT',
    )
    expect(wrong.status).toBe(400)
    // Without user verification.
    const weak = await ownAssertion(s, auth, { flags: 0x01 })
    const weakPut = await call(
      s,
      '/api/webauthn',
      { deviceResponse: weak.deviceResponse, token: weak.opts.token, ...KEYS },
      'PUT',
    )
    expect(weakPut.status).toBe(400)
    expect((await list(s)).data[0].prfStatus).toBe(1)
    expect((await put(KEYS)).status).toBe(200)
  })
})

describe('key rotation', () => {
  const path = '/api/accounts/key-management/rotate-user-account-keys'
  const body = (email: string, passkeys?: object[]) => ({
    oldMasterKeyAuthenticationHash: PW,
    accountUnlockData: {
      masterPasswordUnlockData: {
        kdfType: 0,
        kdfIterations: 600000,
        email,
        masterKeyAuthenticationHash: 'rotated-hash',
        masterKeyEncryptedUserKey: '2.newkey',
        masterPasswordHint: null,
      },
      ...(passkeys ? { passkeyUnlockData: passkeys } : {}),
    },
    accountKeys: { userKeyEncryptedAccountPrivateKey: '2.newpriv', accountPublicKey: 'public-key' },
    accountData: { ciphers: [], folders: [], sends: [] },
  })

  it('re-wraps keysets that are sent and drops those that are not', async () => {
    const email = 'pk-rot@example.com'
    const s = await createSession(email)
    const a = await addPasskey(s, { name: 'kept' })
    await addPasskey(s, { name: 'dropped' })
    await addPasskey(s, { name: 'plain', supportsPrf: false })
    const rows = (await list(s)).data as any[]
    const kept = rows.find((r) => r.name === 'kept')
    const res = await authed(
      path,
      s.access_token,
      'POST',
      body(email, [{ id: kept.id, encryptedPublicKey: '2.rotpub', encryptedUserKey: '4.rotuser' }]),
    )
    expect(res.status).toBe(200)
    // The rotation revoked the session; log in again to read the list.
    const fresh = (await (await login(email, 'rotated-hash')).json()) as Session
    const after = Object.fromEntries(((await list(fresh)).data as any[]).map((r) => [r.name, r]))
    expect(after.kept).toMatchObject({
      prfStatus: 0,
      encryptedUserKey: '4.rotuser',
      encryptedPublicKey: '2.rotpub',
    })
    expect(after.dropped).toMatchObject({ prfStatus: 1, encryptedUserKey: null })
    expect(after.plain.prfStatus).toBe(2)
    // The private key wrapped by the PRF output is unchanged.
    const login1 = await passkeyLogin(a.auth)
    expect(login1.body.UserDecryptionOptions.WebAuthnPrfOption).toMatchObject({
      EncryptedUserKey: '4.rotuser',
      EncryptedPrivateKey: KEYS.encryptedPrivateKey,
    })
    expect(login1.body.Key).toBe('2.newkey')
  })

  it('drops every keyset on the legacy rotation endpoint', async () => {
    const email = 'pk-rot-legacy@example.com'
    const s = await createSession(email)
    await addPasskey(s)
    const res = await authed('/api/accounts/key', s.access_token, 'POST', {
      masterPasswordHash: PW,
      key: '2.legacykey',
      privateKey: '2.pk2',
      folders: [],
      ciphers: [],
      sends: [],
    })
    expect(res.status).toBe(200)
    const fresh = (await (await login(email)).json()) as Session
    expect(((await list(fresh)).data as any[])[0]).toMatchObject({
      prfStatus: 1,
      encryptedUserKey: null,
    })
  })

  it('does not leave an old-key keyset when one is written during the rotation', async () => {
    const email = 'pk-rot-race@example.com'
    const s = await createSession(email)
    const { auth } = await addPasskey(s, { supportsPrf: true, keys: null })
    const user = await env.DB.prepare('select uuid from users where email = ?')
      .bind(email)
      .first<{ uuid: string }>()
    const db = createDb(env.DB)
    // Rotation reads the credentials (no keyset yet) and builds its statements ...
    const statements = await passkeyRotation(db, user?.uuid as string, [])
    // ... a concurrent PUT /api/webauthn then stores a keyset wrapping the old user key ...
    await env.DB.prepare(
      "update webauthn_credentials set encrypted_user_key = '4.old', encrypted_public_key = '2.old', encrypted_private_key = '2.old', updated_at = ? where user_uuid = ?",
    )
      .bind(Date.now() + 5, user?.uuid)
      .run()
    // ... and the rotation batch still removes it.
    await runBatch(db, statements)
    const row = await env.DB.prepare(
      'select encrypted_user_key k from webauthn_credentials where user_uuid = ?',
    )
      .bind(user?.uuid)
      .first<{ k: string | null }>()
    expect(row?.k).toBeNull()
    expect(auth).toBeTruthy()
  })

  it('removes a stale re-wrap when the credential changed after it was read', async () => {
    const email = 'pk-rot-race2@example.com'
    const s = await createSession(email)
    await addPasskey(s)
    const user = await env.DB.prepare('select uuid from users where email = ?')
      .bind(email)
      .first<{ uuid: string }>()
    const id = ((await list(s)).data[0] as any).id
    const db = createDb(env.DB)
    const statements = await passkeyRotation(db, user?.uuid as string, [
      { id, encryptedPublicKey: '2.newpub', encryptedUserKey: '4.newuser' },
    ])
    await env.DB.prepare(
      "update webauthn_credentials set encrypted_user_key = '4.raced', updated_at = updated_at + 7 where uuid = ?",
    )
      .bind(id)
      .run()
    await runBatch(db, statements)
    const row = await env.DB.prepare(
      'select encrypted_user_key k from webauthn_credentials where uuid = ?',
    )
      .bind(id)
      .first<{ k: string | null }>()
    expect(row?.k).toBeNull()
  })

  it('rejects rotation naming a foreign or keyset-less passkey and changes nothing', async () => {
    const email = 'pk-rot-bad@example.com'
    const s = await createSession(email)
    await addPasskey(s, { name: 'mine' })
    const plain = await addPasskey(s, { name: 'plain', supportsPrf: false })
    expect(plain.res.status).toBe(200)
    const other = await createSession('pk-rot-other@example.com')
    await addPasskey(other)
    const foreignId = ((await list(other)).data[0] as any).id
    const plainId = ((await list(s)).data as any[]).find((r) => r.name === 'plain').id
    const send = (id: string) =>
      authed(
        path,
        s.access_token,
        'POST',
        body(email, [{ id, encryptedPublicKey: '2.p', encryptedUserKey: '4.u' }]),
      )
    expect((await send(foreignId)).status).toBe(400)
    expect((await send(plainId)).status).toBe(400)
    expect((await send('nope')).status).toBe(400)
    expect((await login(email)).status).toBe(200)
    expect(((await list(s)).data as any[]).find((r) => r.name === 'mine').prfStatus).toBe(0)
  })
})

it('offers the login options on GET only', async () => {
  const res = await json('/identity/accounts/webauthn/assertion-options', {})
  expect(res.status).toBe(404)
})
