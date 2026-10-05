import { env } from 'cloudflare:workers'
import { afterEach, describe, expect, it } from 'vitest'
import { BASE, createSession, freezeRateLimitWindow, login, registerBody, withEnv } from './helpers'
import { actor, createOrg, mailbox } from './org-helpers'

// Behaviour of every mail dependent feature with and without a mail transport (TASKS #350).

let n = 0
const uniq = (p: string) => `${p}${++n}@example.com`
const secret = () => `setup-token-${crypto.randomUUID()}-${crypto.randomUUID()}`
const post = (over: Record<string, unknown>, path: string, body: unknown, token?: string) =>
  withEnv(over, path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  })
const get = (over: Record<string, unknown>, path: string, token?: string) =>
  withEnv(over, path, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
const mailOver = () => {
  const mb = mailbox()
  return { mb, over: { EMAIL: mb.EMAIL, MAIL_FROM: mb.MAIL_FROM } }
}
const redeem = (over: Record<string, unknown>, email: string, code: string) =>
  post(over, '/api/cloudwarden/registration/redeem', { email, code })
const finish = (over: Record<string, unknown>, email: string, token: string) =>
  post(over, '/identity/accounts/register/finish', {
    ...registerBody(email),
    emailVerificationToken: token,
  })
const tokenOf = async (res: Response) =>
  ((await res.json()) as { emailVerificationToken: string }).emailVerificationToken

const restore: (() => void)[] = []
afterEach(() => {
  while (restore.length) restore.pop()?.()
})

describe('/api/config', () => {
  it('reports that mail is off and what each feature does', async () => {
    const res = await get({}, '/api/config')
    const body = (await res.json()) as any
    expect(body.cloudwarden.email.configured).toBe(false)
    const state = (id: string) =>
      body.cloudwarden.email.features.find((f: any) => f.id === id)?.state
    expect(state('email-2fa')).toBe('refused')
    expect(state('magic-link')).toBe('refused')
    expect(state('new-device-otp')).toBe('skipped')
    expect(state('instance-invite')).toBe('link')
    expect(state('first-admin')).toBe('manual')
  })

  it('reports that mail works and every feature is available', async () => {
    const { over } = mailOver()
    const body = (await (await get(over, '/api/config')).json()) as any
    expect(body.cloudwarden.email.configured).toBe(true)
    expect(body.cloudwarden.email.features.every((f: any) => f.state === 'available')).toBe(true)
  })
})

describe('first admin with the setup token (mail off)', () => {
  const setup = (admins: string, token = secret()) => ({
    ADMIN_ENABLED: 'true',
    SIGNUPS_ALLOWED: 'false',
    ADMIN_EMAILS: admins,
    ADMIN_SETUP_TOKEN: token,
  })

  it('refuses the usual route for an admin address', async () => {
    const admin = uniq('adm')
    const over = setup(admin)
    const res = await post(over, '/identity/accounts/register/send-verification-email', {
      email: admin,
    })
    expect(res.status).toBe(400)
    // The same answer as for any closed signup, plus where to go.
    expect(((await res.json()) as any).message).toContain('/#/instance-setup')
    // Open signups never make an admin address claimable.
    const open = await post(
      { ...over, SIGNUPS_ALLOWED: 'true' },
      '/identity/accounts/register/send-verification-email',
      { email: admin },
    )
    expect(open.status).toBe(400)
    expect(
      (
        await post(
          { ...over, SIGNUPS_ALLOWED: 'true' },
          '/identity/accounts/register',
          registerBody(admin),
        )
      ).status,
    ).toBe(400)
  })

  it('creates the first admin with the right token, once', async () => {
    const admin = uniq('adm')
    const token = secret()
    const over = setup(admin, token)
    const reg = await redeem(over, admin, token)
    expect(reg.status).toBe(200)
    expect((await finish(over, admin, await tokenOf(reg))).status).toBe(200)
    const s = await login(admin)
    const me = await get(over, '/api/cloudwarden/me', ((await s.json()) as any).access_token)
    expect(((await me.json()) as any).isAdmin).toBe(true)
    // Recorded in D1, keyed by the secret's hash and not by the secret.
    const used = await env.DB.prepare('SELECT * FROM admin_setup_uses').all<any>()
    expect(used.results.some((r) => r.user_uuid && !JSON.stringify(r).includes(token))).toBe(true)
  })

  it('refuses a wrong token, a missing secret and a short secret with one answer', async () => {
    const admin = uniq('adm')
    const token = secret()
    const wrong = await redeem(setup(admin, token), admin, `${token}x`)
    expect(wrong.status).toBe(400)
    const msg = ((await wrong.json()) as any).message
    const none = await redeem({ ...setup(admin), ADMIN_SETUP_TOKEN: undefined }, admin, token)
    expect(none.status).toBe(400)
    expect(((await none.json()) as any).message).toBe(msg)
    const short = await redeem(
      { ...setup(admin), ADMIN_SETUP_TOKEN: 'short-secret' },
      admin,
      'short-secret',
    )
    expect(short.status).toBe(400)
    expect(((await short.json()) as any).message).toBe(msg)
    // An empty code never matches an unset secret.
    expect((await redeem({ ...setup(admin), ADMIN_SETUP_TOKEN: '' }, admin, ' ')).status).toBe(400)
  })

  it('cannot be reused once the first admin exists, for any admin address', async () => {
    const first = uniq('adm')
    const second = uniq('adm')
    const token = secret()
    const over = setup(`${first},${second}`, token)
    // A token for the second address is minted before the first admin is created.
    const early = await tokenOf(await redeem(over, second, token))
    const reg = await redeem(over, first, token)
    expect((await finish(over, first, await tokenOf(reg))).status).toBe(200)
    // Fresh redemptions are refused, for the same and for another admin address.
    expect((await redeem(over, first, token)).status).toBe(400)
    expect((await redeem(over, second, token)).status).toBe(400)
    // So is the registration token minted earlier.
    expect((await finish(over, second, early)).status).toBe(400)
    expect(
      (await env.DB.prepare('SELECT 1 FROM users WHERE email = ?1').bind(second).all()).results,
    ).toHaveLength(0)
  })

  it('stays spent when the admin account is deleted, until the secret is rotated', async () => {
    const admin = uniq('adm')
    const token = secret()
    const over = setup(admin, token)
    expect(
      (await finish(over, admin, await tokenOf(await redeem(over, admin, token)))).status,
    ).toBe(200)
    await env.DB.prepare('DELETE FROM users WHERE email = ?1').bind(admin).run()
    expect((await redeem(over, admin, token)).status).toBe(400)
    const rotated = secret()
    const again = await redeem(setup(admin, rotated), admin, rotated)
    expect(again.status).toBe(200)
  })

  it('does not honour a registration token that lacks the setup claim', async () => {
    const admin = uniq('adm')
    const token = secret()
    // A token from the emailed link (mail on) proves the mailbox, but a mail-off server must not
    // accept it for an admin address: whoever holds it did not use the setup secret.
    const { mb, over: mailed } = mailOver()
    const base = setup(admin, token)
    const sent = await post(
      { ...base, ...mailed, SIGNUPS_ALLOWED: 'true' },
      '/identity/accounts/register/send-verification-email',
      { email: admin },
    )
    expect(sent.status).toBe(204)
    const link = /token=([^&\s]+)/.exec(mb.sent[0]?.text ?? '')?.[1] ?? ''
    const emailed = decodeURIComponent(link)
    expect((await finish(base, admin, emailed)).status).toBe(400)
    // With mail the same token works and needs no setup secret.
    expect(
      (await finish({ ...base, ...mailed, ADMIN_SETUP_TOKEN: undefined }, admin, emailed)).status,
    ).toBe(200)
  })

  it('is refused when mail works, and a non-admin address cannot use the secret', async () => {
    const admin = uniq('adm')
    const other = uniq('usr')
    const token = secret()
    const { over: mailed } = mailOver()
    const res = await redeem({ ...setup(admin, token), ...mailed }, admin, token)
    expect(res.status).toBe(400)
    expect(((await res.json()) as any).message).toContain('sends email')
    const nonAdmin = await redeem(setup(admin, token), other, token)
    expect(nonAdmin.status).toBe(400)
  })

  it('refuses a long setup secret that is visibly not random', async () => {
    const admin = uniq('adm')
    const weak = 'a'.repeat(40)
    expect((await redeem(setup(admin, weak), admin, weak)).status).toBe(400)
  })

  it('is rate limited per address, with time frozen', async () => {
    restore.push(freezeRateLimitWindow())
    const admin = uniq('adm')
    const over = setup(admin)
    const statuses: number[] = []
    for (let i = 0; i < 7; i++) statuses.push((await redeem(over, admin, `guess-${i}`)).status)
    expect(statuses.slice(0, 5).every((s) => s === 400)).toBe(true)
    expect(statuses.slice(5)).toEqual([429, 429])
    // A correct token is refused while the window is exhausted.
    expect((await redeem(over, admin, over.ADMIN_SETUP_TOKEN)).status).toBe(429)
    // Another address is counted separately.
    const other = uniq('adm')
    expect((await redeem(setup(other), other, 'x')).status).toBe(400)
  })
})

describe('instance invitations without mail', () => {
  const adminOver = (admin: string, extra: Record<string, unknown> = {}) => ({
    ADMIN_ENABLED: 'true',
    ADMIN_EMAILS: admin,
    SIGNUPS_ALLOWED: 'false',
    ...extra,
  })
  async function admin(extra: Record<string, unknown> = {}) {
    const email = uniq('admin')
    const s = await createSession(email)
    return { email, over: adminOver(email, extra), token: s.access_token }
  }
  const invite = (a: Awaited<ReturnType<typeof admin>>, email: string, over = a.over) =>
    post(over, '/api/cloudwarden/admin/invitations', { email }, a.token)
  const codeOf = (link: string) => new URLSearchParams(link.split('?')[1] ?? '').get('code') ?? ''

  it('shows a copyable link instead of mailing, and the link registers the address once', async () => {
    const a = await admin()
    const guest = uniq('guest')
    const res = await invite(a, guest)
    expect(res.status).toBe(201)
    const body = (await res.json()) as any
    expect(body.emailStatus).toBe('not-configured')
    expect(body.link).toContain(`${BASE}/#/instance-setup?email=`)
    const code = codeOf(body.link)
    // Only a hash is stored.
    const row = await env.DB.prepare('SELECT * FROM invitations WHERE email = ?1')
      .bind(guest)
      .first<any>()
    expect(JSON.stringify(row)).not.toContain(code)
    // The ordinary route gives an invited address nothing: an address alone proves nothing.
    expect(
      (
        await post(a.over, '/identity/accounts/register/send-verification-email', {
          email: guest,
        })
      ).status,
    ).toBe(400)
    expect((await post(a.over, '/identity/accounts/register', registerBody(guest))).status).toBe(
      400,
    )
    // A wrong code, and the code with another address, are refused.
    expect((await redeem(a.over, guest, `${code}x`)).status).toBe(400)
    expect((await redeem(a.over, uniq('other'), code)).status).toBe(400)
    const ok = await redeem(a.over, guest, code)
    expect(ok.status).toBe(200)
    expect((await finish(a.over, guest, await tokenOf(ok))).status).toBe(200)
    // Spent with the invitation.
    expect((await redeem(a.over, guest, code)).status).toBe(400)
  })

  it('wrong guesses from one client do not block the right code from another', async () => {
    restore.push(freezeRateLimitWindow())
    const a = await admin()
    const guest = uniq('guest')
    const code = codeOf(((await (await invite(a, guest)).json()) as any).link)
    const from = (ip: string, c: string) =>
      withEnv(a.over, '/api/cloudwarden/registration/redeem', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
        body: JSON.stringify({ email: guest, code: c }),
      })
    for (let i = 0; i < 6; i++) await from('198.51.100.7', `guess-${i}`)
    // The guesser is now blocked, even with the right code; the invitee is not.
    expect((await from('198.51.100.7', code)).status).toBe(429)
    expect((await from('203.0.113.9', code)).status).toBe(200)
  })

  it('wrong guesses at an admin address do not block the setup secret from another client', async () => {
    restore.push(freezeRateLimitWindow())
    const adminAddr = uniq('adm')
    const token = secret()
    const over = {
      ADMIN_ENABLED: 'true',
      SIGNUPS_ALLOWED: 'false',
      ADMIN_EMAILS: adminAddr,
      ADMIN_SETUP_TOKEN: token,
    }
    const from = (ip: string, c: string) =>
      withEnv(over, '/api/cloudwarden/registration/redeem', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
        body: JSON.stringify({ email: adminAddr, code: c }),
      })
    for (let i = 0; i < 6; i++) await from('198.51.100.8', `guess-${i}`)
    expect((await from('203.0.113.10', token)).status).toBe(200)
  })

  it('a new link retires the old one, and an expired code is refused', async () => {
    const a = await admin()
    const guest = uniq('guest')
    const first = codeOf(((await (await invite(a, guest)).json()) as any).link)
    const second = ((await (await invite(a, guest)).json()) as any).link
    expect(codeOf(second)).not.toBe(first)
    expect((await redeem(a.over, guest, first)).status).toBe(400)
    await env.DB.prepare('UPDATE invitations SET token_expires_at = ?1 WHERE email = ?2')
      .bind(Date.now() - 1000, guest)
      .run()
    expect((await redeem(a.over, guest, codeOf(second))).status).toBe(400)
    const list = (await (
      await get(a.over, '/api/cloudwarden/admin/invitations', a.token)
    ).json()) as any
    expect(list.data.find((i: any) => i.email === guest).codeExpiresAt).not.toBeNull()
  })

  it('an invitation made while mail worked has no code and needs a new link', async () => {
    const a = await admin()
    const { over: mailed } = mailOver()
    const guest = uniq('guest')
    const res = await invite(a, guest, { ...a.over, ...mailed })
    expect(((await res.json()) as any).link).toBeUndefined()
    expect((await redeem(a.over, guest, 'anything')).status).toBe(400)
    expect(((await (await invite(a, guest)).json()) as any).link).toContain('code=')
  })

  it('an invite code never creates an admin account', async () => {
    const a = await admin()
    const target = uniq('adm')
    const over = adminOver(`${a.email},${target}`, { ADMIN_SETUP_TOKEN: secret() })
    const res = await post(over, '/api/cloudwarden/admin/invitations', { email: target }, a.token)
    const code = codeOf(((await res.json()) as any).link)
    expect((await redeem(over, target, code)).status).toBe(400)
  })

  it('open signups and the domain whitelist keep working without mail', async () => {
    const open = await post(
      { SIGNUPS_ALLOWED: 'true' },
      '/identity/accounts/register/send-verification-email',
      { email: uniq('open') },
    )
    expect(open.status).toBe(200)
    const listed = await post(
      { SIGNUPS_ALLOWED: 'false', SIGNUPS_DOMAINS_WHITELIST: 'example.com' },
      '/identity/accounts/register/send-verification-email',
      { email: uniq('wl') },
    )
    expect(listed.status).toBe(200)
  })

  it('with mail the invitation is emailed and carries no code', async () => {
    const a = await admin()
    const { mb, over: mailed } = mailOver()
    const guest = uniq('guest')
    const res = await invite(a, guest, { ...a.over, ...mailed })
    const body = (await res.json()) as any
    expect(body.emailStatus).toBe('sent')
    expect(body.link).toBeUndefined()
    expect(mb.sent[0]?.to).toBe(guest)
    // The emailed route still works as before: invited and mail proves the address.
    const sent = await post(
      { ...a.over, ...mailed },
      '/identity/accounts/register/send-verification-email',
      { email: guest },
    )
    expect(sent.status).toBe(204)
  })

  it('the admin overview says email is not configured and lists affected features', async () => {
    const a = await admin()
    const res = await get(a.over, '/api/cloudwarden/admin/overview', a.token)
    const body = (await res.json()) as any
    expect(body.emailConfigured).toBe(false)
    expect(body.email.configured).toBe(false)
    expect(
      body.email.features.some((f: any) => f.id === 'email-2fa' && f.state === 'refused'),
    ).toBe(true)
    const { over: mailed } = mailOver()
    const on = (await (
      await get({ ...a.over, ...mailed }, '/api/cloudwarden/admin/overview', a.token)
    ).json()) as any
    expect(on.email.configured).toBe(true)
  })
})

describe('email address change', () => {
  const change = async (
    over: Record<string, unknown>,
    token: string,
    newEmail: string,
    extra = {},
  ) => {
    const req = await post(
      over,
      '/api/accounts/email-token',
      { newEmail, masterPasswordHash: 'client-derived-hash' },
      token,
    )
    if (req.status !== 204) return req
    return post(
      over,
      '/api/accounts/email',
      {
        newEmail,
        masterPasswordHash: 'client-derived-hash',
        newMasterPasswordHash: 'client-derived-hash',
        key: '2.newKey',
        ...extra,
      },
      token,
    )
  }

  it('without mail needs the master password, twice, and no code', async () => {
    const me = uniq('chg')
    const s = await createSession(me)
    const to = uniq('new')
    const wrong = await post(
      {},
      '/api/accounts/email-token',
      { newEmail: to, masterPasswordHash: 'wrong' },
      s.access_token,
    )
    expect(wrong.status).toBe(400)
    // No pending request: the change itself is refused.
    const bare = await post(
      {},
      '/api/accounts/email',
      {
        newEmail: to,
        masterPasswordHash: 'client-derived-hash',
        newMasterPasswordHash: 'x',
        key: '2.k',
      },
      s.access_token,
    )
    expect(bare.status).toBe(400)
    const wrongAgain = await change({}, s.access_token, to, { masterPasswordHash: 'wrong' })
    expect(wrongAgain.status).toBe(400)
    expect((await change({}, s.access_token, to)).status).toBe(200)
    expect((await login(to)).status).toBe(200)
    expect((await login(me)).status).toBe(400)
  }, 150_000)

  it('without mail never moves an account onto an admin address', async () => {
    const me = uniq('chg')
    const s = await createSession(me)
    const adminAddr = uniq('adm')
    const over = { ADMIN_ENABLED: 'true', ADMIN_EMAILS: adminAddr }
    const res = await post(
      over,
      '/api/accounts/email-token',
      { newEmail: adminAddr, masterPasswordHash: 'client-derived-hash' },
      s.access_token,
    )
    expect(res.status).toBe(400)
    // Even with a request stored before the address was listed.
    await env.DB.prepare(
      'UPDATE users SET email_new = ?1, email_new_expires_at = ?2 WHERE email = ?3',
    )
      .bind(adminAddr, Date.now() + 60_000, me)
      .run()
    const direct = await post(
      over,
      '/api/accounts/email',
      {
        newEmail: adminAddr,
        masterPasswordHash: 'client-derived-hash',
        newMasterPasswordHash: 'client-derived-hash',
        key: '2.k',
      },
      s.access_token,
    )
    expect(direct.status).toBe(400)
    expect((await login(me)).status).toBe(200)
  })

  it('without mail the new address is stored unverified, and an invited address is refused', async () => {
    const me = uniq('chg')
    const s = await createSession(me)
    await env.DB.prepare('UPDATE users SET verified_at = ?1 WHERE email = ?2')
      .bind(Date.now(), me)
      .run()
    const invited = uniq('inv')
    await env.DB.prepare(
      'INSERT INTO invitations (uuid, email, invited_by, created_at) VALUES (?1, ?2, ?3, ?4)',
    )
      .bind(crypto.randomUUID(), invited, 'someone', Date.now())
      .run()
    const refused = await change({}, s.access_token, invited)
    expect(refused.status).toBe(400)
    expect(((await refused.json()) as any).message ?? '').toContain('already in use')
    // A free address is accepted and ends up unverified.
    const to = uniq('new')
    expect((await change({}, s.access_token, to)).status).toBe(200)
    const row = await env.DB.prepare('SELECT verified_at FROM users WHERE email = ?1')
      .bind(to)
      .first<{ verified_at: number | null }>()
    expect(row?.verified_at).toBeNull()
  }, 150_000)

  it('with mail the proven address stays verified', async () => {
    const me = uniq('chg')
    const s = await createSession(me)
    await env.DB.prepare('UPDATE users SET verified_at = ?1 WHERE email = ?2')
      .bind(Date.now(), me)
      .run()
    const to = uniq('new')
    const { mb, over } = mailOver()
    await change(over, s.access_token, to)
    const code = /\b(\d{6})\b/.exec(mb.sent.at(-1)?.text ?? '')?.[1] ?? ''
    const ok = await post(
      over,
      '/api/accounts/email',
      {
        newEmail: to,
        masterPasswordHash: 'client-derived-hash',
        newMasterPasswordHash: 'client-derived-hash',
        key: '2.k',
        token: code,
      },
      s.access_token,
    )
    expect(ok.status).toBe(200)
    const row = await env.DB.prepare('SELECT verified_at FROM users WHERE email = ?1')
      .bind(to)
      .first<{ verified_at: number | null }>()
    expect(row?.verified_at).not.toBeNull()
  }, 150_000)

  it('answers an admin address exactly like an address that is taken', async () => {
    const me = uniq('chg')
    const s = await createSession(me)
    const taken = uniq('taken')
    await createSession(taken)
    const adminAddr = uniq('adm')
    const over = { ADMIN_ENABLED: 'true', ADMIN_EMAILS: adminAddr }
    const ask = async (addr: string) => {
      const res = await post(
        over,
        '/api/accounts/email-token',
        { newEmail: addr, masterPasswordHash: 'client-derived-hash' },
        s.access_token,
      )
      return { status: res.status, body: await res.text() }
    }
    const a = await ask(adminAddr)
    const b = await ask(taken)
    expect(a.status).toBe(400)
    expect(a).toEqual(b)
    expect(a.body).not.toContain('reserved')
  })

  it('with mail still needs the emailed code', async () => {
    const me = uniq('chg')
    const s = await createSession(me)
    const to = uniq('new')
    const { mb, over } = mailOver()
    expect((await change(over, s.access_token, to)).status).toBe(400)
    expect((await change(over, s.access_token, to, { token: '000000' })).status).toBe(400)
    const code = /\b(\d{6})\b/.exec(mb.sent.at(-1)?.text ?? '')?.[1] ?? ''
    const ok = await post(
      over,
      '/api/accounts/email',
      {
        newEmail: to,
        masterPasswordHash: 'client-derived-hash',
        newMasterPasswordHash: 'client-derived-hash',
        key: '2.k',
        token: code,
      },
      s.access_token,
    )
    expect(ok.status).toBe(200)
  })
})

describe('verified address, two-step login and invitations', () => {
  it('treats an unverified account as verified only while mail is off', async () => {
    const me = uniq('ver')
    const s = await createSession(me)
    await env.DB.prepare('UPDATE users SET verified_at = NULL WHERE email = ?1').bind(me).run()
    const off = (await (await get({}, '/api/accounts/profile', s.access_token)).json()) as any
    expect(off.emailVerified).toBe(true)
    const { over } = mailOver()
    const on = (await (await get(over, '/api/accounts/profile', s.access_token)).json()) as any
    expect(on.emailVerified).toBe(false)
    // The admin check never relaxes: an unverified listed address is not an admin.
    const admin = await get(
      { ADMIN_ENABLED: 'true', ADMIN_EMAILS: me },
      '/api/cloudwarden/me',
      s.access_token,
    )
    expect(((await admin.json()) as any).isAdmin).toBe(false)
  })

  it('email two-step login is refused without mail and hidden next to other providers', async () => {
    const me = uniq('tf')
    const s = await createSession(me)
    const proof = { masterPasswordHash: 'client-derived-hash' }
    const refused = await post(
      {},
      '/api/two-factor/send-email',
      { ...proof, email: me },
      s.access_token,
    )
    expect(refused.status).toBe(400)
    expect(((await refused.json()) as any).message).toContain('not configured')
    const login2 = (extra = {}) =>
      login(me, 'client-derived-hash', { deviceIdentifier: `d-${n}`, ...extra })
    const [{ uuid }] = (
      await env.DB.prepare('SELECT uuid FROM users WHERE email = ?1').bind(me).all<any>()
    ).results
    await env.DB.prepare(
      'INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data) VALUES (?1, ?2, 1, 1, ?3)',
    )
      .bind(crypto.randomUUID(), uuid, JSON.stringify({ email: me, code: null }))
      .run()
    // Email only: the challenge says why and points to the recovery code.
    const only = await login2()
    expect(only.status).toBe(400)
    const body = (await only.json()) as any
    expect(body.TwoFactorProviders).toEqual(['1'])
    expect(body.error_description).toContain('recovery code')
    // The login-time code request is refused with a clear message too.
    const send = await post({}, '/api/two-factor/send-email-login', {
      email: me,
      masterPasswordHash: 'client-derived-hash',
    })
    expect(send.status).toBe(400)
    // With an authenticator as well, email is no longer offered.
    await env.DB.prepare(
      'INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data) VALUES (?1, ?2, 0, 1, ?3)',
    )
      .bind(crypto.randomUUID(), uuid, JSON.stringify({ key: 'JBSWY3DPEHPK3PXP' }))
      .run()
    const both = (await (await login2()).json()) as any
    expect(both.TwoFactorProviders).toEqual(['0'])
    // With mail both are offered.
    const { over } = mailOver()
    const withMail = await withEnv(over, '/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        username: me,
        password: 'client-derived-hash',
        scope: 'api offline_access',
        client_id: 'web',
        deviceType: '9',
        deviceName: 'chrome',
        deviceIdentifier: 'd-mail',
      }).toString(),
    })
    expect(((await withMail.json()) as any).TwoFactorProviders).toEqual(['0', '1'])
  })

  it('a new device is not asked for an emailed code without mail, and is with mail', async () => {
    const me = uniq('nd')
    await createSession(me, { deviceIdentifier: 'first' })
    expect((await login(me, 'client-derived-hash', { deviceIdentifier: 'second' })).status).toBe(
      200,
    )
    const { over } = mailOver()
    const res = await withEnv(over, '/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        username: me,
        password: 'client-derived-hash',
        scope: 'api offline_access',
        client_id: 'web',
        deviceType: '9',
        deviceName: 'chrome',
        deviceIdentifier: 'third',
      }).toString(),
    })
    expect(res.status).toBe(400)
    expect(JSON.stringify(await res.json())).toContain('new device verification required')
  })

  it('organisation and emergency access invitations are refused without mail and work with it', async () => {
    const { mb, over } = mailOver()
    const owner = await actor(uniq('owner'), mb)
    const org = await createOrg(owner)
    const guest = uniq('guest')
    const body = {
      emails: [guest],
      type: 2,
      accessAll: false,
      collections: [],
      groups: [],
      permissions: null,
    }
    const off = await post({}, `/api/organizations/${org.id}/users/invite`, body, owner.token)
    expect(off.status).toBe(400)
    expect(((await off.json()) as any).message).toContain('invite link')
    // Nothing was stored by the refused call.
    expect(
      (await env.DB.prepare('SELECT 1 FROM users_organizations WHERE email = ?1').bind(guest).all())
        .results,
    ).toHaveLength(0)
    const on = await post(over, `/api/organizations/${org.id}/users/invite`, body, owner.token)
    expect(on.status).toBe(200)
    const memberId = (
      await env.DB.prepare('SELECT uuid FROM users_organizations WHERE email = ?1')
        .bind(guest)
        .first<any>()
    ).uuid
    expect(
      (await post({}, `/api/organizations/${org.id}/users/${memberId}/reinvite`, {}, owner.token))
        .status,
    ).toBe(400)
    expect(
      (await post(over, `/api/organizations/${org.id}/users/${memberId}/reinvite`, {}, owner.token))
        .status,
    ).toBe(200)

    const em = { email: uniq('ec'), type: 0, waitTimeDays: 7 }
    const eoff = await post({}, '/api/emergency-access/invite', em, owner.token)
    expect(eoff.status).toBe(400)
    expect(((await eoff.json()) as any).message).toContain('cannot send email')
    expect((await post(over, '/api/emergency-access/invite', em, owner.token)).status).toBe(200)
    const eid = (
      await env.DB.prepare('SELECT uuid FROM emergency_access WHERE email = ?1')
        .bind(em.email)
        .first<any>()
    ).uuid
    expect((await post({}, `/api/emergency-access/${eid}/reinvite`, {}, owner.token)).status).toBe(
      400,
    )
  })

  it('features that need a mailbox answer with a clear 400', async () => {
    const me = uniq('feat')
    const s = await createSession(me)
    for (const [path, body, token] of [
      ['/api/accounts/password-hint', { email: me }, undefined],
      ['/api/accounts/delete-recover', { email: me }, undefined],
      ['/api/accounts/verify-email', {}, s.access_token],
      ['/api/accounts/request-otp', {}, s.access_token],
    ] as const) {
      const res = await post({}, path, body, token)
      expect(res.status, path).toBe(400)
      expect(((await res.json()) as any).message, path).toContain('cannot send email')
    }
    // Email protected Sends cannot be created: their codes could never be delivered.
    const send = await post(
      {},
      '/api/sends',
      {
        type: 0,
        key: '2.k',
        name: '2.n',
        text: { text: '2.t', hidden: false },
        deletionDate: new Date(Date.now() + 86_400_000).toISOString(),
        emails: 'a@example.com',
        authType: 1,
        disabled: false,
      },
      s.access_token,
    )
    expect(send.status).toBe(400)
  })
})
