import { env } from 'cloudflare:workers'
import { expect, it, vi } from 'vitest'
import { notifyElapsedRecoveries } from '../src/emergency-sweep'
import { BASE, createSession, registerBody, registerUser } from './helpers'
import { actor, linkParams, type Mailbox, mailbox } from './org-helpers'

const PW = 'client-derived-hash'

const call = async (
  mb: Mailbox | null,
  path: string,
  init: { method?: string; body?: unknown; token?: string; form?: Record<string, string> } = {},
) => {
  const { default: app } = await import('../src/index')
  const headers: Record<string, string> = {}
  if (init.token) headers.Authorization = `Bearer ${init.token}`
  let body: string | undefined
  if (init.form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    body = new URLSearchParams(init.form).toString()
  } else if (init.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(init.body)
  }
  return app.fetch(
    new Request(`${BASE}${path}`, { method: init.method ?? 'POST', headers, body }),
    {
      ...env,
      ...(mb ? { EMAIL: mb.EMAIL, MAIL_FROM: mb.MAIL_FROM } : {}),
    },
  )
}

const loginWith = (mb: Mailbox | null, email: string, device: string, extra = {}) =>
  call(mb, '/identity/connect/token', {
    form: {
      grant_type: 'password',
      username: email,
      password: PW,
      scope: 'api offline_access',
      client_id: 'web',
      deviceType: '9',
      deviceName: `browser ${device}`,
      deviceIdentifier: device,
      ...extra,
    },
  })

const settle = (mb: Mailbox, count: number) =>
  vi.waitFor(() => expect(mb.sent.length).toBeGreaterThanOrEqual(count))
const code = (text: string) => /\b(\d{6})\b/.exec(text)?.[1] ?? ''
const row = (email: string) =>
  env.DB.prepare('SELECT * FROM users WHERE email = ?1').bind(email).first<Record<string, any>>()

it('password hint: mails the hint, answers the same for unknown addresses', async () => {
  const mb = mailbox()
  await registerUser('hint1@example.com')
  expect(
    (await call(mb, '/api/accounts/password-hint', { body: { email: 'hint1@example.com' } }))
      .status,
  ).toBe(200)
  await settle(mb, 1)
  expect(mb.sent[0]?.to).toBe('hint1@example.com')
  expect(mb.sent[0]?.text).toContain('Your hint: hint')

  const before = mb.sent.length
  const unknown = await call(mb, '/api/accounts/password-hint', {
    body: { email: 'nobody-hint@example.com' },
  })
  expect(unknown.status).toBe(200)
  expect(await unknown.text()).toBe('')
  await new Promise((r) => setTimeout(r, 50))
  expect(mb.sent.length).toBe(before)
})

it('password hint: an account without a hint is told so, and no mail transport is a clear error', async () => {
  const mb = mailbox()
  const reg = await call(null, '/identity/accounts/register', {
    body: registerBody('nohint@example.com', { masterPasswordHint: null }),
  })
  expect(reg.status).toBe(200)
  await call(mb, '/api/accounts/password-hint', { body: { email: 'nohint@example.com' } })
  await settle(mb, 1)
  expect(mb.sent[0]?.text).toContain('no hint set')
  const none = await call(null, '/api/accounts/password-hint', {
    body: { email: 'nohint@example.com' },
  })
  expect(none.status).toBe(400)
})

it('verify email: emailed link verifies the account once, stale links fail', async () => {
  const mb = mailbox()
  const s = await createSession('verify1@example.com')
  await env.DB.prepare('UPDATE users SET verified_at = NULL WHERE email = ?1')
    .bind('verify1@example.com')
    .run()
  expect((await call(mb, '/api/accounts/verify-email', { token: s.access_token })).status).toBe(200)
  await settle(mb, 1)
  const params = linkParams(mb.sent[0])
  expect(mb.sent[0]?.text).toContain('#/verify-email?')
  const userId = params.get('userId')
  const token = params.get('token')
  const bad = await call(null, '/api/accounts/verify-email-token', {
    body: { userId, token: 'x.y.z' },
  })
  expect(bad.status).toBe(400)
  const wrongUser = await call(null, '/api/accounts/verify-email-token', {
    body: { userId: crypto.randomUUID(), token },
  })
  expect(wrongUser.status).toBe(400)
  expect((await row('verify1@example.com'))?.verified_at).toBeNull()
  const ok = await call(null, '/api/accounts/verify-email-token', { body: { userId, token } })
  expect(ok.status).toBe(200)
  expect((await row('verify1@example.com'))?.verified_at).not.toBeNull()
})

it('verify email: refused when no mail can be sent', async () => {
  const s = await createSession('verify2@example.com')
  expect((await call(null, '/api/accounts/verify-email', { token: s.access_token })).status).toBe(
    400,
  )
})

it('request-otp and verify-otp: a code works once and wrong guesses burn it', async () => {
  const mb = mailbox()
  const s = await createSession('otp1@example.com')
  expect((await call(mb, '/api/accounts/request-otp', { token: s.access_token })).status).toBe(200)
  const c = code(mb.sent[0]?.text ?? '')
  expect(c).toHaveLength(6)
  const wrong = await call(null, '/api/accounts/verify-otp', {
    token: s.access_token,
    body: { OTP: c === '000000' ? '111111' : '000000' },
  })
  expect(wrong.status).toBe(400)
  expect(
    (await call(null, '/api/accounts/verify-otp', { token: s.access_token, body: { OTP: c } }))
      .status,
  ).toBe(200)
  expect(
    (await call(null, '/api/accounts/verify-otp', { token: s.access_token, body: { OTP: c } }))
      .status,
  ).toBe(400)

  await call(mb, '/api/accounts/request-otp', { token: s.access_token })
  const c2 = code(mb.sent[1]?.text ?? '')
  for (let i = 0; i < 5; i++) {
    await call(null, '/api/accounts/verify-otp', {
      token: s.access_token,
      body: { OTP: '999999' === c2 ? '888888' : '999999' },
    })
  }
  const spent = await call(null, '/api/accounts/verify-otp', {
    token: s.access_token,
    body: { OTP: c2 },
  })
  expect(spent.status).toBeGreaterThanOrEqual(400)
})

it('verify-devices needs proof and shows in the profile', async () => {
  const s = await createSession('vd1@example.com')
  const profile = async () =>
    (await (
      await call(null, '/api/accounts/profile', { method: 'GET', token: s.access_token })
    ).json()) as any
  expect((await profile()).verifyDevices).toBe(true)
  const bad = await call(null, '/api/accounts/verify-devices', {
    token: s.access_token,
    body: { masterPasswordHash: 'nope', verifyDevices: false },
  })
  expect(bad.status).toBe(400)
  const none = await call(null, '/api/accounts/verify-devices', {
    token: s.access_token,
    body: { verifyDevices: false },
  })
  expect(none.status).toBe(400)
  const ok = await call(null, '/api/accounts/verify-devices', {
    token: s.access_token,
    body: { masterPasswordHash: PW, verifyDevices: false },
  })
  expect(ok.status).toBe(200)
  expect((await profile()).verifyDevices).toBe(false)
})

it('new device: first login is free, later unknown devices need the emailed code', async () => {
  const mb = mailbox()
  await registerUser('nd1@example.com')
  expect((await loginWith(mb, 'nd1@example.com', 'dev-a')).status).toBe(200)
  await new Promise((r) => setTimeout(r, 30))
  expect(mb.sent.filter((m) => m.text.includes('new device'))).toHaveLength(0)

  const need = await loginWith(mb, 'nd1@example.com', 'dev-b')
  expect(need.status).toBe(400)
  const body = (await need.json()) as any
  expect(body.ErrorModel.Message).toBe('new device verification required')
  await settle(mb, 1)
  expect(mb.sent[0]?.subject).toBe('New device verification code')
  const c = code(mb.sent[0]?.text ?? '')

  const wrong = await loginWith(mb, 'nd1@example.com', 'dev-b', {
    newDeviceOtp: c === '123456' ? '654321' : '123456',
  })
  expect(wrong.status).toBe(400)
  expect(((await wrong.json()) as any).ErrorModel.Message).toBe('Invalid new device code.')
  const ok = await loginWith(mb, 'nd1@example.com', 'dev-b', { newDeviceOtp: c })
  expect(ok.status).toBe(200)
  // Spent: replaying it on another device fails.
  const replay = await loginWith(mb, 'nd1@example.com', 'dev-c', { newDeviceOtp: c })
  expect(replay.status).toBe(400)
  // A known device logs in again without a code.
  expect((await loginWith(mb, 'nd1@example.com', 'dev-b')).status).toBe(200)
})

it('new device: opting out skips the code but still sends a notice', async () => {
  const mb = mailbox()
  await registerUser('nd2@example.com')
  await loginWith(null, 'nd2@example.com', 'dev-a')
  await env.DB.prepare('UPDATE users SET verify_devices = 0 WHERE email = ?1')
    .bind('nd2@example.com')
    .run()
  expect(
    (await loginWith(mb, 'nd2@example.com', 'dev-z', { deviceType: '1', deviceName: 'phone' }))
      .status,
  ).toBe(200)
  await settle(mb, 1)
  expect(mb.sent[0]?.subject).toBe('New device logged in')
  expect(mb.sent[0]?.text).toContain('phone (iOS)')
})

it('new device: no mail transport means no code and no notice', async () => {
  await registerUser('nd3@example.com')
  await loginWith(null, 'nd3@example.com', 'dev-a')
  expect((await loginWith(null, 'nd3@example.com', 'dev-b')).status).toBe(200)
})

it('new device: accounts with two-step login use that instead of the email code', async () => {
  const mb = mailbox()
  await registerUser('nd4@example.com')
  await loginWith(null, 'nd4@example.com', 'dev-a')
  const u = await row('nd4@example.com')
  await env.DB.prepare(
    "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data) VALUES (?1, ?2, 0, 1, '{}')",
  )
    .bind(crypto.randomUUID(), u?.uuid)
    .run()
  const res = await loginWith(mb, 'nd4@example.com', 'dev-b')
  expect(res.status).toBe(400)
  expect(((await res.json()) as any).TwoFactorProviders2).toBeDefined()
  expect(mb.sent).toHaveLength(0)
})

it('two-step login changes and recovery code use are announced', async () => {
  const mb = mailbox()
  const s = await createSession('tf1@example.com')
  const u = await row('tf1@example.com')
  await env.DB.prepare(
    'INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data) VALUES (?1, ?2, 1, 1, \'{"email":"tf1@example.com"}\')',
  )
    .bind(crypto.randomUUID(), u?.uuid)
    .run()
  const off = await call(mb, '/api/two-factor/disable', {
    token: s.access_token,
    body: { masterPasswordHash: PW, type: 1 },
  })
  expect(off.status).toBe(200)
  await settle(mb, 1)
  expect(mb.sent[0]?.subject).toBe('Two-step login disabled')
  expect(mb.sent[0]?.text).toContain('email')

  await env.DB.prepare('UPDATE users SET totp_recover = ?1 WHERE email = ?2')
    .bind('A'.repeat(32), 'tf1@example.com')
    .run()
  const rec = await call(mb, '/api/two-factor/recover', {
    body: { email: 'tf1@example.com', masterPasswordHash: PW, recoveryCode: 'A'.repeat(32) },
  })
  expect(rec.status).toBe(200)
  await settle(mb, 2)
  expect(mb.sent[1]?.subject).toBe('Your recovery code was used')
})

it('email change: both addresses are told once it happens', async () => {
  const mb = mailbox()
  const a = await actor('chg-old@example.com', mb)
  expect(
    (
      await a.call('/api/accounts/email-token', 'POST', {
        newEmail: 'chg-new@example.com',
        masterPasswordHash: PW,
      })
    ).status,
  ).toBe(204)
  const token = code(mb.sent.at(-1)?.text ?? '')
  const before = mb.sent.length
  const res = await a.call('/api/accounts/email', 'POST', {
    newEmail: 'chg-new@example.com',
    masterPasswordHash: PW,
    newMasterPasswordHash: PW,
    token,
    key: '2.newKey',
  })
  expect(res.status).toBe(200)
  await settle(mb, before + 2)
  const added = mb.sent.slice(before)
  expect(added.find((m) => m.to === 'chg-old@example.com')?.text).toContain('chg-new@example.com')
  expect(added.find((m) => m.to === 'chg-new@example.com')?.subject).toBe(
    'Your account email address was changed',
  )
})

it('registration sends a welcome email', async () => {
  const mb = mailbox()
  const res = await call(mb, '/identity/accounts/register', {
    body: registerBody('welcome1@example.com'),
  })
  expect(res.status).toBe(200)
  await settle(mb, 1)
  expect(mb.sent[0]).toMatchObject({ to: 'welcome1@example.com' })
  expect(mb.sent[0]?.subject).toBe('Welcome to Cloudwarden')
  expect(mb.sent[0]?.text).toContain('https://vault.example.com')
})

it('emergency access notices: accepted, confirmed, approved, rejected', async () => {
  const mb = mailbox()
  const grantor = await actor('en-grantor@example.com', mb)
  const grantee = await actor('en-grantee@example.com', mb)
  await grantor.call('/api/emergency-access/invite', 'POST', {
    email: grantee.email,
    type: 0,
    waitTimeDays: 7,
  })
  await settle(mb, 1)
  const p = linkParams(mb.sent[0])
  const id = p.get('id') as string
  await grantee.call(`/api/emergency-access/${id}/accept`, 'POST', { token: p.get('token') })
  await settle(mb, 2)
  expect(mb.sent[1]).toMatchObject({ to: grantor.email })
  expect(mb.sent[1]?.subject).toContain('accepted')
  await grantor.call(`/api/emergency-access/${id}/confirm`, 'POST', { key: '4.k' })
  await settle(mb, 3)
  expect(mb.sent[2]).toMatchObject({ to: grantee.email })
  await grantee.call(`/api/emergency-access/${id}/initiate`, 'POST')
  await settle(mb, 4)
  expect(mb.sent[3]).toMatchObject({ to: grantor.email })
  await grantor.call(`/api/emergency-access/${id}/approve`, 'POST')
  await settle(mb, 5)
  expect(mb.sent[4]).toMatchObject({ to: grantee.email })
  expect(mb.sent[4]?.subject).toBe('Emergency access approved')
  await grantor.call(`/api/emergency-access/${id}/reject`, 'POST')
  await settle(mb, 6)
  expect(mb.sent[5]?.subject).toBe('Emergency access rejected')
})

it('emergency access: the sweep tells the contact once when the wait time has passed', async () => {
  const mb = mailbox()
  const grantor = await actor('sw-grantor@example.com', mb)
  const grantee = await actor('sw-grantee@example.com', mb)
  const id = crypto.randomUUID()
  const long = Date.now() - 2 * 24 * 3600 * 1000
  await env.DB.prepare(
    'INSERT INTO emergency_access (uuid, grantor_uuid, grantee_uuid, email, atype, status, wait_time_days, recovery_initiated_at, created_at, updated_at) VALUES (?1,?2,?3,?4,0,3,1,?5,?5,?5)',
  )
    .bind(id, grantor.uuid, grantee.uuid, grantee.email, long)
    .run()
  // Not yet due: a fresh request with a long wait.
  await env.DB.prepare(
    'INSERT INTO emergency_access (uuid, grantor_uuid, grantee_uuid, email, atype, status, wait_time_days, recovery_initiated_at, created_at, updated_at) VALUES (?1,?2,?3,?4,0,3,30,?5,?5,?5)',
  )
    .bind(crypto.randomUUID(), grantor.uuid, grantee.uuid, 'other@example.com', Date.now())
    .run()
  const testEnv = { ...env, EMAIL: mb.EMAIL, MAIL_FROM: mb.MAIL_FROM } as unknown as typeof env
  expect(await notifyElapsedRecoveries(testEnv)).toBe(1)
  expect(await notifyElapsedRecoveries(testEnv)).toBe(0)
  expect(mb.sent).toHaveLength(1)
  expect(mb.sent[0]?.to).toBe(grantee.email)
  expect(mb.sent[0]?.text).toContain('wait time')
})

it('organisation notices: owners hear about acceptance, the member about confirmation', async () => {
  const { createOrg, addMember } = await import('./org-helpers')
  const mb = mailbox()
  const owner = await actor('on-owner@example.com', mb)
  const member = await actor('on-member@example.com', mb)
  const org = await createOrg(owner)
  await addMember(owner, org.id, member, {}, mb)
  await vi.waitFor(() => {
    expect(mb.sent.some((m) => m.to === owner.email && m.subject.includes('accepted'))).toBe(true)
    expect(mb.sent.some((m) => m.to === member.email && m.subject.startsWith('You joined'))).toBe(
      true,
    )
  })
})

it('delete by email: link erases the account, unknown addresses look the same', async () => {
  const mb = mailbox()
  await registerUser('del1@example.com')
  expect(
    (await call(mb, '/api/accounts/delete-recover', { body: { email: 'del1@example.com' } }))
      .status,
  ).toBe(200)
  await settle(mb, 1)
  expect(mb.sent[0]?.text).toContain('#/verify-recover-delete?')
  const p = linkParams(mb.sent[0])
  const bad = await call(null, '/api/accounts/delete-recover-token', {
    body: { userId: p.get('userId'), token: 'a.b.c' },
  })
  expect(bad.status).toBe(400)
  expect(await row('del1@example.com')).not.toBeNull()
  const ok = await call(null, '/api/accounts/delete-recover-token', {
    body: { userId: p.get('userId'), token: p.get('token') },
  })
  expect(ok.status).toBe(200)
  expect(await row('del1@example.com')).toBeNull()

  const unknown = await call(mb, '/api/accounts/delete-recover', {
    body: { email: 'del-none@example.com' },
  })
  expect(unknown.status).toBe(200)
  await new Promise((r) => setTimeout(r, 30))
  expect(mb.sent).toHaveLength(1)
  expect(
    (await call(null, '/api/accounts/delete-recover', { body: { email: 'del1@example.com' } }))
      .status,
  ).toBe(400)
})

it('codes: five per hour per account, and spent guesses carry over a reissue', async () => {
  const mb = mailbox()
  const s = await createSession('otplim@example.com')
  for (let i = 0; i < 5; i++) {
    expect((await call(mb, '/api/accounts/request-otp', { token: s.access_token })).status).toBe(
      200,
    )
  }
  expect((await call(mb, '/api/accounts/request-otp', { token: s.access_token })).status).toBe(429)

  const s2 = await createSession('otplock@example.com')
  await call(mb, '/api/accounts/request-otp', { token: s2.access_token })
  for (let i = 0; i < 5; i++) {
    await call(null, '/api/accounts/verify-otp', {
      token: s2.access_token,
      body: { OTP: '000001' },
    })
  }
  expect((await call(mb, '/api/accounts/request-otp', { token: s2.access_token })).status).toBe(429)
})

it('new device: a locked-out account gets a clear refusal, not another code', async () => {
  const mb = mailbox()
  await registerUser('ndlock@example.com')
  await loginWith(null, 'ndlock@example.com', 'dev-a')
  await loginWith(mb, 'ndlock@example.com', 'dev-b')
  for (let i = 0; i < 5; i++)
    await loginWith(mb, 'ndlock@example.com', 'dev-b', { newDeviceOtp: '000001' })
  const res = await loginWith(mb, 'ndlock@example.com', 'dev-b')
  expect(res.status).toBe(400)
  expect(((await res.json()) as any).ErrorModel.Message).toContain('Too many')
  expect(mb.sent).toHaveLength(1)
})

it('delete by email: a changed security stamp voids the link', async () => {
  const mb = mailbox()
  await registerUser('delstamp@example.com')
  await call(mb, '/api/accounts/delete-recover', { body: { email: 'delstamp@example.com' } })
  await settle(mb, 1)
  const p = linkParams(mb.sent[0])
  await env.DB.prepare("UPDATE users SET security_stamp = 'rotated' WHERE email = ?1")
    .bind('delstamp@example.com')
    .run()
  const res = await call(null, '/api/accounts/delete-recover-token', {
    body: { userId: p.get('userId'), token: p.get('token') },
  })
  expect(res.status).toBe(400)
  expect(await row('delstamp@example.com')).not.toBeNull()
})

it('emergency sweep: a failed send is retried by the next sweep', async () => {
  const grantor = await actor('swf-grantor@example.com', mailbox())
  const grantee = await actor('swf-grantee@example.com', mailbox())
  await env.DB.prepare(
    'INSERT INTO emergency_access (uuid, grantor_uuid, grantee_uuid, email, atype, status, wait_time_days, recovery_initiated_at, created_at, updated_at) VALUES (?1,?2,?3,?4,0,3,1,?5,?5,?5)',
  )
    .bind(
      crypto.randomUUID(),
      grantor.uuid,
      grantee.uuid,
      grantee.email,
      Date.now() - 3 * 24 * 3600 * 1000,
    )
    .run()
  expect(await notifyElapsedRecoveries(env)).toBe(0)
  const mb = mailbox()
  const withMail = { ...env, EMAIL: mb.EMAIL, MAIL_FROM: mb.MAIL_FROM } as unknown as typeof env
  expect(await notifyElapsedRecoveries(withMail)).toBe(1)
})

it('subjects cannot carry line breaks', async () => {
  const { sendNotice } = await import('../src/email/send')
  const mb = mailbox()
  const withMail = { ...env, EMAIL: mb.EMAIL, MAIL_FROM: mb.MAIL_FROM } as unknown as typeof env
  await sendNotice(withMail, 'x@example.com', {
    subject: 'Hi\r\nBcc: evil@example.com',
    text: 't',
    html: 'h',
  })
  expect(mb.sent[0]?.subject).toBe('Hi Bcc: evil@example.com')
})
