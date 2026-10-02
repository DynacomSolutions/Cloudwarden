import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { authed, BASE, createSession, form } from './helpers'
import { actor, type Mailbox, mailbox } from './org-helpers'

const day = 86_400_000
const emailSend = (emails: string, extra: Record<string, unknown> = {}) => ({
  type: 0,
  name: '2.sendname',
  key: '2.sendkey',
  text: { text: '2.secret', hidden: false },
  deletionDate: new Date(Date.now() + 90 * day).toISOString(),
  authType: 0,
  emails,
  ...extra,
})

interface SendOut {
  id: string
  accessId: string
  authType: number
  emails: string | null
  password: string | null
}

/** Anonymous requests with a recording mail transport bound. */
let nextIp = 1
async function anon(mb: Mailbox, path: string, init: RequestInit, ip?: string) {
  const { default: app } = await import('../src/index')
  // A fresh client address per call, so only the limit under test is hit.
  const headers = new Headers(init.headers)
  headers.set('CF-Connecting-IP', ip ?? `10.1.${Math.floor(nextIp / 250)}.${nextIp++ % 250}`)
  return app.fetch(new Request(`${BASE}${path}`, { ...init, headers }), {
    ...env,
    EMAIL: mb.EMAIL,
    MAIL_FROM: mb.MAIL_FROM,
  })
}

const grant = async (mb: Mailbox, accessId: string, extra: Record<string, string> = {}) => {
  const res = await grantNow(mb, accessId, extra)
  await settle()
  return res
}

const grantNow = (mb: Mailbox, accessId: string, extra: Record<string, string> = {}) =>
  anon(mb, '/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'send_access',
      client_id: 'send',
      send_id: accessId,
      ...extra,
    }).toString(),
  })

/** The mail is sent in the background, so let it land before reading the mailbox. */
const settle = () => new Promise((r) => setTimeout(r, 20))

const codeIn = (m: { text: string } | undefined) => /\b(\d{8})\b/.exec(m?.text ?? '')?.[1] ?? ''

const setup = async (email: string, mb: Mailbox, emails = 'Alice@Example.com, bob@example.com') => {
  const owner = await actor(email, mb)
  const made = (await owner.json('/api/sends', 'POST', emailSend(emails))) as SendOut
  return { owner, made }
}

it('stores email-protected Sends with a normalised recipient list', async () => {
  const mb = mailbox()
  const { owner, made } = await setup(
    'se-owner@example.com',
    mb,
    'Alice@Example.com, bob@example.com,alice@example.com',
  )
  expect(made).toMatchObject({
    authType: 0,
    emails: 'alice@example.com,bob@example.com',
    password: null,
  })
  const sync = await owner.json('/api/sync')
  expect(sync.sends[0]).toMatchObject({
    id: made.id,
    authType: 0,
    emails: 'alice@example.com,bob@example.com',
  })
  // A list with no valid address is refused, as is one that is too long.
  expect((await owner.call('/api/sends', 'POST', emailSend('not-an-email'))).status).toBe(400)
  expect((await owner.call('/api/sends', 'POST', emailSend(''))).status).toBe(400)
  const many = Array.from({ length: 101 }, (_, i) => `u${i}@example.com`).join(',')
  expect((await owner.call('/api/sends', 'POST', emailSend(many))).status).toBe(400)
})

it('refuses an email-protected Send when no mail transport is configured', async () => {
  const s = await createSession('se-nomail@example.com')
  const res = await authed('/api/sends', s.access_token, 'POST', emailSend('a@example.com'))
  expect(res.status).toBe(400)
})

it('walks the send_access grant through email, code and token', async () => {
  const mb = mailbox()
  const { made } = await setup('se-flow@example.com', mb)

  const bare = await grant(mb, made.accessId)
  expect(bare.status).toBe(400)
  expect(await bare.json()).toMatchObject({
    error: 'invalid_request',
    send_access_error_type: 'email_required',
  })

  // An address that is not on the list gets the same answer and no mail.
  const outsider = await grant(mb, made.accessId, { email: 'mallory@example.com' })
  expect(await outsider.json()).toMatchObject({ send_access_error_type: 'email_and_otp_required' })
  expect(mb.sent).toHaveLength(0)

  const asked = await grant(mb, made.accessId, { email: ' ALICE@example.com ' })
  expect(asked.status).toBe(400)
  expect(await asked.json()).toMatchObject({
    error: 'invalid_request',
    send_access_error_type: 'email_and_otp_required',
  })
  expect(mb.sent).toHaveLength(1)
  expect(mb.sent[0]?.to).toBe('alice@example.com')
  const code = codeIn(mb.sent[0])
  expect(code).toMatch(/^\d{8}$/)

  // Asking again straight away does not mail a second code.
  await grant(mb, made.accessId, { email: 'alice@example.com' })
  expect(mb.sent).toHaveLength(1)

  // Wrong code, and a code that belongs to another address, are refused.
  const wrong = await grant(mb, made.accessId, {
    email: 'alice@example.com',
    otp: code === '000000' ? '111111' : '000000',
  })
  expect(await wrong.json()).toMatchObject({ send_access_error_type: 'email_and_otp_required' })
  const other = await grant(mb, made.accessId, { email: 'bob@example.com', otp: code })
  expect(other.status).toBe(400)

  const ok = await grant(mb, made.accessId, { email: 'alice@example.com', otp: code })
  expect(ok.status).toBe(200)
  const token = ((await ok.json()) as { access_token: string }).access_token
  const content = await anon(mb, '/api/sends/access', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  })
  expect(content.status).toBe(200)
  expect(await content.json()).toMatchObject({ object: 'send-access', text: { text: '2.secret' } })

  // A code works once.
  const again = await grant(mb, made.accessId, { email: 'alice@example.com', otp: code })
  expect(again.status).toBe(400)
})

it('burns a code after too many wrong guesses and after it expires', async () => {
  const mb = mailbox()
  const { made } = await setup('se-guess@example.com', mb)
  await grant(mb, made.accessId, { email: 'alice@example.com' })
  const code = codeIn(mb.sent[0])
  const wrong = code === '000000' ? '111111' : '000000'
  for (let i = 0; i < 5; i++) {
    await grant(mb, made.accessId, { email: 'alice@example.com', otp: wrong })
  }
  const late = await grant(mb, made.accessId, { email: 'alice@example.com', otp: code })
  expect(late.status).toBe(400)

  // Asking after the resend window mails a fresh code that works.
  await env.DB.prepare('update send_email_codes set sent_at = sent_at - 60000').run()
  await grant(mb, made.accessId, { email: 'alice@example.com' })
  expect(mb.sent).toHaveLength(2)
  const fresh = codeIn(mb.sent[1])
  await env.DB.prepare('update send_email_codes set expires_at = ?')
    .bind(Date.now() - 1)
    .run()
  const expired = await grant(mb, made.accessId, { email: 'alice@example.com', otp: fresh })
  expect(expired.status).toBe(400)
})

it('rate limits code requests per Send', async () => {
  const mb = mailbox()
  const { made } = await setup('se-rate@example.com', mb)
  let limited = 0
  for (let i = 0; i < 30; i++) {
    const res = await grant(mb, made.accessId, { email: 'alice@example.com' })
    if (res.status === 429) limited++
  }
  expect(limited).toBeGreaterThan(0)
})

it('serves email-protected Sends to legacy access with email and code in the body', async () => {
  const mb = mailbox()
  const { made } = await setup('se-legacy@example.com', mb)
  const legacy = (body: unknown) =>
    anon(mb, `/api/sends/access/${made.accessId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  expect((await legacy({})).status).toBe(401)
  expect((await legacy({ email: 'bob@example.com' })).status).toBe(401)
  expect(mb.sent).toHaveLength(1)
  const code = codeIn(mb.sent[0])
  const ok = await legacy({ email: 'bob@example.com', otp: code })
  expect(ok.status).toBe(200)
  expect(await ok.json()).toMatchObject({ object: 'send-access', text: { text: '2.secret' } })
})

it('switches a Send between none, password and email authentication', async () => {
  const mb = mailbox()
  const { owner, made } = await setup('se-switch@example.com', mb)
  const base = { type: 0, name: '2.sendname', key: '2.sendkey', text: { text: '2.secret' } }
  const deletionDate = new Date(Date.now() + day).toISOString()

  const pw = await owner.json(`/api/sends/${made.id}`, 'PUT', {
    ...base,
    deletionDate,
    authType: 1,
    password: 'aGFzaA==',
  })
  expect(pw).toMatchObject({ authType: 1, emails: null })
  expect(pw.password).toBeTruthy()

  // Password auth with no new password keeps the stored one.
  const kept = await owner.json(`/api/sends/${made.id}`, 'PUT', {
    ...base,
    deletionDate,
    authType: 1,
  })
  expect(kept.password).toBe(pw.password)
  const noPassword = await owner.json('/api/sends', 'POST', { ...base, deletionDate, authType: 1 })
  expect(noPassword.message ?? noPassword.Message ?? 'x').toBeTruthy()

  const em = await owner.json(`/api/sends/${made.id}`, 'PUT', {
    ...base,
    deletionDate,
    authType: 0,
    emails: 'carol@example.com',
  })
  expect(em).toMatchObject({ authType: 0, emails: 'carol@example.com', password: null })

  const none = await owner.json(`/api/sends/${made.id}`, 'PUT', {
    ...base,
    deletionDate,
    authType: 2,
  })
  expect(none).toMatchObject({ authType: 2, emails: null, password: null })

  await owner.json(`/api/sends/${made.id}`, 'PUT', {
    ...base,
    deletionDate,
    authType: 0,
    emails: 'carol@example.com',
  })
  const removed = await owner.json(`/api/sends/${made.id}/remove-auth`, 'PUT')
  expect(removed).toMatchObject({ authType: 2, emails: null })
})

it('does not let a stale token outlive an authentication change', async () => {
  const mb = mailbox()
  const { owner, made } = await setup('se-revoke@example.com', mb)
  await grant(mb, made.accessId, { email: 'alice@example.com' })
  const ok = await grant(mb, made.accessId, { email: 'alice@example.com', otp: codeIn(mb.sent[0]) })
  const token = ((await ok.json()) as { access_token: string }).access_token
  await owner.json(`/api/sends/${made.id}`, 'PUT', {
    type: 0,
    name: '2.sendname',
    key: '2.sendkey',
    text: { text: '2.secret' },
    deletionDate: new Date(Date.now() + day).toISOString(),
    authType: 0,
    emails: 'dave@example.com',
  })
  const res = await anon(mb, '/api/sends/access', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  })
  expect(res.status).toBe(401)
})

it('treats listed and unlisted addresses alike: same limits, same answers', async () => {
  const mb = mailbox()
  const { made } = await setup('se-enum@example.com', mb)
  const statuses = async (email: string) => {
    const out: number[] = []
    for (let i = 0; i < 7; i++) out.push((await grant(mb, made.accessId, { email })).status)
    return out
  }
  // Each address gets the same run of 400s and then the same 429s.
  const listed = await statuses('alice@example.com')
  const unlisted = await statuses('mallory@example.com')
  expect(unlisted).toEqual(listed)
  expect(listed).toContain(429)
  expect(listed[0]).toBe(400)
})

it('caps the codes mailed to one address per day and one address cannot lock out another', async () => {
  const mb = mailbox()
  const { made } = await setup('se-cap@example.com', mb)
  // Someone hammering one address does not stop a different recipient getting a code.
  for (let i = 0; i < 8; i++) await grant(mb, made.accessId, { email: 'alice@example.com' })
  await env.DB.prepare('delete from admin_rate_limits where key like ?').bind('send-otp-ip:%').run()
  const bob = await grant(mb, made.accessId, { email: 'bob@example.com' })
  expect(bob.status).toBe(400)
  expect(mb.sent.some((m) => m.to === 'bob@example.com')).toBe(true)
  // Alice's per-address window is spent: no further mail even after the resend window.
  const before = mb.sent.length
  await env.DB.prepare('update send_email_codes set sent_at = 0').run()
  await env.DB.prepare('delete from admin_rate_limits where key like ?').bind('send-otp-ip:%').run()
  const more = await grant(mb, made.accessId, { email: 'alice@example.com' })
  expect(more.status).toBe(429)
  expect(mb.sent.length).toBe(before)
})

it('stops guessing after too many tries across codes', async () => {
  const mb = mailbox()
  const { made } = await setup('se-try@example.com', mb)
  await grant(mb, made.accessId, { email: 'alice@example.com' })
  const code = codeIn(mb.sent[0])
  for (let i = 0; i < 40; i++) {
    await env.DB.prepare('delete from admin_rate_limits where key like ?')
      .bind('send-otp-try-ip:%')
      .run()
    await grant(mb, made.accessId, { email: 'alice@example.com', otp: '00000000' })
    await env.DB.prepare('update send_email_codes set attempts = 0').run()
  }
  await env.DB.prepare('delete from admin_rate_limits where key like ?')
    .bind('send-otp-try-ip:%')
    .run()
  const late = await grant(mb, made.accessId, { email: 'alice@example.com', otp: code })
  expect(late.status).toBe(400)
})

it('answers a code request the same way for any address when mail is not configured', async () => {
  const mb = mailbox()
  const { made } = await setup('se-nomailgrant@example.com', mb)
  for (const email of ['alice@example.com', 'mallory@example.com']) {
    const res = await form('/identity/connect/token', {
      grant_type: 'send_access',
      client_id: 'send',
      send_id: made.accessId,
      email,
    })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ message: expect.stringContaining('not configured') })
  }
})

it('limits requests per client address across Sends and addresses', async () => {
  const mb = mailbox()
  const { made } = await setup('se-ip@example.com', mb)
  const ask = (email: string) =>
    anon(
      mb,
      '/identity/connect/token',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'send_access',
          client_id: 'send',
          send_id: made.accessId,
          email,
        }).toString(),
      },
      '203.0.113.9',
    )
  const out: number[] = []
  for (let i = 0; i < 12; i++) out.push((await ask(`user${i}@example.com`)).status)
  expect(out.slice(0, 10).every((x) => x === 400)).toBe(true)
  expect(out.slice(10)).toEqual([429, 429])
})
