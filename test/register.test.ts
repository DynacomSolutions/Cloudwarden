import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { json, registerBody, registerUser, withEnv } from './helpers'
import { mailbox } from './org-helpers'

const asJson = (body: unknown) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

it.each(['/identity/accounts/register', '/api/accounts/register'])(
  'registers via %s',
  async (path) => {
    const email = `reg${path.length}@example.com`
    const res = await json(path, registerBody(email))
    expect(res.status).toBe(200)
    const row = await env.DB.prepare('select * from users where email = ?')
      .bind(email)
      .first<Record<string, unknown>>()
    expect(row?.akey).toBe('2.encryptedSymmetricKey')
    expect(row?.public_key).toBe('public-key')
    // The client hash is never stored as sent.
    expect(row?.password_hash).not.toBe('client-derived-hash')
    expect(row?.password_iterations).toBe(100000)
  },
)

it('stores email lowercased and rejects duplicates', async () => {
  expect((await registerUser('Dup@Example.com')).status).toBe(200)
  const again = await registerUser('dup@example.com')
  expect(again.status).toBe(400)
  expect(await again.json()).toMatchObject({ object: 'error' })
})

it('accepts the finish-flow payload shape', async () => {
  const res = await json('/identity/accounts/register/finish', {
    email: 'finish@example.com',
    masterPasswordHash: 'h',
    userSymmetricKey: '2.k',
    userAsymmetricKeys: { publicKey: 'p', encryptedPrivateKey: '2.pk' },
    kdf: 0,
    kdfIterations: 600000,
  })
  expect(res.status).toBe(200)
})

it('accepts PascalCase keys', async () => {
  const res = await json('/identity/accounts/register', {
    Email: 'pascal@example.com',
    MasterPasswordHash: 'h',
    Key: '2.k',
    Keys: { PublicKey: 'p', EncryptedPrivateKey: '2.pk' },
    Kdf: 0,
    KdfIterations: 600000,
  })
  expect(res.status).toBe(200)
})

it('validates input', async () => {
  expect((await json('/identity/accounts/register', { email: 'x' })).status).toBe(400)
  const noKey = await json('/identity/accounts/register', {
    email: 'nk@example.com',
    masterPasswordHash: 'h',
  })
  expect(noKey.status).toBe(400)
  const lowIter = await registerUser('low@example.com', { kdfIterations: 100 })
  expect(lowIter.status).toBe(400)
  const badArgon = await registerUser('ba@example.com', { kdf: 1, kdfIterations: 3 })
  expect(badArgon.status).toBe(400)
})

it('refuses registration when signups are closed', async () => {
  const res = await withEnv(
    { SIGNUPS_ALLOWED: 'false' },
    '/identity/accounts/register',
    asJson(registerBody('closed@example.com')),
  )
  expect(res.status).toBe(400)
})

it('allows whitelisted domains and addresses when closed, with a verification token', async () => {
  const over = {
    SIGNUPS_ALLOWED: 'false',
    SIGNUPS_DOMAINS_WHITELIST: 'corp.example.com, boss@other.example.com',
  }
  // Whitelisting alone is not proof of mailbox control.
  const bare = await withEnv(
    over,
    '/identity/accounts/register',
    asJson(registerBody('a@corp.example.com')),
  )
  expect(bare.status).toBe(400)
  const ok = await withEnv(
    over,
    '/identity/accounts/register',
    asJson(
      registerBody('a@corp.example.com', {
        emailVerificationToken: await tokenFor(over, 'a@corp.example.com'),
      }),
    ),
  )
  expect(ok.status).toBe(200)
  const exact = await withEnv(
    over,
    '/identity/accounts/register',
    asJson(
      registerBody('boss@other.example.com', {
        emailVerificationToken: await tokenFor(over, 'boss@other.example.com'),
      }),
    ),
  )
  expect(exact.status).toBe(200)
  const no = await withEnv(
    over,
    '/identity/accounts/register',
    asJson(registerBody('c@other.example.com')),
  )
  expect(no.status).toBe(400)
})

it('send-verification-email returns a token usable by register/finish', async () => {
  const closed = { SIGNUPS_ALLOWED: 'false', SIGNUPS_DOMAINS_WHITELIST: 'corp.example.com' }
  const send = await withEnv(
    closed,
    '/identity/accounts/register/send-verification-email',
    asJson({ email: 'v@corp.example.com', name: 'Vee' }),
  )
  expect(send.status).toBe(200)
  const token = (await send.json()) as string
  const finish = await withEnv(
    closed,
    '/identity/accounts/register/finish',
    asJson({
      email: 'v@corp.example.com',
      emailVerificationToken: token,
      masterPasswordHash: 'h',
      userSymmetricKey: '2.k',
      kdf: 0,
      kdfIterations: 600000,
    }),
  )
  expect(finish.status).toBe(200)
  const row = await env.DB.prepare('select name from users where email = ?')
    .bind('v@corp.example.com')
    .first<{ name: string }>()
  expect(row?.name).toBe('Vee')

  // The token is bound to its address and cannot open registration for another one.
  const other = await withEnv(
    closed,
    '/identity/accounts/register/finish',
    asJson({
      email: 'w@elsewhere.example.com',
      emailVerificationToken: token,
      masterPasswordHash: 'h',
      userSymmetricKey: '2.k',
    }),
  )
  expect(other.status).toBe(400)
})

it('send-verification-email refuses disallowed addresses', async () => {
  const res = await withEnv(
    { SIGNUPS_ALLOWED: 'false' },
    '/identity/accounts/register/send-verification-email',
    asJson({ email: 'z@example.com' }),
  )
  expect(res.status).toBe(400)
})

it('lets an invited address register while signups are closed, then consumes the invitation', async () => {
  // With mail on the emailed link proves the mailbox (without mail an invite code does, see emailless.test.ts).
  const mb = mailbox()
  const closed = { SIGNUPS_ALLOWED: 'false', EMAIL: mb.EMAIL, MAIL_FROM: mb.MAIL_FROM }
  await env.DB.prepare(
    'insert into invitations (uuid, email, invited_by, created_at) values (?,?,?,?)',
  )
    .bind('inv-1', 'Invited@Example.com', 'admin', Date.now())
    .run()
  const bare = await withEnv(
    closed,
    '/identity/accounts/register',
    asJson(registerBody('invited@example.com')),
  )
  expect(bare.status).toBe(400)
  const ok = await withEnv(
    closed,
    '/identity/accounts/register',
    asJson(
      registerBody('invited@example.com', {
        emailVerificationToken: await emailedToken(closed, mb, 'invited@example.com'),
      }),
    ),
  )
  expect(ok.status).toBe(200)
  const left = await env.DB.prepare('select count(*) n from invitations where uuid = ?')
    .bind('inv-1')
    .first<{ n: number }>()
  expect(left?.n).toBe(0)
  const again = await withEnv(
    closed,
    '/identity/accounts/register',
    asJson(registerBody('uninvited@example.com')),
  )
  expect(again.status).toBe(400)
})

/** The mailbox proof with mail on: the token is in the emailed link, never in the response. */
const emailedToken = async (
  over: Record<string, unknown>,
  mb: ReturnType<typeof mailbox>,
  email: string,
) => {
  const res = await withEnv(
    over,
    '/identity/accounts/register/send-verification-email',
    asJson({ email, name: 'Tess' }),
  )
  expect(res.status).toBe(204)
  const last = mb.sent[mb.sent.length - 1]
  return new URLSearchParams(
    (/https?:\/\/\S+/.exec(last?.text ?? '')?.[0] ?? '').split('?')[1],
  ).get('token') as string
}

/** The mailbox proof: with no mail transport the token comes straight back. */
const tokenFor = async (over: Record<string, unknown>, email: string) => {
  const res = await withEnv(
    over,
    '/identity/accounts/register/send-verification-email',
    asJson({ email, name: 'Tess' }),
  )
  expect(res.status).toBe(200)
  return (await res.json()) as string
}

it('never lets an admin address register without proof, even with signups open or an invitation', async () => {
  const admin = { ADMIN_ENABLED: 'true', ADMIN_EMAILS: 'boss@example.com' }
  const open = { ...admin, SIGNUPS_ALLOWED: 'true' }
  const bare = await withEnv(
    open,
    '/identity/accounts/register',
    asJson(registerBody('boss@example.com')),
  )
  expect(bare.status).toBe(400)
  // A pending invitation does not change that.
  await env.DB.prepare(
    'insert into invitations (uuid, email, invited_by, created_at) values (?,?,?,?)',
  )
    .bind('inv-admin', 'boss@example.com', 'x', Date.now())
    .run()
  const closed = { ...admin, SIGNUPS_ALLOWED: 'false' }
  const invited = await withEnv(
    closed,
    '/identity/accounts/register',
    asJson(registerBody('boss@example.com')),
  )
  expect(invited.status).toBe(400)
  // Without a mail transport the token would prove nothing, so none is issued.
  const send = await withEnv(
    open,
    '/identity/accounts/register/send-verification-email',
    asJson({ email: 'boss@example.com' }),
  )
  expect(send.status).toBe(400)
  const none = await env.DB.prepare(
    "select count(*) n from users where email = 'boss@example.com'",
  ).first<{ n: number }>()
  expect(none?.n).toBe(0)
})

it('accepts an admin address that proves the mailbox through the emailed token', async () => {
  const sent: { to: string; text: string }[] = []
  const over = {
    ADMIN_ENABLED: 'true',
    ADMIN_EMAILS: 'chief@example.com',
    SIGNUPS_ALLOWED: 'true',
    EMAIL: { send: async (m: { to: string; text: string }) => void sent.push(m) },
    MAIL_FROM: 'Cloudwarden <noreply@example.com>',
  }
  const send = await withEnv(
    over,
    '/identity/accounts/register/send-verification-email',
    asJson({ email: 'chief@example.com' }),
  )
  expect(send.status).toBe(204)
  const token = new URLSearchParams(
    (/https?:\/\/\S+/.exec(sent[0]?.text ?? '')?.[0] ?? '').split('?')[1],
  ).get('token')
  const ok = await withEnv(
    over,
    '/identity/accounts/register',
    asJson(registerBody('chief@example.com', { emailVerificationToken: token })),
  )
  expect(ok.status).toBe(200)
})

const mailer = () => {
  const sent: { to: string; text: string }[] = []
  return {
    sent,
    EMAIL: { send: async (m: { to: string; text: string }) => void sent.push(m) },
    MAIL_FROM: 'Cloudwarden <noreply@example.com>',
  }
}

it('emails the verification link and returns 204 when a transport is configured', async () => {
  const m = mailer()
  const res = await withEnv(
    { EMAIL: m.EMAIL, MAIL_FROM: m.MAIL_FROM },
    '/identity/accounts/register/send-verification-email',
    asJson({ email: 'mail@example.com', name: 'M' }),
  )
  expect(res.status).toBe(204)
  expect(m.sent).toHaveLength(1)
  expect(m.sent[0]?.to).toBe('mail@example.com')
  expect(m.sent[0]?.text).toContain('finish-signup')
})

it('emails the email-change code to the new address', async () => {
  const { createSession } = await import('./helpers')
  const s = await createSession('chg@example.com')
  const m = mailer()
  const { default: app } = await import('../src/index')
  const res = await app.fetch(
    new Request(`https://vault.example.com/api/accounts/email-token`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${s.access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        newEmail: 'chg2@example.com',
        masterPasswordHash: 'client-derived-hash',
      }),
    }),
    { ...env, EMAIL: m.EMAIL, MAIL_FROM: m.MAIL_FROM },
  )
  expect(res.status).toBe(204)
  const row = await env.DB.prepare('select email_new_token t from users where email = ?')
    .bind('chg@example.com')
    .first<{ t: string }>()
  expect(m.sent[0]?.to).toBe('chg2@example.com')
  expect(m.sent[0]?.text).toContain(row?.t as string)
})

it('verification-email-clicked validates the token', async () => {
  const send = await json('/identity/accounts/register/send-verification-email', {
    email: 'click@example.com',
  })
  const token = (await send.json()) as string
  const clicked = (email: string, emailVerificationToken: string) =>
    json('/identity/accounts/register/verification-email-clicked', {
      email,
      emailVerificationToken,
    })
  expect((await clicked('click@example.com', token)).status).toBe(200)
  expect((await clicked('Click@Example.com', token)).status).toBe(200)
  expect((await clicked('other@example.com', token)).status).toBe(400)
  expect((await clicked('click@example.com', 'garbage')).status).toBe(400)
  expect((await registerUser('click@example.com')).status).toBe(200)
  expect((await clicked('click@example.com', token)).status).toBe(400)
})
