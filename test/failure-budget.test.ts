import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { generateTotpKey, totpAt } from '../src/auth/totp'
import { clock } from '../src/auth/twofactor'
import { authed, createSession, json, login, registerUser } from './helpers'

const PW = 'client-derived-hash'

it('locks the password grant after the budget and resets on success', async () => {
  await registerUser('budget-pw@example.com')
  for (let i = 0; i < 9; i++) expect((await login('budget-pw@example.com', 'bad')).status).toBe(400)
  expect((await login('budget-pw@example.com', PW)).status).toBe(200) // success resets
  for (let i = 0; i < 10; i++)
    expect((await login('budget-pw@example.com', 'bad')).status).toBe(400)
  expect((await login('budget-pw@example.com', 'bad')).status).toBe(429)
  expect((await login('budget-pw@example.com', PW)).status).toBe(429)
})

it('treats unknown accounts like known ones', async () => {
  for (let i = 0; i < 10; i++)
    expect((await login('budget-nobody@example.com', 'x')).status).toBe(400)
  expect((await login('budget-nobody@example.com', 'x')).status).toBe(429)
})

it('does not let parallel password attempts exceed the budget', async () => {
  await registerUser('budget-par@example.com')
  const res = await Promise.all(
    Array.from({ length: 25 }, () => login('budget-par@example.com', 'bad')),
  )
  const statuses = res.map((r) => r.status)
  expect(statuses.filter((s) => s === 400)).toHaveLength(10)
  expect(statuses.filter((s) => s === 429)).toHaveLength(15)
})

it('locks TOTP guesses per user and resets on success', async () => {
  const email = 'budget-totp@example.com'
  const s = await createSession(email)
  const key = generateTotpKey()
  const got = await authed('/api/two-factor/get-authenticator', s.access_token, 'POST', {
    masterPasswordHash: PW,
  })
  const code = (await totpAt(key, clock.now())) as string
  await authed('/api/two-factor/authenticator', s.access_token, 'PUT', {
    key,
    token: code,
    userVerificationToken: ((await got.json()) as any).userVerificationToken,
  })
  const guess = (token: string) =>
    login(email, PW, { twoFactorProvider: '0', twoFactorToken: token })
  for (let i = 0; i < 10; i++) expect((await guess('000000')).status).toBe(400)
  expect((await guess('000000')).status).toBe(429)
  const user = await env.DB.prepare('SELECT uuid FROM users WHERE email = ?1')
    .bind(email)
    .first<{ uuid: string }>()
  await env.DB.prepare('DELETE FROM admin_rate_limits WHERE key = ?1')
    .bind(`tffail:${user?.uuid}`)
    .run()
  const next = (await totpAt(key, clock.now() + 30_000)) as string
  clock.now = () => Date.now() + 30_000
  try {
    expect((await guess(next)).status).toBe(200)
  } finally {
    clock.now = () => Date.now()
  }
  const row = await env.DB.prepare('SELECT count(*) AS n FROM admin_rate_limits WHERE key = ?1')
    .bind(`tffail:${user?.uuid}`)
    .first<{ n: number }>()
  expect(row?.n).toBe(0)
})

it('caps push-creating auth requests per target, with an identical response', async () => {
  const email = 'budget-ar@example.com'
  await registerUser(email)
  const create = () =>
    json('/api/auth-requests', {
      email,
      deviceIdentifier: 'd',
      publicKey: 'pub',
      type: 0,
      accessCode: 'c',
    })
  const shapes: string[] = []
  for (let i = 0; i < 7; i++) {
    const res = await create()
    expect(res.status).toBe(200)
    shapes.push(Object.keys((await res.json()) as object).join())
  }
  expect(new Set(shapes).size).toBe(1)
  const count = await env.DB.prepare(
    "SELECT count(*) AS n FROM auth_requests WHERE user_uuid IS NOT NULL AND request_device_identifier = 'd'",
  ).first<{ n: number }>()
  expect(count?.n).toBe(5)
})
