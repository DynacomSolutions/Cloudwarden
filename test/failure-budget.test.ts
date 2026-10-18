import { env } from 'cloudflare:workers'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { generateTotpKey, totpAt } from '../src/auth/totp'
import { clock } from '../src/auth/twofactor'
import { FAILURE_WINDOW_MS } from '../src/ratelimit'
import { authed, createSession, json, login, registerUser } from './helpers'

const PW = 'client-derived-hash'

// Pin Date early in a budget window so the 15 minute fixed window cannot roll over mid-test.
beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] })
  vi.setSystemTime(Math.floor(Date.now() / FAILURE_WINDOW_MS) * FAILURE_WINDOW_MS + 60_000)
})
afterEach(() => vi.useRealTimers())

it('runs the Worker under the pinned clock', async () => {
  // Proves the fake Date reaches the code under test: a pin far from real time shows up in the
  // stored window. (Token validity does not matter for a failed password login.)
  const pinned = Date.UTC(2031, 0, 1, 0, 1)
  vi.setSystemTime(pinned)
  expect((await login('budget-clock@example.com', 'bad')).status).toBe(400)
  const row = await env.DB.prepare('SELECT window_start FROM admin_rate_limits WHERE key = ?1')
    .bind('pwfail:budget-clock@example.com')
    .first<{ window_start: number }>()
  expect(row?.window_start).toBe(Math.floor(pinned / FAILURE_WINDOW_MS) * FAILURE_WINDOW_MS)
})

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

it('caps push-sending auth requests per target, with an identical response', async () => {
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
  expect(count?.n).toBe(7)
})

it('does not block an approved login-with-device when the password budget is exhausted', async () => {
  const email = 'budget-dev@example.com'
  const s = await createSession(email)
  for (let i = 0; i < 10; i++) await login(email, 'bad', { deviceIdentifier: 'attacker' })
  expect((await login(email, 'bad')).status).toBe(429)
  const created = (await (
    await json('/api/auth-requests/', {
      email,
      deviceIdentifier: 'new-device',
      publicKey: 'pub',
      type: 0,
      accessCode: 'code-1',
    })
  ).json()) as { id: string }
  await authed(`/api/auth-requests/${created.id}`, s.access_token, 'PUT', {
    key: 'k',
    masterPasswordHash: 'h',
    deviceIdentifier: 'device-1',
    requestApproved: true,
  })
  const res = await login(email, 'code-1', {
    authRequest: created.id,
    deviceIdentifier: 'new-device',
  })
  expect(res.status).toBe(200)
})

it('keeps over-budget login-with-device requests approvable', async () => {
  const email = 'budget-over@example.com'
  const s = await createSession(email)
  const create = async () =>
    (await (
      await json('/api/auth-requests/', {
        email,
        deviceIdentifier: 'new-device',
        publicKey: 'pub',
        type: 0,
        accessCode: 'code-1',
      })
    ).json()) as { id: string }
  for (let i = 0; i < 5; i++) await create()
  const sixth = await create()
  const put = await authed(`/api/auth-requests/${sixth.id}`, s.access_token, 'PUT', {
    key: 'k',
    masterPasswordHash: 'h',
    deviceIdentifier: 'device-1',
    requestApproved: true,
  })
  expect(put.status).toBe(200)
  const res = await login(email, 'code-1', {
    authRequest: sixth.id,
    deviceIdentifier: 'new-device',
  })
  expect(res.status).toBe(200)
})
