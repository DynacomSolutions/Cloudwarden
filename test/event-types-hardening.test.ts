// Event writes off the request path: a failed or slow event write never changes a response.
import { env } from 'cloudflare:workers'
import { afterEach, expect, it } from 'vitest'
import { createDb, schema } from '../src/db'
import { authed, BASE, createSession, freezeRateLimitWindow, login, waitFor } from './helpers'
import { actor, addMember, createOrg, enableRecoveryPolicy } from './org-helpers'

type Stmt = {
  sql: string
  real: D1PreparedStatement
  bind(...v: unknown[]): Stmt
  all(): Promise<unknown>
  run(): Promise<unknown>
  first(c?: string): Promise<unknown>
  raw(o?: unknown): Promise<unknown>
}

/**
 * A D1 binding that records the SQL of every statement it runs. Statements that match `gated`
 * wait for `release()` before they run, so a test can tell whether a response waited for them.
 */
function spyDb(gated: RegExp | null) {
  let open!: () => void
  const gate = new Promise<void>((r) => {
    open = r
  })
  const log: string[] = []
  const done: string[] = []
  const isGated = (sql: string) => gated?.test(sql) ?? false
  const wrap = (sql: string, real: D1PreparedStatement): Stmt => {
    const run = async <T>(fn: () => Promise<T>) => {
      log.push(sql)
      if (isGated(sql)) await gate
      const out = await fn()
      done.push(sql)
      return out
    }
    return {
      sql,
      real,
      bind: (...v) => wrap(sql, real.bind(...v)),
      all: () => run(() => real.all()),
      run: () => run(() => real.run()),
      first: (c) => run(() => real.first(c as never)),
      raw: (o) => run(() => real.raw(o as never)),
    }
  }
  const db = {
    prepare: (sql: string) => wrap(sql, env.DB.prepare(sql)),
    batch: async (stmts: Stmt[]) => {
      for (const s of stmts) log.push(s.sql)
      if (stmts.some((s) => isGated(s.sql))) await gate
      const out = await env.DB.batch(stmts.map((s) => s.real))
      for (const s of stmts) done.push(s.sql)
      return out
    },
    exec: (sql: string) => env.DB.exec(sql),
    dump: () => env.DB.dump(),
  } as unknown as D1Database
  return { db, log, done, release: open }
}

/** Calls the app with a spying database and a context that collects the deferred work. */
async function call(db: D1Database, path: string, init: RequestInit, ip = '10.9.0.1') {
  const { default: app } = await import('../src/index')
  const deferred: Promise<unknown>[] = []
  const ctx = {
    waitUntil: (p: Promise<unknown>) => void deferred.push(p.catch(() => undefined)),
    passThroughOnException() {},
  } as unknown as ExecutionContext
  const headers = new Headers(init.headers)
  headers.set('CF-Connecting-IP', ip)
  const res = await app.fetch(
    new Request(`${BASE}${path}`, { ...init, headers }),
    { ...env, DB: db },
    ctx,
  )
  return { res, settle: () => Promise.all(deferred) }
}

const loginForm = (email: string, password: string, extra: Record<string, string> = {}) => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'password',
    username: email,
    password,
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceName: 'chrome',
    deviceIdentifier: 'device-h',
    ...extra,
  }).toString(),
})

const EVENT_SQL = /insert into "events"|from "users_organizations"/i
const within = <T>(p: Promise<T>, what: string) =>
  Promise.race([
    p,
    new Promise<never>((_, rej) =>
      setTimeout(() => rej(new Error(`${what} waited for an event write`)), 5000),
    ),
  ])

const countOf = async (type: number, userUuid?: string) =>
  (
    await env.DB.prepare(
      `select count(*) n from events where event_type = ?1 ${userUuid ? 'and user_uuid = ?2' : ''}`,
    )
      .bind(...(userUuid ? [type, userUuid] : [type]))
      .first<{ n: number }>()
  )?.n ?? 0

const failEvents = () =>
  env.DB.exec(
    "create trigger fail_events before insert on events begin select raise(abort, 'events are down'); end",
  )
afterEach(() => env.DB.exec('drop trigger if exists fail_events'))

it('answers a failed login without waiting for the event, the same for known and unknown accounts', async () => {
  await createSession('hd-known@example.com')
  const known = spyDb(EVENT_SQL)
  const unknown = spyDb(EVENT_SQL)
  const a = await within(
    call(known.db, '/identity/connect/token', loginForm('hd-known@example.com', 'wrong')),
    'known account',
  )
  const b = await within(
    call(unknown.db, '/identity/connect/token', loginForm('hd-nobody@example.com', 'wrong')),
    'unknown account',
  )
  expect(a.res.status).toBe(400)
  expect(b.res.status).toBe(400)
  // Every statement the response waited for is the same; the event work is not among them.
  expect(known.done).toEqual(unknown.done)
  known.release()
  await a.settle()
  await waitFor(async () => (await countOf(1005)) >= 1 || false)
})

const idOf = async (token: string) =>
  ((await (await authed('/api/accounts/profile', token)).json()) as { id: string }).id

it('does not record a failed login for a bad login-with-device request', async () => {
  const s = await createSession('hd-device@example.com')
  const id = await idOf(s.access_token)
  const spy = spyDb(null)
  const settles: (() => Promise<unknown>)[] = []
  for (let i = 0; i < 50; i++) {
    const r = await call(
      spy.db,
      '/identity/connect/token',
      loginForm('hd-device@example.com', 'access-code', { authRequest: crypto.randomUUID() }),
      `10.9.1.${i + 1}`,
    )
    expect(r.res.status).toBe(400)
    settles.push(r.settle)
  }
  await Promise.all(settles.map((f) => f()))
  expect(await countOf(1005, id)).toBe(0)
})

it('keeps one 1005 row for one bad master password', async () => {
  const s = await createSession('hd-pw@example.com')
  const id = await idOf(s.access_token)
  expect((await login('hd-pw@example.com', 'wrong')).status).toBe(400)
  await waitFor(async () => (await countOf(1005, id)) === 1 || false)
})

it('signs in even when the event write fails', async () => {
  await createSession('hd-login@example.com')
  await failEvents()
  const r = await call(
    spyDb(null).db,
    '/identity/connect/token',
    loginForm('hd-login@example.com', 'client-derived-hash'),
  )
  expect(r.res.status).toBe(200)
  expect(((await r.res.json()) as { access_token?: string }).access_token).toBeTruthy()
  await r.settle()
})

it('lets a Send be accessed when the event write fails', async () => {
  const s = await createSession('hd-send@example.com')
  const made = await authed('/api/sends', s.access_token, 'POST', {
    type: 0,
    name: '2.n',
    key: '2.k',
    text: { text: '2.t', hidden: false },
    maxAccessCount: 1,
    deletionDate: new Date(Date.now() + 86_400_000).toISOString(),
    disabled: false,
  })
  const send = (await made.json()) as { accessId: string }
  await failEvents()
  const r = await call(spyDb(null).db, `/api/sends/access/${send.accessId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  })
  expect(r.res.status).toBe(200)
  expect(((await r.res.json()) as { text?: unknown }).text).toBeTruthy()
  await r.settle()
})

it('does not wait for the event when an administrator opens the organisation vault', async () => {
  const owner = await actor('hd-vault-owner@example.com')
  const { id: orgId } = await createOrg(owner)
  const spy = spyDb(/insert into "events"/i)
  const r = await within(
    call(spy.db, `/api/ciphers/organization-details?organizationId=${orgId}`, {
      headers: { Authorization: `Bearer ${owner.token}` },
    }),
    'vault listing',
  )
  expect(r.res.status).toBe(200)
  spy.release()
  await r.settle()
  expect(await countOf(1603)).toBe(1)
})

it('records the vault export (1007) with the server time and an organisation copy', async () => {
  const owner = await actor('hd-export-owner@example.com')
  const member = await actor('hd-export-member@example.com')
  const { id: orgId } = await createOrg(owner)
  await addMember(owner, orgId, member)
  const before = Date.now()
  const res = await member.call('/events/collect', 'POST', [
    { type: 1007, date: '2001-01-01T00:00:00.000Z' },
  ])
  expect(res.status).toBe(200)
  const own = await member.json('/api/events')
  const rows = own.data.filter((e: any) => e.type === 1007)
  expect(rows).toHaveLength(1)
  // The client date is ignored.
  expect(Date.parse(rows[0].date)).toBeGreaterThanOrEqual(before - 1000)
  const log = await owner.json(`/api/organizations/${orgId}/events`)
  expect(log.data.filter((e: any) => e.type === 1007)).toHaveLength(1)
})

it('drops phishing blocker events (2400 to 2402) that name no organisation', async () => {
  const s = await actor('hd-phish@example.com')
  const now = new Date().toISOString()
  const res = await s.call(
    '/events/collect',
    'POST',
    [2400, 2401, 2402].map((type) => ({ type, date: now })),
  )
  expect(res.status).toBe(200)
  const own = await s.json('/api/events')
  expect(own.data.filter((e: any) => e.type >= 2400 && e.type <= 2402)).toHaveLength(0)
})

it('limits how often a client may report events', async () => {
  const s = await actor('hd-limit@example.com')
  const { default: app } = await import('../src/index')
  // The window is fixed, so freeze the clock to keep the 130 requests inside one window.
  const restore = freezeRateLimitWindow()
  let limited = 0
  for (let i = 0; i < 130; i++) {
    const res = await app.fetch(
      new Request(`${BASE}/events/collect`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${s.token}`,
          'Content-Type': 'application/json',
          'CF-Connecting-IP': '10.9.2.2',
        },
        body: '[]',
      }),
      { ...env },
    )
    if (res.status === 429) limited++
  }
  restore()
  expect(limited).toBeGreaterThan(0)
})

it('puts the device approval request (1010) in the own feed', async () => {
  const owner = await actor('hd-1010-owner@example.com')
  const member = await actor('hd-1010@example.com')
  const { id: orgId } = await createOrg(owner)
  await addMember(owner, orgId, member, { type: 2 })
  await enableRecoveryPolicy(owner, orgId)
  await createDb(env.DB)
    .insert(schema.ssoConfigs)
    .values({
      organizationUuid: orgId,
      enabled: true,
      data: JSON.stringify({ memberDecryptionType: 2 }),
      createdAt: Date.now(),
      updatedAt: Date.now(),
    })
  expect(
    (
      await member.call(
        `/api/organizations/${orgId}/users/${member.uuid}/reset-password-enrollment`,
        'PUT',
        { resetPasswordKey: '4.recovery', masterPasswordHash: 'client-derived-hash' },
      )
    ).status,
  ).toBe(200)
  const res = await member.call('/api/auth-requests/admin-request', 'POST', {
    email: member.email,
    deviceIdentifier: 'tde-device',
    publicKey: 'devicePublicKey',
    type: 2,
    accessCode: 'access-code',
  })
  expect(res.status).toBe(200)
  const own = await member.json('/api/events')
  expect(own.data.filter((e: any) => e.type === 1010)).toHaveLength(1)
  const log = await owner.json(`/api/organizations/${orgId}/events`)
  expect(log.data.filter((e: any) => e.type === 1010)).toHaveLength(1)
})

it('writes the revocation events of a two-step policy as one statement', async () => {
  const owner = await actor('hd-pol-owner@example.com')
  const { id: orgId } = await createOrg(owner)
  const members = []
  for (const n of [1, 2, 3]) {
    const m = await actor(`hd-pol-m${n}@example.com`)
    await addMember(owner, orgId, m)
    members.push(m)
  }
  const spy = spyDb(null)
  const r = await call(spy.db, `/api/organizations/${orgId}/policies/0`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${owner.token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled: true }),
  })
  expect(r.res.status).toBe(200)
  await r.settle()
  // One statement for the revoked members and one for the policy update, whatever the count.
  expect(spy.log.filter((s) => /insert into "events"/i.test(s))).toHaveLength(2)
  expect(await countOf(1520)).toBe(3)
  // The events come before the update that makes the members compliant-looking (revoked).
  const rows = await env.DB.prepare(
    'select acting_user_uuid a, organization_user_uuid m from events where event_type = 1520',
  ).all<{ a: string; m: string }>()
  expect(rows.results.every((e) => e.a === owner.uuid && e.m)).toBe(true)
})
