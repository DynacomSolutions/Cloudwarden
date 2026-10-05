import { env } from 'cloudflare:workers'
import { describe, expect, it } from 'vitest'
import { D1_BOOKMARK_HEADER, sessionConstraint, sessionsEnabled } from '../src/db/sessions'
import { BASE, createSession } from './helpers'

const cipher = (name = '2.name') => ({
  type: 2,
  name,
  notes: '2.notes',
  secureNote: { type: 0 },
})

/** Wraps the D1 binding so tests can see which constraint each session was opened with. */
function spiedDb() {
  const constraints: unknown[] = []
  const db = new Proxy(env.DB, {
    get(target, prop) {
      if (prop === 'withSession') {
        return (constraint?: string) => {
          constraints.push(constraint)
          return target.withSession(constraint)
        }
      }
      const value = Reflect.get(target, prop)
      return typeof value === 'function' ? value.bind(target) : value
    },
  })
  return { db, constraints }
}

const ctx = { waitUntil: () => {}, passThroughOnException: () => {} } as unknown as ExecutionContext

async function request(
  overrides: Record<string, unknown>,
  path: string,
  token: string,
  init: { method?: string; body?: unknown; bookmark?: string } = {},
) {
  const { default: app } = await import('../src/index')
  const headers: Record<string, string> = { Authorization: `Bearer ${token}` }
  if (init.body !== undefined) headers['Content-Type'] = 'application/json'
  if (init.bookmark) headers[D1_BOOKMARK_HEADER] = init.bookmark
  return app.fetch(
    new Request(`${BASE}${path}`, {
      method: init.method ?? 'GET',
      headers,
      ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
    }),
    { ...env, ...overrides } as never,
    ctx,
  )
}

describe('D1 sessions flag and constraint', () => {
  it('is off unless the variable is exactly true', () => {
    expect(sessionsEnabled({})).toBe(false)
    expect(sessionsEnabled({ D1_SESSIONS: 'false' })).toBe(false)
    expect(sessionsEnabled({ D1_SESSIONS: '1' })).toBe(false)
    expect(sessionsEnabled({ D1_SESSIONS: 'true' })).toBe(true)
  })

  it('starts on the primary unless the client sends a plausible bookmark', () => {
    expect(sessionConstraint(undefined)).toBe('first-primary')
    expect(sessionConstraint('')).toBe('first-primary')
    expect(sessionConstraint('x'.repeat(257))).toBe('first-primary')
    expect(sessionConstraint('bad bookmark!')).toBe('first-primary')
    expect(sessionConstraint('first-unconstrained')).toBe('first-primary')
    expect(sessionConstraint('first-primary')).toBe('first-primary')
    const bm = '00000085-0000024c-00004c6d-8e61117bf38d7adb71b934ebbf891683'
    expect(sessionConstraint(bm)).toBe(bm)
  })
})

describe('D1 sessions middleware', () => {
  it('is inert by default: no session, no bookmark header', async () => {
    const s = await createSession('d1-off@example.com')
    const spy = spiedDb()
    const res = await request({ DB: spy.db }, '/api/sync', s.access_token)
    expect(res.status).toBe(200)
    expect(res.headers.get(D1_BOOKMARK_HEADER)).toBeNull()
    expect(spy.constraints).toEqual([])
  })

  it('opens a primary session per request and returns a bookmark when enabled', async () => {
    const s = await createSession('d1-on@example.com')
    const spy = spiedDb()
    const on = { DB: spy.db, D1_SESSIONS: 'true' }
    const res = await request(on, '/api/sync', s.access_token)
    expect(res.status).toBe(200)
    expect(spy.constraints).toEqual(['first-primary'])
    const bookmark = res.headers.get(D1_BOOKMARK_HEADER)
    expect(bookmark).toBeTruthy()

    // The bookmark is accepted back and used as the starting constraint.
    const next = await request(on, '/api/sync', s.access_token, { bookmark: bookmark as string })
    expect(next.status).toBe(200)
    expect(spy.constraints.at(-1)).toBe(bookmark)

    // A junk header is ignored, not trusted and not an error.
    const junk = await request(on, '/api/sync', s.access_token, { bookmark: '../../etc' })
    expect(junk.status).toBe(200)
    expect(spy.constraints.at(-1)).toBe('first-primary')
  })

  it('leaves failures and unauthenticated routes working', async () => {
    const on = { D1_SESSIONS: 'true' }
    const denied = await request(on, '/api/sync', 'bogus')
    expect(denied.status).toBe(401)
    const { default: app } = await import('../src/index')
    const alive = await app.fetch(new Request(`${BASE}/alive`), { ...env, ...on } as never, ctx)
    expect(alive.status).toBe(200)
  })
})

describe('primary-only paths', () => {
  it('starts identity requests on the primary even with a bookmark', async () => {
    const spy = spiedDb()
    const { default: app } = await import('../src/index')
    await app.fetch(
      new Request(`${BASE}/identity/accounts/prelogin`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [D1_BOOKMARK_HEADER]: 'abc-def' },
        body: JSON.stringify({ email: 'x@example.com' }),
      }),
      { ...env, DB: spy.db, D1_SESSIONS: 'true' } as never,
      ctx,
    )
    expect(spy.constraints).toEqual(['first-primary'])
  })

  it('reads the user and security stamp through the plain binding', async () => {
    const s = await createSession('d1-auth@example.com')
    const spy = spiedDb()
    const prepared: string[] = []
    const plain = new Proxy(spy.db, {
      get(t, p) {
        if (p === 'prepare') {
          return (q: string) => {
            prepared.push(q)
            return t.prepare(q)
          }
        }
        const v = Reflect.get(t, p)
        return typeof v === 'function' ? v.bind(t) : v
      },
    })
    const res = await request({ DB: plain, D1_SESSIONS: 'true' }, '/api/sync', s.access_token, {
      bookmark: 'first-unconstrained',
    })
    expect(res.status).toBe(200)
    // The auth read hit the plain binding; the session never saw a junk keyword.
    expect(prepared.some((q) => q.includes('"users"'))).toBe(true)
    expect(spy.constraints).toEqual(['first-primary'])
  })
})

describe('revision dates with sessions enabled', () => {
  it('never regress when bookmarks are chained, and conflict checks agree', async () => {
    const s = await createSession('d1-rev@example.com')
    const on = { D1_SESSIONS: 'true' }
    let bookmark: string | undefined
    const call = async (path: string, method = 'GET', body?: unknown) => {
      const res = await request(on, path, s.access_token, { method, body, bookmark })
      bookmark = res.headers.get(D1_BOOKMARK_HEADER) ?? bookmark
      return { status: res.status, body: (await res.json().catch(() => null)) as any }
    }

    const created = await call('/api/ciphers', 'POST', cipher())
    expect(created.status).toBe(200)
    const dates = [Date.parse(created.body.revisionDate)]
    let last = created.body.revisionDate as string
    for (let i = 0; i < 3; i++) {
      await new Promise((r) => setTimeout(r, 1100))
      const edit = await call(`/api/ciphers/${created.body.id}`, 'PUT', {
        ...cipher(`2.v${i}`),
        lastKnownRevisionDate: last,
      })
      expect(edit.status, JSON.stringify(edit.body)).toBe(200)
      last = edit.body.revisionDate
      dates.push(Date.parse(last))

      // A read that carries the writer's bookmark sees the write it follows.
      const sync = await call('/api/sync')
      const seen = sync.body.ciphers.find((c: any) => c.id === created.body.id)
      expect(seen.revisionDate).toBe(last)
      expect(seen.name).toBe(`2.v${i}`)
    }
    for (let i = 1; i < dates.length; i++) {
      expect(dates[i]).toBeGreaterThan(dates[i - 1] as number)
    }
    // The stale copy is still rejected exactly as without sessions.
    const stale = await call(`/api/ciphers/${created.body.id}`, 'PUT', {
      ...cipher('2.late'),
      lastKnownRevisionDate: created.body.revisionDate,
    })
    expect(stale.status).toBe(400)
  })

  it('behaves the same as the plain binding for a client that sends no bookmark', async () => {
    const s = await createSession('d1-nobm@example.com')
    const on = { D1_SESSIONS: 'true' }
    const w = await request(on, '/api/ciphers', s.access_token, { method: 'POST', body: cipher() })
    const created = (await w.json()) as any
    // Immediately read it back with no bookmark: the primary answers, so the write is visible.
    const read = await request(on, `/api/ciphers/${created.id}`, s.access_token)
    expect(((await read.json()) as any).revisionDate).toBe(created.revisionDate)
    const off = await request({}, `/api/ciphers/${created.id}`, s.access_token)
    expect(((await off.json()) as any).revisionDate).toBe(created.revisionDate)
  })
})
