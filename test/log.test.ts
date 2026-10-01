import { env } from 'cloudflare:workers'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { app } from '../src/index'
import { formatLine, sanitizeFields } from '../src/log'

afterEach(() => vi.restoreAllMocks())

describe('structured logging', () => {
  it('drops sensitive keys and non-scalar values', () => {
    const out = sanitizeFields({
      status: 200,
      route: '/api/x',
      password: 'p',
      masterPasswordHash: 'h',
      access_token: 't',
      email: 'user@example.com',
      body: 'secret',
      Authorization: 'Bearer x',
      nested: { a: 1 } as unknown as string,
    })
    expect(out).toEqual({ status: 200, route: '/api/x' })
  })

  it('truncates long strings and emits one JSON line', () => {
    const line = formatLine('info', 'evt', { note: 'x'.repeat(500) }, 0)
    const parsed = JSON.parse(line)
    expect(parsed.ts).toBe('1970-01-01T00:00:00.000Z')
    expect(parsed.event).toBe('evt')
    expect(parsed.note.length).toBeLessThan(300)
    expect(line.includes('\n')).toBe(false)
  })

  it('logs one request line with route, status and duration, and never the body or query', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const res = await app.request(
      '/identity/accounts/prelogin?token=SECRET-QUERY',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'user@example.com', masterPasswordHash: 'SECRET-BODY' }),
      },
      env,
    )
    expect(res.headers.get('X-Request-Id')).toBeTruthy()
    const lines = spy.mock.calls.map((c) => String(c[0]))
    expect(lines.length).toBe(1)
    const entry = JSON.parse(lines[0] as string)
    expect(entry).toMatchObject({ event: 'request', level: 'info', method: 'POST' })
    expect(typeof entry.status).toBe('number')
    expect(typeof entry.durationMs).toBe('number')
    expect(typeof entry.requestId).toBe('string')
    expect(lines[0]).not.toContain('SECRET')
    expect(lines[0]).not.toContain('user@example.com')
  })

  it('honours LOG_LEVEL', async () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {})
    await app.request('/alive', {}, { ...env, LOG_LEVEL: 'error' })
    expect(spy).not.toHaveBeenCalled()
  })
})
