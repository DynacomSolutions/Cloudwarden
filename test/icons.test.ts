import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { Hono } from 'hono'
import { describe, expect, it } from 'vitest'
import type { Env } from '../src/env'
import { type Fetcher, fetchIcon, parseIconLinks } from '../src/icons/fetch'
import { isBlockedIpLiteral, validateHost, validateUrl } from '../src/icons/ssrf'
import { app } from '../src/index'
import { createIcons } from '../src/routes/icons'

const PNG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4])
const png = () => new Response(PNG, { headers: { 'content-type': 'image/png' } })
const redirect = (to: string) => new Response(null, { status: 302, headers: { location: to } })

function recorder(handler: (url: string) => Response | Promise<Response>) {
  const calls: string[] = []
  const fetcher: Fetcher = async (url) => {
    calls.push(url)
    return handler(url)
  }
  return { calls, fetcher }
}

describe('validateHost refuses SSRF targets', () => {
  const refused = [
    'localhost',
    'foo.localhost',
    'printer.local',
    'db.internal',
    'service.lan',
    '127.0.0.1',
    '10.0.0.1',
    '172.16.0.1',
    '192.168.1.1',
    '169.254.169.254',
    '100.64.0.1',
    '0.0.0.0',
    '2130706433',
    '0x7f.0.0.1',
    '0177.0.0.1',
    '127.1',
    '[::1]',
    '::1',
    '::ffff:127.0.0.1',
    'fe80::1',
    'fd00::1',
    '8.8.8.8',
    'single',
    'a..com',
    '-bad.example.com',
    'bad-.example.com',
    'exa mple.com',
    'example.com:8080',
    'user@example.com',
    'example.com/path',
    'example.com?x=1',
    'example.123',
    '',
    `${'a'.repeat(64)}.example.com`,
    `${'a.'.repeat(130)}com`,
  ]
  for (const host of refused) {
    it(`refuses ${JSON.stringify(host.length > 40 ? `${host.slice(0, 20)}...` : host)}`, () => {
      expect(validateHost(host).ok).toBe(false)
    })
  }

  it('accepts ordinary public names and normalises case and punycode', () => {
    expect(validateHost('Example.COM')).toEqual({ ok: true, host: 'example.com' })
    expect(validateHost('sub.example.co.uk').ok).toBe(true)
    expect(validateHost('bücher.example.com')).toEqual({
      ok: true,
      host: 'xn--bcher-kva.example.com',
    })
  })

  it('classifies address ranges', () => {
    for (const ip of [
      '10.1.2.3',
      '127.0.0.1',
      '169.254.1.1',
      '100.100.0.1',
      '172.31.255.255',
      '192.168.0.1',
      '::',
      '::1',
      'fe80::1',
      'fc00::1',
      '::ffff:10.0.0.1',
      '2002:c0a8:101::1',
    ]) {
      expect(isBlockedIpLiteral(ip), ip).toBe(true)
    }
    for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) {
      expect(isBlockedIpLiteral(ip), ip).toBe(false)
    }
  })

  it('refuses unsafe URLs', () => {
    expect(validateUrl(new URL('ftp://example.com/x')).ok).toBe(false)
    expect(validateUrl(new URL('https://example.com:8443/x')).ok).toBe(false)
    expect(validateUrl(new URL('https://user:pw@example.com/')).ok).toBe(false)
    expect(validateUrl(new URL('http://[::1]/')).ok).toBe(false)
    expect(validateUrl(new URL('https://example.com/x')).ok).toBe(true)
  })
})

describe('fetchIcon', () => {
  it('returns /favicon.ico when it is a real image', async () => {
    const { fetcher, calls } = recorder(() => png())
    const icon = await fetchIcon('example.com', fetcher)
    expect(icon?.contentType).toBe('image/png')
    expect(calls).toEqual(['https://example.com/favicon.ico'])
  })

  it('never contacts a refused host', async () => {
    const { fetcher, calls } = recorder(() => png())
    expect(await fetchIcon('127.0.0.1', fetcher)).toBeNull()
    expect(await fetchIcon('localhost', fetcher)).toBeNull()
    expect(calls).toEqual([])
  })

  it('refuses a redirect to a private address', async () => {
    const { fetcher, calls } = recorder((url) =>
      url.includes('favicon')
        ? redirect('http://169.254.169.254/latest/meta-data')
        : new Response('nope', { status: 404 }),
    )
    expect(await fetchIcon('example.com', fetcher)).toBeNull()
    expect(calls.some((u) => u.includes('169.254'))).toBe(false)
  })

  it('refuses a redirect to an internal name or non-http scheme', async () => {
    for (const to of [
      'https://admin.internal/icon.png',
      'http://localhost/x',
      'file:///etc/passwd',
      'https://example.com:22/x',
    ]) {
      const { fetcher, calls } = recorder((url) =>
        url === 'https://example.com/favicon.ico'
          ? redirect(to)
          : new Response('', { status: 404 }),
      )
      expect(await fetchIcon('example.com', fetcher)).toBeNull()
      expect(calls.some((u) => u === to)).toBe(false)
    }
  })

  it('refuses a redirect from https to http', async () => {
    const { fetcher, calls } = recorder((url) =>
      url === 'https://example.com/favicon.ico'
        ? redirect('http://cdn.example.net/i.png')
        : new Response('', { status: 404 }),
    )
    expect(await fetchIcon('example.com', fetcher)).toBeNull()
    expect(calls.some((u) => u.startsWith('http://'))).toBe(false)
  })

  it('flags transient failures but not definitive misses', async () => {
    const s1 = { transient: false }
    await fetchIcon('example.com', recorder(() => new Response('', { status: 404 })).fetcher, s1)
    expect(s1.transient).toBe(false)
    const s2 = { transient: false }
    await fetchIcon('example.com', recorder(() => new Response('', { status: 503 })).fetcher, s2)
    expect(s2.transient).toBe(true)
    const s3 = { transient: false }
    await fetchIcon(
      'example.com',
      recorder(() => {
        throw new Error('timeout')
      }).fetcher,
      s3,
    )
    expect(s3.transient).toBe(true)
  })

  it('stops after three redirects', async () => {
    let n = 0
    const { fetcher, calls } = recorder(() => redirect(`https://example.com/r${++n}`))
    expect(await fetchIcon('example.com', fetcher)).toBeNull()
    // favicon: 1 + 3 redirects; homepage: 1 + 3 redirects.
    expect(calls.length).toBe(8)
  })

  it('follows allowed redirects and re-validates each hop', async () => {
    const { fetcher } = recorder((url) =>
      url === 'https://example.com/favicon.ico' ? redirect('https://cdn.example.net/i.png') : png(),
    )
    expect((await fetchIcon('example.com', fetcher))?.contentType).toBe('image/png')
  })

  it('rejects non-image content types and mismatched bytes', async () => {
    const html = recorder(
      () => new Response('<html></html>', { headers: { 'content-type': 'text/html' } }),
    )
    expect(await fetchIcon('example.com', html.fetcher)).toBeNull()
    const lying = recorder(
      () => new Response('<script>alert(1)</script>', { headers: { 'content-type': 'image/png' } }),
    )
    expect(await fetchIcon('example.com', lying.fetcher)).toBeNull()
    const svg = recorder(
      () =>
        new Response('<svg xmlns="http://www.w3.org/2000/svg"/>', {
          headers: { 'content-type': 'image/svg+xml' },
        }),
    )
    expect(await fetchIcon('example.com', svg.fetcher)).toBeNull()
  })

  it('rejects oversized icons', async () => {
    const big = new Uint8Array(600 * 1024)
    big.set(PNG)
    const { fetcher } = recorder(
      () => new Response(big, { headers: { 'content-type': 'image/png' } }),
    )
    expect(await fetchIcon('example.com', fetcher)).toBeNull()
  })

  it('falls back to <link rel=icon> and refuses a private icon href', async () => {
    const page =
      '<html><head><link rel="icon" href="http://10.0.0.5/a.png"><link rel="shortcut icon" href="/static/i.png"></head></html>'
    const { fetcher, calls } = recorder((url) => {
      if (url.endsWith('/favicon.ico')) return new Response('', { status: 404 })
      if (url === 'https://example.com/')
        return new Response(page, { headers: { 'content-type': 'text/html' } })
      if (url === 'https://example.com/static/i.png') return png()
      return new Response('', { status: 404 })
    })
    expect((await fetchIcon('example.com', fetcher))?.contentType).toBe('image/png')
    expect(calls.some((u) => u.includes('10.0.0.5'))).toBe(false)
  })

  it('parses link tags', () => {
    const urls = parseIconLinks(
      `<link rel='icon' href='a.png'><link rel=stylesheet href=s.css><link href="b.ico" rel="shortcut icon">`,
      new URL('https://example.com/dir/'),
    )
    expect(urls.map(String)).toEqual([
      'https://example.com/dir/b.ico',
      'https://example.com/dir/a.png',
    ])
  })
})

describe('GET /icons/:domain/icon.png', () => {
  const ctx = {
    waitUntil: (p: Promise<unknown>) => void p.catch(() => {}),
    passThroughOnException() {},
  } as unknown as ExecutionContext

  it('returns the fallback PNG with 200 for refused hosts without fetching', async () => {
    const { fetcher, calls } = recorder(() => png())
    const r = new Hono<Env>().route('/', createIcons(fetcher))
    for (const d of [
      '127.0.0.1',
      'localhost',
      '169.254.169.254',
      'metadata.internal',
      '%3A%3A1',
      '2130706433',
    ]) {
      const res = await r.request(`/icons/${d}/icon.png`, {}, env, ctx)
      expect(res.status).toBe(200)
      expect(res.headers.get('X-Icon-Source')).toBe('fallback')
      expect(res.headers.get('Content-Type')).toBe('image/png')
      expect((await res.arrayBuffer()).byteLength).toBeGreaterThan(0)
    }
    expect(calls).toEqual([])
  })

  it('serves, then caches, a found icon', async () => {
    const { fetcher, calls } = recorder(() => png())
    const r = new Hono<Env>().route('/', createIcons(fetcher))
    const host = `cache-hit-${crypto.randomUUID().slice(0, 8)}.example.com`
    const pending: Promise<unknown>[] = []
    const c2 = {
      waitUntil: (p: Promise<unknown>) => void pending.push(p),
      passThroughOnException() {},
    } as unknown as ExecutionContext
    const first = await r.request(`/icons/${host}/icon.png`, {}, env, c2)
    expect(first.headers.get('X-Icon-Source')).toBe('origin')
    expect(first.headers.get('Cache-Control')).toBe('public, max-age=604800')
    await Promise.all(pending)
    const second = await r.request(`/icons/${host}/icon.png`, {}, env, c2)
    expect(second.status).toBe(200)
    expect(calls.length).toBe(1)
  })

  it('negative-caches failures and returns a short-lived fallback', async () => {
    const { fetcher, calls } = recorder(() => new Response('', { status: 404 }))
    const r = new Hono<Env>().route('/', createIcons(fetcher))
    const host = `cache-miss-${crypto.randomUUID().slice(0, 8)}.example.com`
    const pending: Promise<unknown>[] = []
    const c2 = {
      waitUntil: (p: Promise<unknown>) => void pending.push(p),
      passThroughOnException() {},
    } as unknown as ExecutionContext
    const first = await r.request(`/icons/${host}/icon.png`, {}, env, c2)
    expect(first.status).toBe(200)
    expect(first.headers.get('Cache-Control')).toBe('public, max-age=3600')
    await Promise.all(pending)
    const before = calls.length
    const second = await r.request(`/icons/${host}/icon.png`, {}, env, c2)
    expect(second.headers.get('X-Icon-Source')).toBe('fallback')
    expect(calls.length).toBe(before)
  })

  it('uses a one hour negative TTL for transient failures', async () => {
    const { fetcher } = recorder(() => new Response('', { status: 503 }))
    const r = new Hono<Env>().route('/', createIcons(fetcher))
    const host = `transient-${crypto.randomUUID().slice(0, 8)}.example.com`
    const pending: Promise<unknown>[] = []
    const c2 = {
      waitUntil: (p: Promise<unknown>) => void pending.push(p),
      passThroughOnException() {},
    } as unknown as ExecutionContext
    await r.request(`/icons/${host}/icon.png`, {}, env, c2)
    await Promise.all(pending)
    const cached = await (caches as unknown as { default: Cache }).default.match(
      new Request(`http://localhost/icons/${host}/icon.png`),
    )
    expect(cached?.headers.get('Cache-Control')).toBe('public, max-age=3600')
  })

  it('rate limits cache misses per client but not cache hits', async () => {
    let allow = true
    const limiter = { limit: async () => ({ success: allow }) } as unknown as RateLimit
    const { fetcher, calls } = recorder(() => png())
    const r = new Hono<Env>().route('/', createIcons(fetcher))
    const pending: Promise<unknown>[] = []
    const c2 = {
      waitUntil: (p: Promise<unknown>) => void pending.push(p),
      passThroughOnException() {},
    } as unknown as ExecutionContext
    const e = { ...env, LOGIN_LIMITER: limiter }
    const cached = `rl-cached-${crypto.randomUUID().slice(0, 8)}.example.com`
    await r.request(`/icons/${cached}/icon.png`, {}, e, c2)
    await Promise.all(pending)
    allow = false
    const hit = await r.request(`/icons/${cached}/icon.png`, {}, e, c2)
    expect(hit.status).toBe(200)
    const before = calls.length
    const miss = await r.request(
      `/icons/rl-miss-${crypto.randomUUID().slice(0, 8)}.example.com/icon.png`,
      {},
      e,
      c2,
    )
    expect(miss.status).toBe(429)
    expect(calls.length).toBe(before)
  })

  it('is disabled when ICONS_ENABLED is false', async () => {
    const res = await app.request(
      '/icons/example.com/icon.png',
      {},
      { ...env, ICONS_ENABLED: 'false' },
      ctx,
    )
    expect(res.status).toBe(404)
  })

  it('is wired into the worker and refuses private targets end to end', async () => {
    const res = await SELF.fetch('https://vault.example.com/icons/127.0.0.1/icon.png')
    expect(res.status).toBe(200)
    expect(res.headers.get('X-Icon-Source')).toBe('fallback')
  })
})
