import { Hono } from 'hono'
import type { Env } from '../env'
import {
  type Fetcher,
  type FetchState,
  fetchIcon,
  OVERALL_TIMEOUT_MS,
  safeGet,
} from '../icons/fetch'
import { validateHost } from '../icons/ssrf'
import { log } from '../log'
import { rateLimit } from '../ratelimit'

/** 1x1 transparent PNG served when no icon can be found. */
const FALLBACK_PNG = Uint8Array.from(
  atob(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  ),
  (c) => c.charCodeAt(0),
)

const POSITIVE_TTL = 7 * 24 * 3600
/** Definitive misses (404, no icon, not an image) are remembered for a day; transient failures for an hour. */
const NEGATIVE_TTL = 24 * 3600
const TRANSIENT_TTL = 3600
const CLIENT_FALLBACK_TTL = 3600

const COMMON_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': "default-src 'none'; sandbox",
  'Cross-Origin-Resource-Policy': 'cross-origin',
}

function fallback(ttl: number): Response {
  return new Response(FALLBACK_PNG, {
    status: 200,
    headers: {
      ...COMMON_HEADERS,
      'Content-Type': 'image/png',
      'Cache-Control': `public, max-age=${ttl}`,
      'X-Icon-Source': 'fallback',
    },
  })
}

/** Build the icon route. `fetcher` is injectable so tests never touch the network. */
export function createIcons(fetcher: Fetcher = (u, i) => fetch(u, i)) {
  const icons = new Hono<Env>()

  icons.get('/icons/:domain/icon.png', async (c) => {
    if (c.env.ICONS_ENABLED === 'false') {
      return c.json({ message: 'Not found', validationErrors: null, object: 'error' }, 404)
    }
    const checked = validateHost(c.req.param('domain'))
    if (!checked.ok) {
      log('warn', 'icon.refused', { reason: checked.reason }, c.env)
      // Same shape as any other miss, so the response does not reveal why a host was refused.
      return fallback(CLIENT_FALLBACK_TTL)
    }

    const host = checked.host
    const cache = (caches as unknown as { default: Cache }).default
    const key = new Request(`${new URL(c.req.url).origin}/icons/${host}/icon.png`)
    const hit = await cache.match(key)
    if (hit) {
      if (hit.headers.get('X-Icon-Source') === 'fallback') return fallback(CLIENT_FALLBACK_TTL)
      return hit
    }

    // Only cache misses cost an outbound fetch, so only they are rate limited per client address.
    let allowed = false
    const limited = await rateLimit('icons')(c, async () => {
      allowed = true
    })
    if (!allowed) return limited as Response

    const state: FetchState = { transient: false }
    const icon = await fetchIcon(host, fetcher, state)
    if (!icon) {
      const ttl = state.transient ? TRANSIENT_TTL : NEGATIVE_TTL
      c.executionCtx.waitUntil(
        cache.put(
          key,
          new Response(FALLBACK_PNG, {
            headers: {
              ...COMMON_HEADERS,
              'Content-Type': 'image/png',
              'Cache-Control': `public, max-age=${ttl}`,
              'X-Icon-Source': 'fallback',
            },
          }),
        ),
      )
      return fallback(CLIENT_FALLBACK_TTL)
    }
    const res = new Response(icon.bytes, {
      headers: {
        ...COMMON_HEADERS,
        'Content-Type': icon.contentType,
        'Cache-Control': `public, max-age=${POSITIVE_TTL}`,
        'X-Icon-Source': 'origin',
      },
    })
    c.executionCtx.waitUntil(cache.put(key, res.clone()))
    return res
  })

  // Change-password URL for a login URI (ChangePasswordUriResponse { uri }), found with the
  // W3C well-known URL for changing passwords. A site counts as supporting it only when
  // /.well-known/change-password succeeds and a path that cannot exist does not, as the
  // specification recommends to rule out servers that answer 200 for everything.
  icons.get('/icons/change-password-uri', async (c) => {
    if (c.env.ICONS_ENABLED === 'false') {
      return c.json({ message: 'Not found', validationErrors: null, object: 'error' }, 404)
    }
    const raw = c.req.query('uri') ?? ''
    let host: string
    try {
      host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`).hostname
    } catch {
      return c.json({ uri: null })
    }
    const checked = validateHost(host)
    if (!checked.ok) return c.json({ uri: null })

    const cache = (caches as unknown as { default: Cache }).default
    const key = new Request(
      `${new URL(c.req.url).origin}/icons/change-password-uri/${checked.host}`,
    )
    const hit = await cache.match(key)
    if (hit) return c.json(await hit.json())

    let allowed = false
    const limited = await rateLimit('icons')(c, async () => {
      allowed = true
    })
    if (!allowed) return limited as Response

    const overall = AbortSignal.timeout(OVERALL_TIMEOUT_MS)
    const origin = `https://${checked.host}`
    const probe = async (path: string) => {
      const got = await safeGet(new URL(path, origin), fetcher, '*/*', overall)
      await got?.res.body?.cancel().catch(() => {})
      return got !== null
    }
    const wellKnown = `${origin}/.well-known/change-password`
    const supported =
      (await probe('/.well-known/change-password')) &&
      !(await probe(
        '/.well-known/resource-that-should-not-exist-whose-status-code-should-not-be-200',
      ))
    const body = { uri: supported ? wellKnown : null }
    c.executionCtx.waitUntil(
      cache.put(
        key,
        new Response(JSON.stringify(body), {
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': `public, max-age=${NEGATIVE_TTL}`,
          },
        }),
      ),
    )
    return c.json(body)
  })

  return icons
}

export const icons = createIcons()
