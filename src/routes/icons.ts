import { Hono } from 'hono'
import type { Env } from '../env'
import { type Fetcher, fetchIcon } from '../icons/fetch'
import { validateHost } from '../icons/ssrf'
import { log } from '../log'

/** 1x1 transparent PNG served when no icon can be found. */
const FALLBACK_PNG = Uint8Array.from(
  atob(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  ),
  (c) => c.charCodeAt(0),
)

const POSITIVE_TTL = 7 * 24 * 3600
const NEGATIVE_TTL = 24 * 3600
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

    const icon = await fetchIcon(host, fetcher)
    if (!icon) {
      c.executionCtx.waitUntil(
        cache.put(
          key,
          new Response(FALLBACK_PNG, {
            headers: {
              ...COMMON_HEADERS,
              'Content-Type': 'image/png',
              'Cache-Control': `public, max-age=${NEGATIVE_TTL}`,
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

  return icons
}

export const icons = createIcons()
