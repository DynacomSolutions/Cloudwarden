import { Hono } from 'hono'
import { requireAuth } from '../auth/middleware'
import type { Env } from '../env'
import { ApiError } from '../errors'
import type { Fetcher } from '../icons/fetch'
import { log } from '../log'

const HIBP_URL = 'https://haveibeenpwned.com/api/v3/breachedaccount/'
const PASSKEY_DIRECTORY_URL = 'https://passkeys-api.2fa.directory/v1/all.json'
const DIRECTORY_TTL = 24 * 3600
const USER_AGENT = 'Cloudwarden'

/** One entry of the public passkeys directory (2fa.directory), keyed by domain. */
interface DirectoryEntry {
  passwordless?: unknown
  mfa?: unknown
  documentation?: unknown
  domain?: unknown
}

/** Maps the directory to PasskeyDirectoryEntryResponse (DomainName, Instructions, Passwordless, Mfa). */
export function mapPasskeyDirectory(raw: unknown) {
  if (!raw || typeof raw !== 'object') return []
  // The list is an object keyed by domain; the array form ([name, entry] pairs) is accepted too.
  const pairs = Array.isArray(raw)
    ? raw.filter((p): p is [string, DirectoryEntry] => Array.isArray(p) && p.length === 2)
    : Object.entries(raw as Record<string, DirectoryEntry>)
  return pairs
    .filter(([, e]) => e && typeof e === 'object')
    .map(([key, e]) => ({
      domainName: typeof e.domain === 'string' ? e.domain : key,
      instructions: typeof e.documentation === 'string' ? e.documentation : '',
      passwordless: Boolean(e.passwordless),
      mfa: Boolean(e.mfa),
    }))
}

/** Build the report routes. `fetcher` is injectable so tests never touch the network. */
export function createReports(fetcher: Fetcher = (u, i) => fetch(u, i)) {
  const reports = new Hono<Env>()

  // Data breach report: a proxy to the Have I Been Pwned v3 API, which needs a paid key. Without
  // one the report answers 400 and the web vault shows its generic error state.
  reports.get('/api/hibp/breach', requireAuth, async (c) => {
    const key = c.env.HIBP_API_KEY
    if (!key) throw new ApiError(400, 'The breach report is not configured on this server.')
    const username = c.req.query('username') ?? ''
    if (!username) throw new ApiError(400, 'A username is required.')
    let res: Response
    try {
      res = await fetcher(
        `${HIBP_URL}${encodeURIComponent(username)}?truncateResponse=false&includeUnverified=false`,
        { headers: { 'hibp-api-key': key, 'User-Agent': USER_AGENT } },
      )
    } catch {
      throw new ApiError(502, 'The breach service could not be reached.')
    }
    // HIBP answers 404 for an address found in no breach.
    if (res.status === 404) return c.json([])
    if (!res.ok) {
      log('warn', 'hibp.failed', { status: res.status }, c.env)
      throw new ApiError(res.status === 429 ? 429 : 502, 'The breach service returned an error.')
    }
    return c.json(await res.json())
  })

  // Passkey report: the public passkeys.2fa.directory list, cached for a day.
  reports.get('/api/reports/passkey-directory', requireAuth, async (c) => {
    const cache = (caches as unknown as { default: Cache }).default
    const cacheKey = new Request(`${new URL(c.req.url).origin}/__cache/passkey-directory`)
    const hit = await cache.match(cacheKey)
    if (hit) return c.json(await hit.json())
    let raw: unknown
    try {
      const res = await fetcher(PASSKEY_DIRECTORY_URL, {
        headers: { Accept: 'application/json', 'User-Agent': USER_AGENT },
      })
      if (!res.ok) throw new Error(String(res.status))
      raw = await res.json()
    } catch {
      throw new ApiError(502, 'The passkey directory could not be loaded.')
    }
    const entries = mapPasskeyDirectory(raw)
    c.executionCtx.waitUntil(
      cache.put(
        cacheKey,
        new Response(JSON.stringify(entries), {
          headers: {
            'Content-Type': 'application/json',
            'Cache-Control': `public, max-age=${DIRECTORY_TTL}`,
          },
        }),
      ),
    )
    return c.json(entries)
  })

  return reports
}

export const reports = createReports()
