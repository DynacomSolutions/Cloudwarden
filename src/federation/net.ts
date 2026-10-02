// SSRF-safe outbound fetch for federation (TASKS #301). Peers are named by domain only: https on
// port 443, no IP literals, no redirects, and every A and AAAA record (resolved over DNS over
// HTTPS) must be a public address. A response size cap and a timeout bound each call.
import type { Bindings } from '../env'
import { ApiError } from '../errors'
import { isBlockedIpLiteral } from '../icons/ssrf'

const DOH_URL = 'https://cloudflare-dns.com/dns-query'
export const FETCH_TIMEOUT_MS = 15_000

/** Lower-case host name, or null when it is not an acceptable peer domain. */
export function parsePeerDomain(input: string): string | null {
  const raw = input
    .trim()
    .toLowerCase()
    .replace(/^https:\/\//, '')
    .replace(/\/+$/, '')
  if (raw.length === 0 || raw.length > 253) return null
  // Host names only: letters, digits, hyphens and dots, at least one dot, no port, no IP literal.
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/.test(raw)) {
    return null
  }
  if (raw === 'localhost' || raw.endsWith('.localhost') || raw.endsWith('.local')) return null
  if (raw.endsWith('.internal') || raw.endsWith('.arpa')) return null
  return raw
}

type Transport = (r: Request) => Promise<Response>

const transportOf = (env: Bindings): Transport =>
  env.FEDERATION_TRANSPORT
    ? (r) => (env.FEDERATION_TRANSPORT as { fetch(r: Request): Promise<Response> }).fetch(r)
    : (r) => fetch(r)

async function resolve(transport: Transport, host: string, type: 'A' | 'AAAA') {
  const res = await transport(
    new Request(`${DOH_URL}?name=${encodeURIComponent(host)}&type=${type}`, {
      headers: { accept: 'application/dns-json' },
    }),
  )
  if (!res.ok) throw new ApiError(502, 'Could not resolve the peer domain.')
  const body = (await res.json()) as { Status?: number; Answer?: { type: number; data: string }[] }
  const want = type === 'A' ? 1 : 28
  return (body.Answer ?? []).filter((a) => a.type === want).map((a) => a.data)
}

/** Throws unless the host resolves only to public addresses. */
export async function assertPublicHost(env: Bindings, host: string): Promise<void> {
  const transport = transportOf(env)
  const [a, aaaa] = await Promise.all([
    resolve(transport, host, 'A'),
    resolve(transport, host, 'AAAA'),
  ])
  if (a.length + aaaa.length === 0) throw new ApiError(502, 'The peer domain does not resolve.')
  // Same address policy as the icon proxy and event integrations.
  if ([...a, ...aaaa].some(isBlockedIpLiteral)) {
    throw new ApiError(400, 'The peer domain resolves to a private or reserved address.')
  }
}

/**
 * Fetches an https URL on a vetted peer domain. Redirects are refused and the call times out.
 * `checkDns` can be skipped only for a request that just checked the same host.
 */
export async function safeFetch(env: Bindings, request: Request, checkDns = true) {
  const url = new URL(request.url)
  if (url.protocol !== 'https:' || url.port !== '' || url.username || url.password) {
    throw new ApiError(400, 'Federation only talks to https peers on the default port.')
  }
  if (!parsePeerDomain(url.hostname)) throw new ApiError(400, 'Invalid peer domain.')
  if (checkDns) await assertPublicHost(env, url.hostname)
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
  try {
    const res = await transportOf(env)(
      new Request(request, { redirect: 'manual', signal: controller.signal }),
    )
    if (res.status >= 300 && res.status < 400) {
      throw new ApiError(502, 'The peer answered with a redirect, which federation refuses.')
    }
    return res
  } catch (err) {
    if (err instanceof ApiError) throw err
    throw new ApiError(502, 'The peer could not be reached.')
  } finally {
    clearTimeout(timer)
  }
}

/** Reads a JSON body of at most `limit` bytes. */
export async function readJson<T>(res: Response, limit = 8 * 1024 * 1024): Promise<T> {
  const text = await readText(res, limit)
  try {
    return JSON.parse(text) as T
  } catch {
    throw new ApiError(502, 'The peer sent an invalid response.')
  }
}

export async function readText(res: Response, limit: number): Promise<string> {
  const declared = Number(res.headers.get('content-length') ?? '0')
  if (declared > limit) throw new ApiError(502, 'The peer response is too large.')
  const reader = res.body?.getReader()
  if (!reader) return ''
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > limit) {
      await reader.cancel()
      throw new ApiError(502, 'The peer response is too large.')
    }
    chunks.push(value)
  }
  const out = new Uint8Array(total)
  let o = 0
  for (const c of chunks) {
    out.set(c, o)
    o += c.byteLength
  }
  return new TextDecoder().decode(out)
}
