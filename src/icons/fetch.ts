import { validateHost, validateUrl } from './ssrf'

export const MAX_BYTES = 512 * 1024
export const REQUEST_TIMEOUT_MS = 5000
export const OVERALL_TIMEOUT_MS = 15000
export const MAX_REDIRECTS = 3

export type Fetcher = (input: string, init?: RequestInit) => Promise<Response>

/** Filled in while fetching; `transient` means a retry could succeed (timeout, 5xx, 429). */
export interface FetchState {
  transient: boolean
}

export interface Icon {
  bytes: Uint8Array
  contentType: string
}

const IMAGE_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/x-icon',
  'image/vnd.microsoft.icon',
])

/** Identify an image by magic number. SVG is deliberately unsupported (script-capable). */
export function sniffImage(b: Uint8Array): string | null {
  const at = (i: number) => b[i] ?? -1
  if (at(0) === 0x89 && at(1) === 0x50 && at(2) === 0x4e && at(3) === 0x47) return 'image/png'
  if (at(0) === 0xff && at(1) === 0xd8 && at(2) === 0xff) return 'image/jpeg'
  if (at(0) === 0x47 && at(1) === 0x49 && at(2) === 0x46 && at(3) === 0x38) return 'image/gif'
  if (
    at(0) === 0x52 &&
    at(1) === 0x49 &&
    at(2) === 0x46 &&
    at(3) === 0x46 &&
    at(8) === 0x57 &&
    at(9) === 0x45
  ) {
    return 'image/webp'
  }
  if (at(0) === 0 && at(1) === 0 && at(2) === 1 && at(3) === 0) return 'image/x-icon'
  return null
}

/** Read at most `max` bytes. `truncated` is true when the body was longer. */
export async function readCapped(
  res: Response,
  max: number,
): Promise<{ bytes: Uint8Array; truncated: boolean }> {
  if (!res.body) return { bytes: new Uint8Array(0), truncated: false }
  const reader = res.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  let truncated = false
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.length
    if (total > max) {
      chunks.push(value.slice(0, value.length - (total - max)))
      truncated = true
      await reader.cancel().catch(() => {})
      break
    }
    chunks.push(value)
  }
  const bytes = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0))
  let off = 0
  for (const c of chunks) {
    bytes.set(c, off)
    off += c.length
  }
  return { bytes, truncated }
}

/**
 * GET a URL following at most MAX_REDIRECTS redirects, validating every hop. Returns the final
 * 2xx response and its URL, or null on any refusal or failure.
 */
export async function safeGet(
  start: URL,
  fetcher: Fetcher,
  accept: string,
  overall: AbortSignal,
  state: FetchState = { transient: false },
): Promise<{ res: Response; url: URL } | null> {
  let url = start
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    // Every hop, including the first, must be https and pass the SSRF checks.
    if (url.protocol !== 'https:' || !validateUrl(url).ok) return null
    let res: Response
    try {
      res = await fetcher(url.toString(), {
        method: 'GET',
        redirect: 'manual',
        headers: { Accept: accept, 'User-Agent': 'Cloudwarden-Icons/1' },
        signal: AbortSignal.any([overall, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]),
      })
    } catch {
      state.transient = true
      return null
    }
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location')
      await res.body?.cancel().catch(() => {})
      if (!loc) return null
      try {
        url = new URL(loc, url)
      } catch {
        return null
      }
      continue
    }
    if (res.status < 200 || res.status >= 300) {
      if (res.status >= 500 || res.status === 429 || res.status === 408) state.transient = true
      await res.body?.cancel().catch(() => {})
      return null
    }
    return { res, url }
  }
  return null
}

async function readIcon(got: { res: Response } | null): Promise<Icon | null> {
  if (!got) return null
  const declared =
    (got.res.headers.get('content-type') ?? '').split(';')[0]?.trim().toLowerCase() ?? ''
  const length = Number(got.res.headers.get('content-length') ?? 0)
  if (length > MAX_BYTES) {
    await got.res.body?.cancel().catch(() => {})
    return null
  }
  // Servers often label favicons octet-stream or text/plain; the declared type must still be image/*
  // or a generic binary type, and the magic number decides the type we serve.
  const plausible = IMAGE_TYPES.has(declared) || declared === 'application/octet-stream'
  if (!plausible) {
    await got.res.body?.cancel().catch(() => {})
    return null
  }
  const { bytes, truncated } = await readCapped(got.res, MAX_BYTES)
  if (truncated || bytes.length < 8) return null
  const sniffed = sniffImage(bytes)
  if (!sniffed) return null
  return { bytes, contentType: sniffed }
}

const LINK_TAG = /<link\b[^>]*>/gi

function attr(tag: string, name: string): string | null {
  const m = new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i').exec(tag)
  return m ? (m[1] ?? m[2] ?? m[3] ?? '') : null
}

/** Candidate icon URLs from `<link rel=icon>` tags, best first. */
export function parseIconLinks(html: string, base: URL): URL[] {
  const ranked: { url: URL; rank: number }[] = []
  for (const tag of html.match(LINK_TAG) ?? []) {
    const rel = (attr(tag, 'rel') ?? '').toLowerCase().split(/\s+/)
    const href = attr(tag, 'href')
    if (!href || !rel.includes('icon')) continue
    try {
      const url = new URL(href.trim(), base)
      if (validateUrl(url).ok) ranked.push({ url, rank: rel.includes('shortcut') ? 0 : 1 })
    } catch {
      // Unparseable href: skip.
    }
  }
  return ranked.sort((a, b) => a.rank - b.rank).map((r) => r.url)
}

const IMAGE_ACCEPT = 'image/png,image/x-icon,image/vnd.microsoft.icon,image/*;q=0.8'

/** Find an icon for a validated hostname: /favicon.ico first, then the homepage's link tags. */
export async function fetchIcon(
  host: string,
  fetcher: Fetcher,
  state: FetchState = { transient: false },
): Promise<Icon | null> {
  if (!validateHost(host).ok) return null
  const overall = AbortSignal.timeout(OVERALL_TIMEOUT_MS)

  const direct = await readIcon(
    await safeGet(new URL(`https://${host}/favicon.ico`), fetcher, IMAGE_ACCEPT, overall, state),
  )
  if (direct) return direct

  const page = await safeGet(new URL(`https://${host}/`), fetcher, 'text/html', overall, state)
  if (!page) return null
  const type = (page.res.headers.get('content-type') ?? '').toLowerCase()
  if (!type.includes('html')) {
    await page.res.body?.cancel().catch(() => {})
    return null
  }
  const { bytes } = await readCapped(page.res, MAX_BYTES)
  const html = new TextDecoder().decode(bytes)
  for (const candidate of parseIconLinks(html, page.url).slice(0, 3)) {
    const icon = await readIcon(await safeGet(candidate, fetcher, IMAGE_ACCEPT, overall, state))
    if (icon) return icon
  }
  return null
}
