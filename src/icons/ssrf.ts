/**
 * SSRF guard for the icon proxy (TASKS #142). Every hostname the proxy contacts, including
 * redirect targets and icon URLs found in HTML, passes through `validateHost` first.
 */

const MAX_HOST_LENGTH = 253
const LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
const TLD = /^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$/

/** Suffixes that are never public or never worth fetching. */
const BLOCKED_SUFFIXES = [
  'localhost',
  'local',
  'internal',
  'localdomain',
  'lan',
  'home',
  'corp',
  'intranet',
  'private',
  'invalid',
  'test',
  'example',
  'arpa',
  'onion',
]

export type HostCheck = { ok: true; host: string } | { ok: false; reason: string }

/** Parse an IPv4 literal in dotted, decimal, hex or octal forms (inet_aton style). */
export function parseIPv4(input: string): number[] | null {
  const parts = input.split('.')
  if (parts.length < 1 || parts.length > 4 || parts.some((p) => p === '')) return null
  const nums: number[] = []
  for (const p of parts) {
    let n: number
    if (/^0x[0-9a-f]+$/i.test(p)) n = Number.parseInt(p, 16)
    else if (/^0[0-7]+$/.test(p)) n = Number.parseInt(p, 8)
    else if (/^(0|[1-9][0-9]*)$/.test(p)) n = Number.parseInt(p, 10)
    else return null
    if (!Number.isFinite(n)) return null
    nums.push(n)
  }
  const last = nums[nums.length - 1] as number
  const head = nums.slice(0, -1)
  if (head.some((n) => n > 255)) return null
  if (last >= 256 ** (5 - nums.length)) return null
  const bytes = [...head]
  for (let i = 4 - nums.length; i >= 0; i--) bytes.push(Math.floor(last / 256 ** i) % 256)
  return bytes.length === 4 ? bytes : null
}

/** Parse an IPv6 literal (no brackets, no zone) into 8 groups, or null. */
export function parseIPv6(input: string): number[] | null {
  if (!input.includes(':') || /[^0-9a-f:.]/i.test(input)) return null
  let s = input.toLowerCase()
  const lastColon = s.lastIndexOf(':')
  const tail = s.slice(lastColon + 1)
  if (tail.includes('.')) {
    const v4 = parseIPv4(tail)
    if (v4?.length !== 4) return null
    const hi = (((v4[0] as number) << 8) | (v4[1] as number)).toString(16)
    const lo = (((v4[2] as number) << 8) | (v4[3] as number)).toString(16)
    s = `${s.slice(0, lastColon + 1)}${hi}:${lo}`
  }
  const halves = s.split('::')
  if (halves.length > 2) return null
  const toGroups = (h: string) => (h === '' ? [] : h.split(':'))
  const head = toGroups(halves[0] as string)
  const rest = halves.length === 2 ? toGroups(halves[1] as string) : []
  if (halves.length === 1 && head.length !== 8) return null
  if (halves.length === 2 && head.length + rest.length > 7) return null
  const fill = halves.length === 2 ? new Array(8 - head.length - rest.length).fill('0') : []
  const groups = [...head, ...fill, ...rest]
  if (groups.length !== 8) return null
  const out: number[] = []
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null
    out.push(Number.parseInt(g, 16))
  }
  return out
}

/** True when the IPv4 address is not publicly routable. */
export function isBlockedIPv4(b: number[]): boolean {
  const [a, c] = [b[0] as number, b[1] as number]
  return (
    a === 0 || // this network
    a === 10 || // private
    a === 127 || // loopback
    (a === 100 && c >= 64 && c <= 127) || // CGNAT
    (a === 169 && c === 254) || // link-local, cloud metadata
    (a === 172 && c >= 16 && c <= 31) || // private
    (a === 192 && c === 168) || // private
    (a === 192 && c === 0) || // IETF protocol assignments and documentation
    (a === 198 && (c === 18 || c === 19)) || // benchmarking
    (a === 198 && c === 51) || // documentation
    (a === 203 && c === 0) || // documentation
    a >= 224 // multicast, reserved, broadcast
  )
}

/** True when the IPv6 address is not publicly routable (including v4-mapped and NAT64 forms). */
export function isBlockedIPv6(g: number[]): boolean {
  const first = g[0] as number
  if (g.every((x) => x === 0)) return true // unspecified
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return true // loopback
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) {
    // v4-mapped and v4-compatible
    return isBlockedIPv4([
      (g[6] as number) >> 8,
      (g[6] as number) & 255,
      (g[7] as number) >> 8,
      (g[7] as number) & 255,
    ])
  }
  if (first === 0x64 && g[1] === 0xff9b) return true // NAT64
  if ((first & 0xfe00) === 0xfc00) return true // unique local
  if ((first & 0xffc0) === 0xfe80) return true // link-local
  if ((first & 0xffc0) === 0xfec0) return true // site-local
  if ((first & 0xff00) === 0xff00) return true // multicast
  if (first === 0x2001 && g[1] === 0x0db8) return true // documentation
  if (first === 0x2002) return true // 6to4, can embed private v4
  return false
}

/** True when `host` is an IP literal (any v4 form or v6, bracketed or not) in a non-public range. */
export function isBlockedIpLiteral(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '')
  const v6 = parseIPv6(h)
  if (v6) return isBlockedIPv6(v6)
  const v4 = parseIPv4(h)
  if (v4) return isBlockedIPv4(v4)
  return false
}

/** True when `host` parses as any IP literal at all. */
export function isIpLiteral(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '')
  return parseIPv6(h) !== null || parseIPv4(h) !== null
}

/**
 * Validate a hostname that the proxy may contact. Accepts only ASCII (or punycode) DNS names with
 * at least two labels and an alphabetic top-level label. Rejects IP literals in every encoding.
 */
export function validateHost(input: string): HostCheck {
  const raw = input.trim()
  if (raw.length === 0 || raw.length > MAX_HOST_LENGTH * 2) return { ok: false, reason: 'length' }
  if (/[\s/\\:@?#%[\]]/.test(raw)) return { ok: false, reason: 'charset' }

  let host = raw.toLowerCase()
  if (/[^\x21-\x7e]/.test(host)) {
    // Non-ASCII: normalise to punycode through the URL parser, then validate strictly.
    try {
      host = new URL(`https://${host}`).hostname
    } catch {
      return { ok: false, reason: 'charset' }
    }
  }
  if (host.endsWith('.')) host = host.slice(0, -1)
  if (host.length === 0 || host.length > MAX_HOST_LENGTH) return { ok: false, reason: 'length' }

  if (isIpLiteral(host)) return { ok: false, reason: 'ip-literal' }

  const labels = host.split('.')
  if (labels.length < 2) return { ok: false, reason: 'no-public-suffix' }
  if (!labels.every((l) => LABEL.test(l))) return { ok: false, reason: 'charset' }
  if (!TLD.test(labels[labels.length - 1] as string)) return { ok: false, reason: 'tld' }
  if (BLOCKED_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`))) {
    return { ok: false, reason: 'reserved-name' }
  }
  return { ok: true, host }
}

/** Validate a full URL the proxy is about to request: scheme, port, credentials and host. */
export function validateUrl(url: URL): HostCheck {
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return { ok: false, reason: 'scheme' }
  if (url.username || url.password) return { ok: false, reason: 'credentials' }
  if (url.port !== '' && url.port !== '80' && url.port !== '443')
    return { ok: false, reason: 'port' }
  return validateHost(url.hostname)
}
