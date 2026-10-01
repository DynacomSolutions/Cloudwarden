import type { User } from '../env'

/**
 * Built-in global equivalent domain groups. `type` is the identifier clients use to
 * label a group. Extend this list as needed; it is deliberately small.
 */
export const GLOBAL_DOMAINS: { type: number; domains: string[] }[] = [
  { type: 0, domains: ['youtube.com', 'google.com', 'gmail.com'] },
  { type: 1, domains: ['apple.com', 'icloud.com'] },
]

const parseList = <T>(s: string): T[] => {
  try {
    const v = JSON.parse(s)
    return Array.isArray(v) ? v : []
  } catch {
    return []
  }
}

export function domainsJson(
  user: Pick<User, 'equivalentDomains' | 'excludedGlobals'>,
  includeGlobals = true,
) {
  const excluded = new Set(parseList<number>(user.excludedGlobals))
  return {
    equivalentDomains: parseList<string[]>(user.equivalentDomains),
    globalEquivalentDomains: includeGlobals
      ? GLOBAL_DOMAINS.map((g) => ({
          type: g.type,
          domains: g.domains,
          excluded: excluded.has(g.type),
        }))
      : [],
    object: 'domains',
  }
}
