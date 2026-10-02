import { and, eq, inArray, isNotNull, isNull, lt, lte } from 'drizzle-orm'
import { randomB64u } from '../auth/crypto'
import type { Db } from '../db'
import { createDb, schema } from '../db'
import type { Bindings } from '../env'
import { ApiError } from '../errors'
import { errorKind, log } from '../log'
import { Status } from './constants'

/**
 * Claimed (verified) domains (TASKS #286). An organisation proves control of a domain with a DNS
 * TXT record holding its token. Verified domains drive SSO discovery by email and mark members
 * with addresses on the domain as claimed by the organisation.
 */

export type DomainRow = typeof schema.organizationDomains.$inferSelect

/** Interval between background checks of an unverified domain, and how long to keep trying. */
export const DOMAIN_RECHECK_MS = 12 * 3600 * 1000
export const DOMAIN_MAX_CHECKS = 6
/** DNS over HTTPS resolver (JSON API). */
export const DOH_URL = 'https://cloudflare-dns.com/dns-query'

export const domainJson = (d: DomainRow) => ({
  object: 'organizationDomain',
  id: d.uuid,
  organizationId: d.organizationUuid,
  txt: d.txt,
  domainName: d.domainName,
  creationDate: new Date(d.createdAt).toISOString(),
  nextRunDate: new Date(d.nextRunAt).toISOString(),
  jobRunCount: d.jobRunCount,
  verifiedDate: d.verifiedAt === null ? null : new Date(d.verifiedAt).toISOString(),
  lastCheckedDate: d.lastCheckedAt === null ? null : new Date(d.lastCheckedAt).toISOString(),
})

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/

/** Normalises a domain name (lowercase, no scheme, no trailing dot) or returns null if invalid. */
export function normalizeDomain(input: string): string | null {
  let d = input.trim().toLowerCase()
  d = d
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/\.$/, '')
  if (d.length < 3 || d.length > 253) return null
  const labels = d.split('.')
  if (labels.length < 2) return null
  if (!labels.every((l) => LABEL.test(l))) return null
  if (/^[0-9]+$/.test(labels[labels.length - 1] ?? '')) return null
  return d
}

export const newDomainToken = () => `bw=${randomB64u(32)}`

export const emailDomain = (email: string) => email.trim().toLowerCase().split('@')[1] ?? ''

/** Reads TXT records through DNS over HTTPS. Joins split character strings of one record. */
export async function lookupTxt(name: string, fetcher: typeof fetch = fetch): Promise<string[]> {
  const url = `${DOH_URL}?name=${encodeURIComponent(name)}&type=TXT`
  const res = await fetcher(url, {
    headers: { Accept: 'application/dns-json' },
    signal: AbortSignal.timeout(5000),
  })
  if (!res.ok) throw new Error(`DNS lookup failed with status ${res.status}`)
  const body = (await res.json()) as { Status?: number; Answer?: { type: number; data: string }[] }
  if (body.Status !== 0) return []
  return (body.Answer ?? [])
    .filter((a) => a.type === 16)
    .map(
      (a) =>
        [...a.data.matchAll(/"((?:[^"\\]|\\.)*)"/g)]
          .map((m) => (m[1] ?? '').replace(/\\(.)/g, '$1'))
          .join('') || a.data,
    )
}

/** True when the domain publishes the organisation's token in a TXT record. */
export async function txtMatches(domain: DomainRow): Promise<boolean> {
  const records = await lookupTxt(domain.domainName)
  return records.some((r) => r.trim() === domain.txt)
}

/** True when another organisation has already verified the domain. */
export async function claimedElsewhere(db: Db, domain: DomainRow): Promise<boolean> {
  const [row] = await db
    .select({ uuid: schema.organizationDomains.uuid })
    .from(schema.organizationDomains)
    .where(
      and(
        eq(schema.organizationDomains.domainName, domain.domainName),
        isNotNull(schema.organizationDomains.verifiedAt),
      ),
    )
    .limit(1)
  return row !== undefined && row.uuid !== domain.uuid
}

/**
 * Checks one domain now and records the outcome. Returns the updated row. A domain another
 * organisation verified first is never verified a second time.
 */
export async function checkDomain(db: Db, domain: DomainRow, now = Date.now()): Promise<DomainRow> {
  let verified = false
  try {
    verified = (await txtMatches(domain)) && !(await claimedElsewhere(db, domain))
  } catch (err) {
    log('warn', 'domain.check_failed', { errorKind: errorKind(err) })
  }
  const next: Partial<DomainRow> = verified
    ? { verifiedAt: now, lastCheckedAt: now }
    : {
        lastCheckedAt: now,
        jobRunCount: domain.jobRunCount + 1,
        nextRunAt: now + DOMAIN_RECHECK_MS,
      }
  await db
    .update(schema.organizationDomains)
    .set(next)
    .where(
      and(
        eq(schema.organizationDomains.uuid, domain.uuid),
        isNull(schema.organizationDomains.verifiedAt),
      ),
    )
  return { ...domain, ...next }
}

/** Cron job: re-checks unverified domains that are due, up to the attempt limit. */
export async function verifyPendingDomains(env: Bindings, now = Date.now()): Promise<number> {
  const db = createDb(env.DB)
  const due = await db
    .select()
    .from(schema.organizationDomains)
    .where(
      and(
        isNull(schema.organizationDomains.verifiedAt),
        lte(schema.organizationDomains.nextRunAt, now),
        lt(schema.organizationDomains.jobRunCount, DOMAIN_MAX_CHECKS),
      ),
    )
    .limit(50)
  let verified = 0
  for (const d of due) if ((await checkDomain(db, d, now)).verifiedAt !== null) verified++
  return verified
}

/** Verified domain names per organisation, for the given organisations. */
export async function verifiedDomains(
  db: Db,
  orgUuids: string[],
): Promise<Map<string, Set<string>>> {
  const out = new Map<string, Set<string>>()
  if (orgUuids.length === 0) return out
  const rows = await db
    .select({
      org: schema.organizationDomains.organizationUuid,
      name: schema.organizationDomains.domainName,
    })
    .from(schema.organizationDomains)
    .where(
      and(
        inArray(schema.organizationDomains.organizationUuid, orgUuids),
        isNotNull(schema.organizationDomains.verifiedAt),
      ),
    )
  for (const r of rows) out.set(r.org, (out.get(r.org) ?? new Set()).add(r.name))
  return out
}

/** True when the organisation has verified the domain of `email`. */
export async function orgClaimsEmail(db: Db, orgUuid: string, email: string): Promise<boolean> {
  const domain = emailDomain(email)
  if (!domain) return false
  const [row] = await db
    .select({ uuid: schema.organizationDomains.uuid })
    .from(schema.organizationDomains)
    .where(
      and(
        eq(schema.organizationDomains.organizationUuid, orgUuid),
        eq(schema.organizationDomains.domainName, domain),
        isNotNull(schema.organizationDomains.verifiedAt),
      ),
    )
    .limit(1)
  return row !== undefined
}

/**
 * Organisations that claim the user: they verified the user's email domain and the user is an
 * accepted or confirmed member.
 */
export async function claimingOrganizations(db: Db, user: { uuid: string; email: string }) {
  const domain = emailDomain(user.email)
  if (!domain) return []
  const rows = await db
    .select({ org: schema.usersOrganizations.organizationUuid })
    .from(schema.usersOrganizations)
    .innerJoin(
      schema.organizationDomains,
      eq(schema.organizationDomains.organizationUuid, schema.usersOrganizations.organizationUuid),
    )
    .where(
      and(
        eq(schema.usersOrganizations.userUuid, user.uuid),
        inArray(schema.usersOrganizations.status, [Status.Accepted, Status.Confirmed]),
        eq(schema.organizationDomains.domainName, domain),
        isNotNull(schema.organizationDomains.verifiedAt),
      ),
    )
  return rows.map((r) => r.org)
}

/**
 * Claimed accounts are managed by their organisation: the member cannot delete the account,
 * purge the vault, change the email address or leave (TASKS #286). `orgUuid` limits the check to
 * one organisation (leaving).
 */
export async function assertNotClaimed(
  db: Db,
  user: { uuid: string; email: string },
  message: string,
  orgUuid?: string,
) {
  const orgs = await claimingOrganizations(db, user)
  if (orgUuid ? orgs.includes(orgUuid) : orgs.length > 0) throw new ApiError(400, message)
}
