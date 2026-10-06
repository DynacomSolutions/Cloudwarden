// Incoming trust settings for peers (TASKS #381): whether a valid signed pairing request from
// another instance is trusted at once, and the list of domains whose requests are refused.
import { eq } from 'drizzle-orm'
import { createDb, schema } from '../db'
import type { Bindings } from '../env'
import { parsePeerDomain } from './net'

const SETTINGS_KEY = 'federation'

/** Peers an incoming request trusted automatically (inbound only) at most; further ones wait. */
export const MAX_AUTO_ACCEPTED_PEERS = 25
/** Incoming requests waiting for an admin at most; admin-added peers do not count. */
export const MAX_INCOMING_PENDING = 20
/** Incoming requests nobody approved are dropped after this long. */
export const INCOMING_TTL_MS = 7 * 24 * 3_600_000

/** Whether incoming pairing requests need an instance admin's approval (default: no). */
export async function requireIncomingApproval(env: Bindings): Promise<boolean> {
  const [row] = await createDb(env.DB)
    .select({ config: schema.instanceSettings.config })
    .from(schema.instanceSettings)
    .where(eq(schema.instanceSettings.key, SETTINGS_KEY))
    .limit(1)
  if (!row) return false
  try {
    return (
      (JSON.parse(row.config) as { requireIncomingApproval?: unknown }).requireIncomingApproval ===
      true
    )
  } catch {
    return false
  }
}

export async function setRequireIncomingApproval(env: Bindings, value: boolean, actor: string) {
  const config = JSON.stringify({ requireIncomingApproval: value })
  const now = Date.now()
  await createDb(env.DB)
    .insert(schema.instanceSettings)
    .values({ key: SETTINGS_KEY, config, updatedAt: now, updatedBy: actor })
    .onConflictDoUpdate({
      target: schema.instanceSettings.key,
      set: { config, updatedAt: now, updatedBy: actor },
    })
}

export type BlockKind = 'domain' | 'instance' | 'fingerprint'

/**
 * Parses what an admin typed into a stored rule: a host name, a suffix pattern `*.example.net`
 * (the name itself and everything under it; there is no public suffix list here, so the admin
 * names the registrable domain), `instance:<uuid>` or `fp:<hex>`. Null when it is none of these.
 */
export function parseBlockRule(input: string): { value: string; kind: BlockKind } | null {
  const raw = input.trim().toLowerCase()
  const inst = /^instance:([0-9a-f-]{36})$/.exec(raw)
  if (inst) return { value: `instance:${inst[1]}`, kind: 'instance' }
  const fp = /^fp:([0-9a-f:\s-]+)$/.exec(raw)
  if (fp) {
    const hex = (fp[1] as string).replace(/[^0-9a-f]/g, '')
    return hex.length === 64 ? { value: `fp:${hex}`, kind: 'fingerprint' } : null
  }
  const wild = raw.startsWith('*.')
  const host = parsePeerDomain(wild ? raw.slice(2) : raw)
  return host ? { value: wild ? `*.${host}` : host, kind: 'domain' } : null
}

export interface PeerIdentity {
  domain: string
  instanceId?: string | null
  fingerprint?: string | null
}

/** Whether a stored rule matches a peer by name (exact or suffix), instance id or fingerprint. */
export function ruleMatches(rule: string, p: PeerIdentity): boolean {
  if (rule.startsWith('*.')) {
    const base = rule.slice(2)
    return p.domain === base || p.domain.endsWith(`.${base}`)
  }
  if (rule.startsWith('instance:')) return p.instanceId === rule.slice(9)
  if (rule.startsWith('fp:')) {
    return (p.fingerprint ?? '').replace(/[^0-9a-f]/gi, '').toLowerCase() === rule.slice(3)
  }
  return p.domain === rule
}

export async function isBlocked(env: Bindings, p: PeerIdentity): Promise<boolean> {
  const rows = await createDb(env.DB)
    .select({ d: schema.federationBlockedDomains.domain })
    .from(schema.federationBlockedDomains)
  return rows.some((r) => ruleMatches(r.d, p))
}

export const isBlockedDomain = (env: Bindings, domain: string) => isBlocked(env, { domain })

export async function listBlockedDomains(env: Bindings) {
  const rows = await createDb(env.DB).select().from(schema.federationBlockedDomains)
  return rows
    .map((r) => ({ domain: r.domain, kind: r.kind, date: new Date(r.createdAt).toISOString() }))
    .sort((a, b) => a.domain.localeCompare(b.domain))
}

export async function blockDomain(
  env: Bindings,
  value: string,
  kind: BlockKind,
  actor: string | null,
) {
  await createDb(env.DB)
    .insert(schema.federationBlockedDomains)
    .values({ domain: value, kind, createdAt: Date.now(), createdBy: actor })
    .onConflictDoNothing()
}

/** Removed without a block: the next incoming request from this domain waits for approval. */
export async function rememberRemoved(env: Bindings, domain: string) {
  await createDb(env.DB)
    .insert(schema.federationRemovedDomains)
    .values({ domain, removedAt: Date.now() })
    .onConflictDoUpdate({
      target: schema.federationRemovedDomains.domain,
      set: { removedAt: Date.now() },
    })
}

export async function wasRemoved(env: Bindings, domain: string): Promise<boolean> {
  const [r] = await createDb(env.DB)
    .select({ d: schema.federationRemovedDomains.domain })
    .from(schema.federationRemovedDomains)
    .where(eq(schema.federationRemovedDomains.domain, domain))
    .limit(1)
  return !!r
}

export async function forgetRemoved(env: Bindings, domain: string) {
  await createDb(env.DB)
    .delete(schema.federationRemovedDomains)
    .where(eq(schema.federationRemovedDomains.domain, domain))
}

export async function unblockDomain(env: Bindings, domain: string) {
  await createDb(env.DB)
    .delete(schema.federationBlockedDomains)
    .where(eq(schema.federationBlockedDomains.domain, domain))
}
