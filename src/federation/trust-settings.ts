// Incoming trust settings for peers (TASKS #381): whether a valid signed pairing request from
// another instance is trusted at once, and the list of domains whose requests are refused.
import { eq } from 'drizzle-orm'
import { createDb, schema } from '../db'
import type { Bindings } from '../env'

const SETTINGS_KEY = 'federation'

/** Peers trusted automatically on this side at most; further requests wait for an admin. */
export const MAX_AUTO_ACCEPTED_PEERS = 25

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

export async function isBlockedDomain(env: Bindings, domain: string): Promise<boolean> {
  const [row] = await createDb(env.DB)
    .select({ d: schema.federationBlockedDomains.domain })
    .from(schema.federationBlockedDomains)
    .where(eq(schema.federationBlockedDomains.domain, domain))
    .limit(1)
  return !!row
}

export async function listBlockedDomains(env: Bindings) {
  const rows = await createDb(env.DB).select().from(schema.federationBlockedDomains)
  return rows
    .map((r) => ({ domain: r.domain, date: new Date(r.createdAt).toISOString() }))
    .sort((a, b) => a.domain.localeCompare(b.domain))
}

export async function blockDomain(env: Bindings, domain: string, actor: string | null) {
  await createDb(env.DB)
    .insert(schema.federationBlockedDomains)
    .values({ domain, createdAt: Date.now(), createdBy: actor })
    .onConflictDoNothing()
}

export async function unblockDomain(env: Bindings, domain: string) {
  await createDb(env.DB)
    .delete(schema.federationBlockedDomains)
    .where(eq(schema.federationBlockedDomains.domain, domain))
}
