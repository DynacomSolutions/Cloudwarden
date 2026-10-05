// Logic shared by the HTML admin (app.ts) and the JSON admin API (api.ts) (TASKS #150).

import { isReservedBlobKey } from '../blob-keys'
import { createDb } from '../db'
import { createEmailTransport, type EmailTransport, inviteEmail } from '../email'
import { mailStatus, newInviteCode } from '../emailless'
import type { Bindings } from '../env'
import { ApiError } from '../errors'
import { log } from '../log'
import { AdminEventType } from '../orgs/constants'
import { assertNotSoleOwner } from '../orgs/members'
import { SERVER_VERSION } from '../routes/config'
import { type GrantableRole, instanceRoleOf, isAdminEmail } from './security'

export { AdminEventType }

/** Who performed an admin write. `actor` is a user id when known (API); null for the HTML admin. */
export interface Audit {
  actor: string | null
  ipAddress?: string | null
  deviceType?: number | null
  now?: number
}

const TFA_NAMES: Record<number, string> = {
  0: 'Authenticator',
  1: 'Email',
  2: 'Duo',
  3: 'YubiKey',
  6: 'Duo (organisation)',
  7: 'Passkey',
}
export const tfaName = (type: number) => TFA_NAMES[type] ?? `Type ${type}`

const nowOf = (a?: Audit) => a?.now ?? Date.now()

/** One audit event insert; add it to the batch of the write it records. */
export function auditStatement(
  db: D1Database,
  audit: Audit,
  type: number,
  target: { userUuid?: string; organizationUuid?: string } = {},
  /** Records the event only while this holds (evaluated inside the same batch, after earlier writes). */
  onlyIf?: { sql: string; args: (string | number)[] },
) {
  const values = `?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8`
  return db
    .prepare(
      `INSERT INTO events (uuid, event_type, user_uuid, organization_uuid, acting_user_uuid, device_type, ip_address, event_date)
       ${onlyIf ? `SELECT ${values} WHERE ${onlyIf.sql.replace(/\?(\d+)/g, (_, n) => `?${Number(n) + 8}`)}` : `VALUES (${values})`}`,
    )
    .bind(
      crypto.randomUUID(),
      type,
      target.userUuid ?? null,
      target.organizationUuid ?? null,
      audit.actor,
      audit.deviceType ?? null,
      audit.ipAddress ?? null,
      nowOf(audit),
      ...(onlyIf?.args ?? []),
    )
}

export const emailTransportFor = (env: Bindings, override?: (env: Bindings) => EmailTransport) =>
  (override ?? createEmailTransport)(env)

const base = (env: Bindings) => env.DOMAIN.replace(/\/+$/, '')

// Reads ---------------------------------------------------------------------

export async function overviewCounts(db: D1Database) {
  const count = async (sql: string) => (await db.prepare(sql).first<{ n: number }>())?.n ?? 0
  const [users, organizations, ciphers, sends] = await Promise.all([
    count('SELECT COUNT(*) AS n FROM users'),
    count('SELECT COUNT(*) AS n FROM organizations'),
    count('SELECT COUNT(*) AS n FROM ciphers'),
    count('SELECT COUNT(*) AS n FROM sends'),
  ])
  return { users, organizations, ciphers, sends }
}

export function serverConfig(env: Bindings, transport: EmailTransport) {
  return {
    version: SERVER_VERSION,
    domain: env.DOMAIN,
    signupsAllowed: env.SIGNUPS_ALLOWED === 'true',
    adminEnabled: env.ADMIN_ENABLED === 'true',
    emailConfigured: transport.configured,
    email: mailStatus(env, transport.configured),
    jwtSecretConfigured: Boolean(env.JWT_SECRET),
  }
}

export interface UserRow {
  uuid: string
  email: string
  name: string
  created_at: number
  enabled: number
  verified_at: number | null
  instance_role: string
  last_active: number | null
  items: number
  tfa: string | null
}

export const parseTfa = (tfa: string | null): number[] => (tfa ? tfa.split(',').map(Number) : [])

/** One page of users, newest first. Fetches one extra row so callers know whether more exist. */
export async function listUsers(db: D1Database, page: number, pageSize: number) {
  const { results } = await db
    .prepare(
      `SELECT u.uuid, u.email, u.name, u.created_at, u.enabled, u.verified_at, u.instance_role,
        (SELECT MAX(d.updated_at) FROM devices d WHERE d.user_uuid = u.uuid) AS last_active,
        (SELECT COUNT(*) FROM ciphers x WHERE x.user_uuid = u.uuid) AS items,
        (SELECT GROUP_CONCAT(t.atype) FROM twofactor t WHERE t.user_uuid = u.uuid AND t.enabled = 1 AND t.atype != 8) AS tfa
       FROM users u ORDER BY u.created_at DESC, u.uuid LIMIT ?1 OFFSET ?2`,
    )
    .bind(pageSize + 1, (page - 1) * pageSize)
    .all<UserRow>()
  return { rows: results.slice(0, pageSize), hasMore: results.length > pageSize }
}

export async function countUsers(db: D1Database) {
  return (await db.prepare('SELECT COUNT(*) AS n FROM users').first<{ n: number }>())?.n ?? 0
}

export async function listInvitations(db: D1Database, limit = 50) {
  const { results } = await db
    .prepare(
      'SELECT email, created_at, token_expires_at FROM invitations ORDER BY created_at DESC LIMIT ?1',
    )
    .bind(limit)
    .all<{ email: string; created_at: number; token_expires_at: number | null }>()
  return results
}

export async function listOrganizations(db: D1Database, limit = 200) {
  const { results } = await db
    .prepare(
      `SELECT o.uuid, o.name, o.created_at,
        (SELECT COUNT(*) FROM users_organizations m WHERE m.organization_uuid = o.uuid) AS members,
        (SELECT COUNT(*) FROM ciphers x WHERE x.organization_uuid = o.uuid) AS ciphers
       FROM organizations o ORDER BY o.created_at DESC LIMIT ?1`,
    )
    .bind(limit)
    .all<{ uuid: string; name: string; created_at: number; members: number; ciphers: number }>()
  return results
}

export async function diagnostics(db: D1Database) {
  const started = Date.now()
  const one = async (sql: string, ...args: unknown[]) =>
    (await db
      .prepare(sql)
      .bind(...args)
      .first<Record<string, number>>()) ?? {}
  const att = await one(
    'SELECT COUNT(*) AS n, COALESCE(SUM(file_size),0) AS bytes FROM attachments',
  )
  const fileSends = await one('SELECT COUNT(*) AS n FROM sends WHERE r2_key IS NOT NULL')
  const inv = await one('SELECT COUNT(*) AS n FROM invitations')
  return {
    attachments: att.n ?? 0,
    attachmentBytes: att.bytes ?? 0,
    fileSends: fileSends.n ?? 0,
    pendingInvitations: inv.n ?? 0,
    dbRoundTripMs: Date.now() - started,
  }
}

// Writes --------------------------------------------------------------------

/** A refused admin action. `reason` lets the HTML admin pick its message without parsing text. */
export class AdminRefusal extends ApiError {
  constructor(
    readonly reason: 'sole-owner' | 'admin-target',
    message: string,
  ) {
    super(400, message)
  }
}

/**
 * Resolves the target of a destructive action. Returns false when the user does not exist and
 * throws when the user is an admin: admins cannot be locked out or removed by another admin
 * through this interface (use the database or CLI for that).
 */
async function guardTarget(env: Bindings, id: string): Promise<boolean> {
  const row = await env.DB.prepare('SELECT email FROM users WHERE uuid = ?1')
    .bind(id)
    .first<{ email: string }>()
  if (!row) return false
  if (isAdminEmail(env.ADMIN_EMAILS, row.email.trim().toLowerCase())) {
    throw new AdminRefusal('admin-target', 'This action cannot be applied to an admin account.')
  }
  return true
}

const userExists = async (db: D1Database, id: string) =>
  (await db.prepare('SELECT 1 AS x FROM users WHERE uuid = ?1').bind(id).first()) !== null

/** Disables or enables an account. Returns false when the user does not exist. */
export async function setUserEnabled(
  env: Bindings,
  id: string,
  enabled: boolean,
  audit: Audit,
): Promise<boolean> {
  const db = env.DB
  if (!enabled ? !(await guardTarget(env, id)) : !(await userExists(db, id))) return false
  await db.batch([
    db
      .prepare('UPDATE users SET enabled = ?1, updated_at = ?2 WHERE uuid = ?3')
      .bind(enabled ? 1 : 0, nowOf(audit), id),
    auditStatement(db, audit, enabled ? AdminEventType.UserEnabled : AdminEventType.UserDisabled, {
      userUuid: id,
    }),
  ])
  return true
}

const isStandIn = async (db: D1Database, id: string, passwordHash: string) =>
  passwordHash.startsWith('!federated.') ||
  (await db
    .prepare('SELECT 1 AS x FROM federation_shadow_users WHERE user_uuid = ?1')
    .bind(id)
    .first()) !== null

/**
 * Grants or revokes the instance `admin` role (TASKS #360). Returns false when the user does not
 * exist. Refused (400) for an owner (the role comes from ADMIN_EMAILS and only the operator can
 * change it), for yourself, and when granting to an account that is unverified or disabled. The
 * grant statement re-checks verification and enabled state, so an email change racing the grant
 * cannot leave an admin role on an unverified address.
 */
export async function setUserRole(
  env: Bindings,
  id: string,
  role: GrantableRole,
  audit: Audit,
): Promise<boolean> {
  const db = env.DB
  const row = await db
    .prepare(
      'SELECT email, password_hash, instance_role, verified_at, enabled FROM users WHERE uuid = ?1',
    )
    .bind(id)
    .first<{
      email: string
      password_hash: string
      instance_role: string
      verified_at: number | null
      enabled: number
    }>()
  if (!row) return false
  const isOwner = instanceRoleOf(env, { email: row.email }) === 'owner'
  // Owners cannot be granted a role. Revoking is allowed so a stored `admin` does not outlive the
  // address leaving ADMIN_EMAILS; it has no effect while the address is still listed.
  if (isOwner && role === 'admin') {
    throw new ApiError(
      400,
      'Owners come from the ADMIN_EMAILS setting of the server and cannot be changed here.',
    )
  }
  if (audit.actor === id) throw new ApiError(400, 'You cannot change your own role.')
  if (role === 'admin') {
    if (await isStandIn(db, id, row.password_hash)) {
      throw new ApiError(400, 'A federated stand-in account cannot be made an admin.')
    }
    if (row.verified_at === null) {
      throw new ApiError(400, 'Only a user with a verified email address can be made an admin.')
    }
    if (row.enabled !== 1) throw new ApiError(400, 'A disabled user cannot be made an admin.')
  }
  if (row.instance_role === role) return true
  const grantGuard =
    role === 'admin'
      ? " AND verified_at IS NOT NULL AND enabled = 1 AND email = ?4 AND password_hash NOT LIKE '!federated.%'"
      : ''
  const results = await db.batch([
    db
      .prepare(`UPDATE users SET instance_role = ?1, updated_at = ?2 WHERE uuid = ?3${grantGuard}`)
      .bind(...(role === 'admin' ? [role, nowOf(audit), id, row.email] : [role, nowOf(audit), id])),
    auditStatement(
      db,
      audit,
      AdminEventType.UserRoleChanged,
      { userUuid: id },
      {
        sql: 'EXISTS (SELECT 1 FROM users WHERE uuid = ?1 AND instance_role = ?2)',
        args: [id, role],
      },
    ),
  ])
  if ((results[0]?.meta.changes ?? 0) === 0) {
    if (role !== 'admin') return false
    throw new ApiError(400, 'This user cannot be made an admin right now. Reload and try again.')
  }
  return true
}

/** Rotates the security stamp so every session and token of the user stops working. */
export async function deauthorizeUser(env: Bindings, id: string, audit: Audit): Promise<boolean> {
  const db = env.DB
  if (!(await guardTarget(env, id))) return false
  await db.batch([
    db
      .prepare('UPDATE users SET security_stamp = ?1, updated_at = ?2 WHERE uuid = ?3')
      .bind(crypto.randomUUID(), nowOf(audit), id),
    auditStatement(db, audit, AdminEventType.UserDeauthorized, { userUuid: id }),
  ])
  return true
}

/** Removes every second factor and remembered device, and signs the user out everywhere. */
export async function removeTwoFactor(env: Bindings, id: string, audit: Audit): Promise<boolean> {
  const db = env.DB
  if (!(await guardTarget(env, id))) return false
  await db.batch([
    db.prepare('DELETE FROM twofactor WHERE user_uuid = ?1').bind(id),
    db.prepare('UPDATE devices SET twofactor_remember = NULL WHERE user_uuid = ?1').bind(id),
    db
      .prepare(
        'UPDATE users SET totp_recover = NULL, security_stamp = ?2, updated_at = ?3 WHERE uuid = ?1',
      )
      .bind(id, crypto.randomUUID(), nowOf(audit)),
    auditStatement(db, audit, AdminEventType.UserTwoFactorRemoved, { userUuid: id }),
  ])
  return true
}

/** Best effort: the rows are already gone, so a failure only leaves orphans for the sweeper. */
export async function deleteBlobs(env: Bindings, keys: string[]) {
  const safe = keys.filter((k) => !isReservedBlobKey(k))
  try {
    for (let i = 0; i < safe.length; i += 1000)
      await env.ATTACHMENTS.delete(safe.slice(i, i + 1000))
  } catch {
    log('error', 'admin.blob_delete_failed', {}, env)
  }
}

/**
 * Deletes a user and their blobs. Throws the same 400 as account self-deletion when the user is
 * the only confirmed owner of an organisation. Returns false when the user does not exist.
 */
export async function deleteUser(env: Bindings, id: string, audit: Audit): Promise<boolean> {
  const db = env.DB
  if (!(await guardTarget(env, id))) return false
  try {
    await assertNotSoleOwner(createDb(db), id)
  } catch (e) {
    if (e instanceof ApiError) throw new AdminRefusal('sole-owner', e.message)
    throw e
  }
  const { results } = await db
    .prepare(
      `SELECT a.r2_key AS k FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid WHERE c.user_uuid = ?1
       UNION SELECT r2_key FROM sends WHERE user_uuid = ?1 AND r2_key IS NOT NULL`,
    )
    .bind(id)
    .all<{ k: string }>()
  await db.batch([
    db.prepare('DELETE FROM users WHERE uuid = ?1').bind(id),
    auditStatement(db, audit, AdminEventType.UserDeleted, { userUuid: id }),
  ])
  await deleteBlobs(
    env,
    results.map((r) => r.k),
  )
  return true
}

export async function deleteOrganization(
  env: Bindings,
  id: string,
  audit: Audit,
): Promise<boolean> {
  const db = env.DB
  const exists = await db
    .prepare('SELECT 1 AS x FROM organizations WHERE uuid = ?1')
    .bind(id)
    .first()
  if (!exists) return false
  const { results } = await db
    .prepare(
      `SELECT a.r2_key AS k FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid WHERE c.organization_uuid = ?1
       UNION SELECT r2_key FROM sends WHERE organization_uuid = ?1 AND r2_key IS NOT NULL`,
    )
    .bind(id)
    .all<{ k: string }>()
  await db.batch([
    db.prepare('DELETE FROM organizations WHERE uuid = ?1').bind(id),
    auditStatement(db, audit, AdminEventType.OrganizationDeleted, { organizationUuid: id }),
  ])
  await deleteBlobs(
    env,
    results.map((r) => r.k),
  )
  return true
}

export type InviteMail = 'sent' | 'not-configured' | 'failed'

/** Records an invitation (idempotent per address) and tries to email it. `email` must be normalised. */
export async function createInvitation(
  env: Bindings,
  email: string,
  invitedBy: string,
  audit: Audit,
  transport: EmailTransport,
): Promise<{
  created: boolean
  createdAt: number
  mail: InviteMail
  /** Copyable link with a one-time code, only when mail is off (shown once, never stored). */
  link: string | null
  codeExpiresAt: number | null
}> {
  const db = env.DB
  const t = nowOf(audit)
  const insert = await db
    .prepare(
      `INSERT INTO invitations (uuid, email, invited_by, created_at) VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT (email) DO NOTHING`,
    )
    .bind(crypto.randomUUID(), email, invitedBy, t)
    .run()
  const created = (insert.meta.changes ?? 0) > 0
  // Event rows never carry the address (it is personal data); the invitation row does.
  if (created) await auditStatement(db, audit, AdminEventType.InvitationCreated).run()
  const row = await db
    .prepare('SELECT created_at FROM invitations WHERE email = ?1')
    .bind(email)
    .first<{ created_at: number }>()
  let mail: InviteMail = 'not-configured'
  let link: string | null = null
  let codeExpiresAt: number | null = null
  if (!transport.configured) {
    // No mail: the admin hands over a link whose code is the proof (docs/emailless.md). Asking
    // again for the same address issues a new code and retires the old one.
    const { code: secretCode, hash, expiresAt } = await newInviteCode(t)
    await db
      .prepare('UPDATE invitations SET token_hash = ?1, token_expires_at = ?2 WHERE email = ?3')
      .bind(hash, expiresAt, email)
      .run()
    link = `${base(env)}/#/instance-setup?email=${encodeURIComponent(email)}&code=${encodeURIComponent(secretCode)}`
    codeExpiresAt = expiresAt
  } else {
    try {
      await transport.send({
        to: email,
        ...inviteEmail(`${base(env)}/#/signup?email=${encodeURIComponent(email)}`),
      })
      mail = 'sent'
    } catch {
      log('error', 'admin.invite_delivery_failed', {}, env)
      mail = 'failed'
    }
  }
  return { created, createdAt: row?.created_at ?? t, mail, link, codeExpiresAt }
}

export async function deleteInvitation(
  db: D1Database,
  email: string,
  audit: Audit,
): Promise<boolean> {
  const del = await db.prepare('DELETE FROM invitations WHERE email = ?1').bind(email).run()
  if ((del.meta.changes ?? 0) === 0) return false
  await auditStatement(db, audit, AdminEventType.InvitationDeleted).run()
  return true
}
