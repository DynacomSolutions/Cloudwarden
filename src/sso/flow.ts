import { and, eq, inArray, isNull, lt, sql } from 'drizzle-orm'
import { randomB64u, safeEqualStrings, sha256B64u } from '../auth/crypto'
import { normalizeEmail } from '../auth/users'
import { type Db, runBatch, schema } from '../db'
import type { Bindings, User } from '../env'
import { Role, Status } from '../orgs/constants'
import { orgClaimsEmail } from '../orgs/domains'
import { SsoError } from './errors'

/**
 * The SSO login flow between the official clients and the organisation's identity provider
 * (TASKS #280, #283):
 *
 * 1. `GET /identity/sso/prevalidate?domainHint=` returns a short-lived token for the organisation.
 * 2. `GET /identity/connect/authorize` checks the client, its redirect URI (allow-listed per
 *    client, so no open redirect), PKCE (S256 only) and that token, stores a flow and sends the
 *    browser to the identity provider. A cookie binds the flow to this browser.
 * 3. The provider returns to `/sso/oidc-signin` or `/sso/saml2/{org}/Acs`; the identity is
 *    validated, the account found, linked or provisioned just in time, and a one-time
 *    authorization code is sent to the client's redirect URI with its own `state`.
 * 4. The client redeems the code at `/identity/connect/token` (`authorization_code` grant) with
 *    its PKCE verifier.
 */

export const FLOW_TTL_MS = 10 * 60 * 1000
export const CODE_TTL_MS = 5 * 60 * 1000
export const PREVALIDATE_TTL_SECONDS = 5 * 60
export const PREVALIDATE_PURPOSE = 'sso-prevalidate'
export const LINK_PURPOSE = 'sso-link'
export const LINK_TTL_SECONDS = 5 * 60
/** `__Host-` prefix: Secure, path `/`, no Domain, so no other origin can set or read it. */
export const FLOW_COOKIE = '__Host-cw-sso'

export type FlowRow = typeof schema.ssoFlows.$inferSelect

export const CLIENT_IDS = new Set(['web', 'browser', 'desktop', 'mobile', 'cli', 'connector'])

const isLoopback = (u: URL) =>
  u.protocol === 'http:' &&
  (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]')

/**
 * Redirect URIs each client may use. Web and browser extensions finish on the vault's
 * `sso-connector.html`; desktop and mobile use the `bitwarden://` scheme; the CLI and desktop may
 * use a loopback listener. Anything else is refused before any redirect happens.
 */
export function redirectAllowed(env: Bindings, clientId: string, redirectUri: string): boolean {
  let u: URL
  try {
    u = new URL(redirectUri)
  } catch {
    return false
  }
  if (u.username || u.password || u.hash) return false
  const vault = env.DOMAIN.replace(/\/+$/, '')
  const connector = `${vault}/sso-connector.html`
  switch (clientId) {
    case 'web':
    case 'browser':
    case 'connector':
      return redirectUri === connector
    case 'desktop':
      return (
        redirectUri === 'bitwarden://sso-callback' || isLoopback(u) || redirectUri === connector
      )
    case 'mobile':
      return redirectUri === 'bitwarden://sso-callback'
    case 'cli':
      return isLoopback(u)
    default:
      return false
  }
}

export const isS256Challenge = (s: string) => /^[A-Za-z0-9_-]{43}$/.test(s)

/** S256 of a PKCE verifier, base64url without padding. */
export async function pkceChallenge(verifier: string): Promise<string> {
  return sha256B64u(verifier)
}

export function parseCookie(header: string | undefined, name: string): string | null {
  for (const part of (header ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=')
    if (k === name) return v.join('=')
  }
  return null
}

export const flowCookie = (value: string, maxAgeSeconds: number) =>
  `${FLOW_COOKIE}=${value}; Path=/; Max-Age=${maxAgeSeconds}; HttpOnly; Secure; SameSite=None`

/** Creates a flow; returns the row and the cookie value that binds it to the browser. */
export async function createFlow(
  db: Db,
  values: Omit<FlowRow, 'uuid' | 'bindingHash' | 'consumedAt' | 'createdAt'>,
): Promise<{ flow: FlowRow; cookie: string }> {
  const now = Date.now()
  // Housekeeping: drop expired flows and codes while we are here.
  await runBatch(db, [
    db.delete(schema.ssoFlows).where(lt(schema.ssoFlows.createdAt, now - FLOW_TTL_MS)),
    db.delete(schema.ssoCodes).where(lt(schema.ssoCodes.createdAt, now - CODE_TTL_MS)),
    db.delete(schema.ssoReplay).where(lt(schema.ssoReplay.expiresAt, now)),
  ])
  const secret = randomB64u(32)
  const flow: FlowRow = {
    ...values,
    uuid: randomB64u(24),
    bindingHash: await sha256B64u(secret),
    consumedAt: null,
    createdAt: now,
  }
  await db.insert(schema.ssoFlows).values(flow)
  return { flow, cookie: `${flow.uuid}.${secret}` }
}

/**
 * Loads and consumes the flow named by `state`, checking it is fresh, unused and bound to this
 * browser's cookie. Single use: a replayed callback loses the conditional update.
 */
export async function takeFlow(
  db: Db,
  state: string,
  cookieHeader: string | undefined,
): Promise<FlowRow> {
  const cookie = parseCookie(cookieHeader, FLOW_COOKIE) ?? ''
  const dot = cookie.indexOf('.')
  const cookieFlow = dot > 0 ? cookie.slice(0, dot) : ''
  const secret = dot > 0 ? cookie.slice(dot + 1) : ''
  if (!state || !cookieFlow || !safeEqualStrings(cookieFlow, state)) {
    throw new SsoError('This sign-in was started in another browser or has expired. Start again.')
  }
  const [flow] = await db
    .select()
    .from(schema.ssoFlows)
    .where(eq(schema.ssoFlows.uuid, state))
    .limit(1)
  if (
    !flow ||
    flow.consumedAt !== null ||
    Date.now() - flow.createdAt > FLOW_TTL_MS ||
    !safeEqualStrings(flow.bindingHash, await sha256B64u(secret))
  ) {
    throw new SsoError('This sign-in was started in another browser or has expired. Start again.')
  }
  const result = await db
    .update(schema.ssoFlows)
    .set({ consumedAt: Date.now() })
    .where(and(eq(schema.ssoFlows.uuid, flow.uuid), isNull(schema.ssoFlows.consumedAt)))
  if (result.meta.changes === 0) throw new SsoError('This sign-in was already completed.')
  return flow
}

/** Records a SAML assertion ID; false when it was seen before (a replay). */
export async function recordAssertion(db: Db, key: string, expiresAt: number): Promise<boolean> {
  const hashed = await sha256B64u(key)
  const result = await db
    .insert(schema.ssoReplay)
    .values({ key: hashed, expiresAt })
    .onConflictDoNothing()
  return result.meta.changes > 0
}

export interface SsoIdentity {
  externalId: string
  email: string | null
  name: string | null
  /**
   * The provider vouches for the address: OIDC `email_verified === true` (or the administrator's
   * opt-out); SAML assertions are signed statements of the provider and count as verified.
   */
  emailVerified?: boolean
}

type Member = typeof schema.usersOrganizations.$inferSelect

/**
 * Finds or provisions the account for an identity asserted by the organisation's provider, and
 * makes sure it is a member. Rules:
 *
 * - An existing link (organisation, external ID) decides the account.
 * - Otherwise an existing account is linked only when (a) it signed in with its master password
 *   and asked to link (`user_identifier`, same email, must be invited or a member), or (b) it is
 *   already an accepted or confirmed member. Pending invitations and claimed domains never link an
 *   existing account silently, so a provider cannot take over an account by asserting its address.
 * - With no account, one is created just in time (no master password) only for a claimed domain
 *   or a pending invitation of that address; only a claimed domain marks the address verified.
 * - Membership: an invitation by email is accepted, a missing membership is created as an
 *   accepted User for an administrator to confirm, a revoked membership is refused.
 */
export async function provisionSsoUser(
  db: Db,
  orgUuid: string,
  identity: SsoIdentity,
  linkUserUuid: string | null,
): Promise<{ user: User; firstLogin: boolean }> {
  const now = Date.now()
  const [link] = await db
    .select()
    .from(schema.ssoUsers)
    .where(
      and(
        eq(schema.ssoUsers.organizationUuid, orgUuid),
        eq(schema.ssoUsers.externalId, identity.externalId),
      ),
    )
    .limit(1)

  let user: User | undefined
  let firstLogin = false
  if (link) {
    ;[user] = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.uuid, link.userUuid))
      .limit(1)
    if (!user) throw new SsoError('The linked account no longer exists.')
    if (linkUserUuid && linkUserUuid !== user.uuid) {
      throw new SsoError('This identity is already linked to another account.')
    }
  } else {
    const email = identity.email ? normalizeEmail(identity.email) : null
    if (!email) throw new SsoError('The identity provider did not return an email address.')
    // Linking or provisioning by email needs an address the provider has verified.
    if (identity.emailVerified === false) {
      throw new SsoError('The identity provider has not verified this email address.')
    }
    if (linkUserUuid) {
      ;[user] = await db
        .select()
        .from(schema.users)
        .where(eq(schema.users.uuid, linkUserUuid))
        .limit(1)
      if (!user) throw new SsoError('The account to link was not found.')
      // Linking is started by the signed-in account; the provider must vouch for the same address,
      // so a crafted link URL cannot attach someone else's identity to an attacker's account.
      if (email !== user.email) {
        throw new SsoError(
          'The identity provider returned a different email address than your account.',
        )
      }
      const m = await findMembership(db, orgUuid, user)
      if (!m || m.status === Status.Revoked) {
        throw new SsoError('Your account is not a member of this organization.')
      }
    } else {
      ;[user] = await db.select().from(schema.users).where(eq(schema.users.email, email)).limit(1)
      // An existing account is linked by email only when it already joined the organisation
      // (accepted or confirmed). A pending invitation, or a claimed domain, is not enough: the
      // person must sign in with their master password and link SSO (or accept the invitation).
      if (user && !(await joinedMembership(db, orgUuid, user.uuid))) {
        throw new SsoError(
          'An account with this email already exists. Log in with your master password, accept the organization invitation or link single sign-on from your account, then use SSO.',
        )
      }
    }

    if (user) {
      const [existing] = await db
        .select()
        .from(schema.ssoUsers)
        .where(
          and(
            eq(schema.ssoUsers.organizationUuid, orgUuid),
            eq(schema.ssoUsers.userUuid, user.uuid),
          ),
        )
        .limit(1)
      if (existing) throw new SsoError('This account is already linked to another identity.')
    } else {
      // Just-in-time provisioning, only for addresses the organisation vouches for: a domain it
      // has claimed, or an invitation it sent. The address counts as verified only for a claimed
      // domain.
      const claimed = await orgClaimsEmail(db, orgUuid, email)
      if (!claimed && !(await pendingInvitation(db, orgUuid, email))) {
        throw new SsoError(
          'You need an invitation to join this organization. Ask an administrator to invite you.',
        )
      }
      const created: typeof schema.users.$inferInsert = {
        uuid: crypto.randomUUID(),
        email,
        name: (identity.name ?? email.split('@')[0] ?? email).slice(0, 50),
        passwordHash: '',
        salt: '',
        passwordIterations: 0,
        akey: '',
        securityStamp: crypto.randomUUID(),
        verifiedAt: claimed ? now : null,
        createdAt: now,
        updatedAt: now,
      }
      try {
        await db.insert(schema.users).values(created)
      } catch {
        throw new SsoError('The account could not be created. Try again.')
      }
      ;[user] = await db.select().from(schema.users).where(eq(schema.users.email, email)).limit(1)
      if (!user) throw new SsoError('The account could not be created. Try again.')
    }
    try {
      await db.insert(schema.ssoUsers).values({
        organizationUuid: orgUuid,
        userUuid: user.uuid,
        externalId: identity.externalId,
        createdAt: now,
      })
    } catch {
      throw new SsoError('This account is already linked to another identity.')
    }
    firstLogin = true
  }

  if (!user.enabled) throw new SsoError('This account has been disabled.')
  await ensureMembership(db, orgUuid, user, now)
  return { user, firstLogin }
}

/** Accepted or confirmed membership of the account itself. */
async function joinedMembership(db: Db, orgUuid: string, userUuid: string) {
  const [m] = await db
    .select({ uuid: schema.usersOrganizations.uuid })
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
        eq(schema.usersOrganizations.userUuid, userUuid),
        inArray(schema.usersOrganizations.status, [Status.Accepted, Status.Confirmed]),
      ),
    )
    .limit(1)
  return m !== undefined
}

/** A pending invitation of the address (no account attached yet). */
async function pendingInvitation(db: Db, orgUuid: string, email: string) {
  const [m] = await db
    .select({ uuid: schema.usersOrganizations.uuid })
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
        eq(schema.usersOrganizations.status, Status.Invited),
        isNull(schema.usersOrganizations.userUuid),
        sql`lower(${schema.usersOrganizations.email}) = ${email}`,
      ),
    )
    .limit(1)
  return m !== undefined
}

async function findMembership(db: Db, orgUuid: string, user: User): Promise<Member | undefined> {
  const [m] = await db
    .select()
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
        sql`(${schema.usersOrganizations.userUuid} = ${user.uuid} or (${schema.usersOrganizations.userUuid} is null and lower(${schema.usersOrganizations.email}) = ${user.email}))`,
      ),
    )
    .limit(1)
  return m
}

async function ensureMembership(db: Db, orgUuid: string, user: User, now: number) {
  const m = await findMembership(db, orgUuid, user)
  if (m?.status === Status.Revoked) {
    throw new SsoError('Your access to this organization has been revoked.')
  }
  if (m && m.status !== Status.Invited) return
  if (m) {
    await db
      .update(schema.usersOrganizations)
      .set({ userUuid: user.uuid, status: Status.Accepted, updatedAt: now })
      .where(eq(schema.usersOrganizations.uuid, m.uuid))
    return
  }
  await db.insert(schema.usersOrganizations).values({
    uuid: crypto.randomUUID(),
    userUuid: user.uuid,
    organizationUuid: orgUuid,
    email: user.email,
    akey: '',
    status: Status.Accepted,
    atype: Role.User,
    accessAll: false,
    createdAt: now,
    updatedAt: now,
  })
}

/** Issues a one-time authorization code for the flow's client. Returns the plain code. */
export async function issueCode(db: Db, flow: FlowRow, userUuid: string): Promise<string> {
  const code = randomB64u(32)
  await db.insert(schema.ssoCodes).values({
    codeHash: await sha256B64u(code),
    userUuid,
    organizationUuid: flow.organizationUuid,
    clientId: flow.clientId,
    redirectUri: flow.redirectUri,
    codeChallenge: flow.codeChallenge,
    usedAt: null,
    createdAt: Date.now(),
  })
  return code
}

/** The client redirect carrying the code and the client's own state, unchanged. */
export function clientRedirect(flow: FlowRow, code: string): string {
  const sep = flow.redirectUri.includes('?') ? '&' : '?'
  return `${flow.redirectUri}${sep}code=${encodeURIComponent(code)}&state=${encodeURIComponent(flow.clientState)}`
}

export type CodeRow = typeof schema.ssoCodes.$inferSelect

/**
 * Finds a code the client may redeem: unused, fresh, issued to this client and redirect URI, and
 * matching the PKCE verifier. Does not consume it (two-step login may need a second attempt).
 */
export async function findRedeemableCode(
  db: Db,
  form: { code?: string; code_verifier?: string; redirect_uri?: string; client_id?: string },
): Promise<CodeRow | null> {
  if (!form.code || !form.code_verifier || !form.redirect_uri || !form.client_id) return null
  if (!/^[A-Za-z0-9._~-]{43,128}$/.test(form.code_verifier)) return null
  const [row] = await db
    .select()
    .from(schema.ssoCodes)
    .where(eq(schema.ssoCodes.codeHash, await sha256B64u(form.code)))
    .limit(1)
  if (
    !row ||
    row.usedAt !== null ||
    Date.now() - row.createdAt > CODE_TTL_MS ||
    row.clientId !== form.client_id ||
    row.redirectUri !== form.redirect_uri ||
    !safeEqualStrings(row.codeChallenge, await pkceChallenge(form.code_verifier))
  ) {
    return null
  }
  return row
}

/** Marks the code used. Atomic: only one concurrent redemption wins. */
export async function consumeCode(db: Db, codeHash: string): Promise<boolean> {
  const result = await db
    .update(schema.ssoCodes)
    .set({ usedAt: Date.now() })
    .where(and(eq(schema.ssoCodes.codeHash, codeHash), isNull(schema.ssoCodes.usedAt)))
  return result.meta.changes > 0
}
