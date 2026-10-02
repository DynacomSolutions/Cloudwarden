// JSON admin API for the native admin pages in the web vault (TASKS #150).
// Bearer auth (the vault's own access token) plus an admin check; never cookie based.
import { type Context, Hono } from 'hono'
import { z } from 'zod'
import { authenticateAccessToken, requireAuth } from '../auth/middleware'
import type { EmailTransport } from '../email'
import type { Bindings, Env } from '../env'
import { ApiError, errorBody } from '../errors'
import { createNotification, notificationJson } from '../notifications/center'
import { relayStatus } from '../notifications/relay'
import { parseBody } from '../validation'
import { isAdminUser, isPlausibleEmail, normaliseEmail, rateLimit } from './security'
import {
  type Audit,
  countUsers,
  createInvitation,
  deauthorizeUser,
  deleteInvitation,
  deleteOrganization,
  deleteUser,
  diagnostics,
  emailTransportFor,
  listInvitations,
  listOrganizations,
  listUsers,
  overviewCounts,
  parseTfa,
  removeTwoFactor,
  serverConfig,
  setUserEnabled,
  tfaName,
} from './service'

const PREFIX = '/api/cloudwarden/admin'
const DEFAULT_PAGE_SIZE = 50
const MAX_PAGE_SIZE = 100
/** Per admin, per minute. Generous for a UI, tight enough to stop a runaway script. */
const RATE_LIMIT = 120

const iso = (ms: number | null) => (ms === null ? null : new Date(ms).toISOString())

export interface AdminApiDeps {
  /** Override the email transport (tests inject a fake). */
  emailTransport?: (env: Bindings) => EmailTransport
}

const adminNotificationSchema = z.object({
  title: z.string().min(1).max(256),
  body: z.string().min(1).max(3000),
  priority: z.number().int().min(0).max(3).nullish(),
  userId: z.string().nullish(),
  organizationId: z.string().nullish(),
})

const notFound = (what: string) => new ApiError(404, `${what} not found`)

export function createAdminApi(deps: AdminApiDeps = {}) {
  const api = new Hono<Env>()

  // Used by the web client to decide whether to show the Instance admin pages.
  api.get('/api/cloudwarden/me', async (c) => {
    c.header('Cache-Control', 'no-store')
    const match = /^Bearer\s+(\S+)$/i.exec(c.req.header('Authorization') ?? '')
    const authed = match?.[1] ? await authenticateAccessToken(c.env, match[1]) : null
    if (!authed) return c.json(errorBody('Unauthorized'), 401)
    return c.json({ isAdmin: isAdminUser(c.env, authed.user), email: authed.user.email })
  })

  api.use(`${PREFIX}/*`, async (c, next) => {
    c.header('Cache-Control', 'no-store')
    await next()
  })
  api.use(`${PREFIX}/*`, requireAuth)
  api.use(`${PREFIX}/*`, async (c, next) => {
    const user = c.var.user
    // Rate limit first so probing the admin check is bounded too.
    if (!(await rateLimit(c.env.DB, `adminapi:${user.uuid}`, RATE_LIMIT, 60_000, Date.now()))) {
      return c.json(errorBody('Too many requests. Try again later.'), 429, { 'Retry-After': '60' })
    }
    if (!isAdminUser(c.env, user)) return c.json(errorBody('Forbidden'), 403)
    await next()
  })

  const auditOf = (c: {
    req: { header(n: string): string | undefined }
    var: Env['Variables']
  }): Audit => {
    const type = Number.parseInt(c.req.header('Device-Type') ?? '', 10)
    return {
      actor: c.var.user.uuid,
      ipAddress: c.req.header('CF-Connecting-IP') ?? null,
      deviceType: Number.isFinite(type) ? type : null,
    }
  }

  api.get(`${PREFIX}/overview`, async (c) => {
    const [counts, transport] = [
      await overviewCounts(c.env.DB),
      emailTransportFor(c.env, deps.emailTransport),
    ]
    return c.json({ counts, ...serverConfig(c.env, transport) })
  })

  api.get(`${PREFIX}/diagnostics`, async (c) => {
    const d = await diagnostics(c.env.DB)
    return c.json({
      storage: {
        attachments: d.attachments,
        attachmentBytes: d.attachmentBytes,
        fileSends: d.fileSends,
        r2Bound: Boolean(c.env.ATTACHMENTS),
        dbRoundTripMs: d.dbRoundTripMs,
      },
      server: serverConfig(c.env, emailTransportFor(c.env, deps.emailTransport)),
      push: relayStatus(c.env),
      pendingInvitations: d.pendingInvitations,
    })
  })

  // Users ---------------------------------------------------------------
  api.get(`${PREFIX}/users`, async (c) => {
    const intParam = (name: string, fallback: number, max: number) => {
      const raw = c.req.query(name)
      if (raw === undefined) return fallback
      if (!/^\d+$/.test(raw) || Number(raw) < 1) {
        throw new ApiError(400, 'Invalid pagination parameter', {
          [name]: [`${name} must be a positive integer`],
        })
      }
      return Math.min(Number(raw), max)
    }
    const page = intParam('page', 1, 1_000_000)
    const pageSize = intParam('pageSize', DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE)
    const [{ rows, hasMore }, total] = await Promise.all([
      listUsers(c.env.DB, page, pageSize),
      countUsers(c.env.DB),
    ])
    return c.json({
      object: 'list',
      data: rows.map((u) => ({
        id: u.uuid,
        email: u.email,
        name: u.name,
        createdAt: iso(u.created_at),
        lastActive: iso(u.last_active),
        itemCount: u.items,
        twoFactorProviders: parseTfa(u.tfa).map((type) => ({ type, name: tfaName(type) })),
        enabled: u.enabled === 1,
        emailVerified: u.verified_at !== null,
      })),
      page,
      pageSize,
      total,
      hasMore,
    })
  })

  const userAction =
    (run: (c: Context<Env>, id: string) => Promise<boolean>) => async (c: Context<Env>) => {
      const id = c.req.param('id') ?? ''
      if (!(await run(c, id))) throw notFound('User')
      return c.body(null, 204)
    }

  api.post(
    `${PREFIX}/users/:id/disable`,
    userAction(async (c, id) => {
      if (id === c.var.user.uuid) throw new ApiError(400, 'You cannot disable your own account.')
      return setUserEnabled(c.env, id, false, auditOf(c))
    }),
  )
  api.post(
    `${PREFIX}/users/:id/enable`,
    userAction((c, id) => setUserEnabled(c.env, id, true, auditOf(c))),
  )
  api.post(
    `${PREFIX}/users/:id/deauthorize`,
    userAction((c, id) => deauthorizeUser(c.env, id, auditOf(c))),
  )
  api.post(
    `${PREFIX}/users/:id/remove-2fa`,
    userAction((c, id) => removeTwoFactor(c.env, id, auditOf(c))),
  )
  api.delete(
    `${PREFIX}/users/:id`,
    userAction(async (c, id) => {
      if (id === c.var.user.uuid) throw new ApiError(400, 'You cannot delete your own account.')
      return deleteUser(c.env, id, auditOf(c))
    }),
  )

  // Invitations ---------------------------------------------------------
  api.post(`${PREFIX}/invitations`, async (c) => {
    const body = await c.req.json().catch(() => null)
    const email = normaliseEmail(
      body && typeof body === 'object' ? (body as { email?: unknown }).email : '',
    )
    if (!isPlausibleEmail(email)) {
      throw new ApiError(400, 'Enter a valid email address.', {
        email: ['Enter a valid email address.'],
      })
    }
    const r = await createInvitation(
      c.env,
      email,
      c.var.user.email,
      auditOf(c),
      emailTransportFor(c.env, deps.emailTransport),
    )
    return c.json(
      { email, createdAt: iso(r.createdAt), emailStatus: r.mail },
      r.created ? 201 : 200,
    )
  })

  api.get(`${PREFIX}/invitations`, async (c) => {
    const rows = await listInvitations(c.env.DB, 200)
    return c.json({
      object: 'list',
      data: rows.map((i) => ({ email: i.email, createdAt: iso(i.created_at) })),
    })
  })

  api.delete(`${PREFIX}/invitations/:email`, async (c) => {
    const email = normaliseEmail(c.req.param('email') ?? '')
    if (!(await deleteInvitation(c.env.DB, email, auditOf(c)))) throw notFound('Invitation')
    return c.body(null, 204)
  })

  // Organisations -------------------------------------------------------
  api.get(`${PREFIX}/organizations`, async (c) => {
    const rows = await listOrganizations(c.env.DB)
    return c.json({
      object: 'list',
      data: rows.map((o) => ({
        id: o.uuid,
        name: o.name,
        createdAt: iso(o.created_at),
        memberCount: o.members,
        itemCount: o.ciphers,
      })),
    })
  })

  api.delete(`${PREFIX}/organizations/:id`, async (c) => {
    if (!(await deleteOrganization(c.env, c.req.param('id') ?? '', auditOf(c)))) {
      throw notFound('Organization')
    }
    return c.body(null, 204)
  })

  // Notification centre (TASKS #231) -----------------------------------
  api.post(`${PREFIX}/notifications`, async (c) => {
    const body = await parseBody(c, adminNotificationSchema)
    const n = await createNotification(c, body)
    return c.json(notificationJson(n, null), 201)
  })

  return api
}

export const adminApi = createAdminApi()
