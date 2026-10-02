import { env } from 'cloudflare:workers'
import { BASE, createSession } from './helpers'

export interface Mail {
  to: string
  subject: string
  text: string
}

/** A fake email transport: the `EMAIL` binding records what would have been sent. */
export const mailbox = () => {
  const sent: Mail[] = []
  return {
    sent,
    EMAIL: { send: async (m: Mail) => void sent.push(m) },
    MAIL_FROM: 'Cloudwarden <noreply@example.com>',
  }
}
export type Mailbox = ReturnType<typeof mailbox>

export const mail = mailbox()

/** The query string of the first link in a message. */
export const linkParams = (m: Mail | undefined) => {
  const url = /https?:\/\/\S+/.exec(m?.text ?? '')?.[0] ?? ''
  return new URLSearchParams(url.split('?')[1] ?? '')
}

export interface Actor {
  email: string
  token: string
  uuid: string
  call(path: string, method?: string, body?: unknown): Promise<Response>
  json(path: string, method?: string, body?: unknown): Promise<any>
}

export async function actor(email: string, mb: Mailbox = mail): Promise<Actor> {
  const { default: app } = await import('../src/index')
  const s = await createSession(email)
  const call = async (path: string, method = 'GET', body?: unknown) =>
    app.fetch(
      new Request(`${BASE}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${s.access_token}`,
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      }),
      { ...env, EMAIL: mb.EMAIL, MAIL_FROM: mb.MAIL_FROM },
    )
  const me = (await (await call('/api/accounts/profile')).json()) as { id: string }
  return {
    email,
    token: s.access_token,
    uuid: me.id,
    call,
    json: async (path, method, body) => (await call(path, method, body)).json(),
  }
}

export const loginCipher = (name = '2.name', extra: Record<string, unknown> = {}) => ({
  type: 1,
  name,
  key: '2.ckey',
  login: { username: '2.u', password: '2.p', uris: [] },
  ...extra,
})

export async function createOrg(owner: Actor, name = 'Acme') {
  const res = await owner.call('/api/organizations', 'POST', {
    name,
    billingEmail: 'billing@example.com',
    key: '4.ownerOrgKey',
    keys: { publicKey: 'orgPublic', encryptedPrivateKey: '2.orgPrivate' },
    collectionName: '2.defaultCollection',
    planType: 0,
  })
  if (res.status !== 200) throw new Error(`create org failed: ${res.status}`)
  const org = (await res.json()) as { id: string }
  const sync = await owner.json('/api/sync')
  return { id: org.id, defaultCollectionId: sync.collections[0].id as string }
}

export interface InviteOptions {
  type?: number
  accessAll?: boolean
  collections?: unknown[]
  groups?: string[]
  permissions?: Record<string, boolean>
  /** Account recovery key sent while accepting (required under auto-enrolment, TASKS #240). */
  resetPasswordKey?: string
}

/** Invites, accepts and confirms `member`; returns the organisation user id. */
export async function addMember(
  owner: Actor,
  orgId: string,
  member: Actor,
  opts: InviteOptions = {},
  mb: Mailbox = mail,
) {
  const before = mb.sent.length
  const inv = await owner.call(`/api/organizations/${orgId}/users/invite`, 'POST', {
    emails: [member.email],
    type: opts.type ?? 2,
    accessAll: opts.accessAll ?? false,
    collections: opts.collections ?? [],
    groups: opts.groups ?? [],
    permissions: opts.permissions ?? null,
  })
  if (inv.status !== 200) throw new Error(`invite failed: ${inv.status}`)
  const params = linkParams(mb.sent[before])
  const id = params.get('organizationUserId') as string
  const acc = await member.call(`/api/organizations/${orgId}/users/${id}/accept`, 'POST', {
    token: params.get('token'),
    ...(opts.resetPasswordKey ? { resetPasswordKey: opts.resetPasswordKey } : {}),
  })
  if (acc.status !== 200) throw new Error(`accept failed: ${acc.status}`)
  const conf = await owner.call(`/api/organizations/${orgId}/users/${id}/confirm`, 'POST', {
    key: '4.memberOrgKey',
  })
  if (conf.status !== 200) throw new Error(`confirm failed: ${conf.status}`)
  return id
}
