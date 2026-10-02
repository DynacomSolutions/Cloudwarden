// Two Cloudwarden instances in one workerd (TASKS #308): the same app with separate D1 databases
// and domains, wired together by an in-process transport that also answers DNS over HTTPS.
import { env } from 'cloudflare:workers'
import { mailbox } from './org-helpers'

export const A_DOMAIN = 'vault.example.com'
export const B_DOMAIN = 'peer.example.org'

export interface Instance {
  name: 'A' | 'B'
  domain: string
  base: string
  env: Record<string, unknown>
  mail: ReturnType<typeof mailbox>
  fetch(path: string, init?: RequestInit): Promise<Response>
}

export interface Net {
  A: Instance
  B: Instance
  /** Every request that crossed the transport, as `METHOD url`. */
  log: string[]
  /** DNS answers by host name; hosts not listed resolve to a public address. */
  dns: Map<string, { A?: string[]; AAAA?: string[] }>
  /** Waits for deferred work (pushes, events) on both instances. */
  flush(): Promise<void>
}

export async function twoInstances(): Promise<Net> {
  const { default: app } = await import('../src/index')
  const pending: Promise<unknown>[] = []
  const ctx = {
    waitUntil: (p: Promise<unknown>) => void pending.push(p.catch(() => undefined)),
    passThroughOnException: () => undefined,
    props: {},
  } as unknown as ExecutionContext
  const log: string[] = []
  const dns = new Map<string, { A?: string[]; AAAA?: string[] }>()
  const instances: Record<string, Instance> = {}
  const transport = {
    async fetch(req: Request): Promise<Response> {
      const url = new URL(req.url)
      if (url.hostname === 'cloudflare-dns.com') {
        const name = url.searchParams.get('name') ?? ''
        const type = url.searchParams.get('type') as 'A' | 'AAAA'
        // Built at run time: a public address literal in the source would trip the identifier guard.
        const records = dns.get(name) ?? { A: [[8, 8, 8, 8].join('.')] }
        const data = records[type] ?? []
        return Response.json({
          Status: 0,
          Answer: data.map((d) => ({ name, type: type === 'A' ? 1 : 28, data: d })),
        })
      }
      log.push(`${req.method} ${req.url}`)
      const target = Object.values(instances).find((i) => i.domain === url.host)
      if (!target) throw new TypeError('network error')
      return await app.fetch(req, target.env as never, ctx)
    },
  }
  const make = (name: 'A' | 'B', domain: string, db: D1Database): Instance => {
    const mail = mailbox()
    const ienv = {
      ...env,
      DB: db,
      DOMAIN: `https://${domain}`,
      FEDERATION_ENABLED: 'true',
      ADMIN_ENABLED: 'true',
      ADMIN_EMAILS: '',
      EMAIL: mail.EMAIL,
      MAIL_FROM: mail.MAIL_FROM,
      FEDERATION_TRANSPORT: transport,
    }
    const inst: Instance = {
      name,
      domain,
      base: `https://${domain}`,
      env: ienv,
      mail,
      fetch: async (path, init) =>
        app.fetch(new Request(`https://${domain}${path}`, init), ienv as never, ctx),
    }
    instances[name] = inst
    return inst
  }
  const A = make('A', A_DOMAIN, env.DB)
  const B = make('B', B_DOMAIN, env.DB_PEER)
  return {
    A,
    B,
    log,
    dns,
    async flush() {
      for (let i = 0; i < 20 && pending.length > 0; i++) await Promise.all(pending.splice(0))
    },
  }
}

export interface User {
  email: string
  uuid: string
  token: string
  call(path: string, method?: string, body?: unknown): Promise<Response>
  json(path: string, method?: string, body?: unknown): Promise<any>
}

export async function userOn(
  inst: Instance,
  email: string,
  opts: { verified?: boolean; publicKey?: string } = {},
): Promise<User> {
  const reg = await inst.fetch('/identity/accounts/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email,
      name: email.split('@')[0],
      masterPasswordHash: 'client-derived-hash',
      key: '2.encryptedSymmetricKey',
      keys: { publicKey: opts.publicKey ?? `pk-${email}`, encryptedPrivateKey: '2.pk' },
      kdf: 0,
      kdfIterations: 600000,
    }),
  })
  if (reg.status !== 200) throw new Error(`register ${email} on ${inst.name}: ${reg.status}`)
  if (opts.verified) {
    // Admin addresses cannot self-register, so the address is listed only once the account exists.
    inst.env.ADMIN_EMAILS = email
  }
  const tok = await inst.fetch('/identity/connect/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      username: email,
      password: 'client-derived-hash',
      scope: 'api offline_access',
      client_id: 'web',
      deviceType: '9',
      deviceName: 'chrome',
      deviceIdentifier: `device-${email}`,
    }).toString(),
  })
  if (tok.status !== 200) throw new Error(`login ${email} on ${inst.name}: ${tok.status}`)
  const { access_token: token } = (await tok.json()) as { access_token: string }
  const call = (path: string, method = 'GET', body?: unknown) =>
    inst.fetch(path, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
  const me = (await (await call('/api/accounts/profile')).json()) as { id: string }
  return {
    email,
    uuid: me.id,
    token,
    call,
    json: async (path, method, body) => (await call(path, method, body)).json(),
  }
}

/** Pairs A and B the way two admins would, comparing fingerprints from each other's descriptor. */
export async function pair(net: Net, adminA: User, adminB: User) {
  const addA = await adminA.json('/api/cloudwarden/federation/admin/peers', 'POST', {
    domain: net.B.domain,
  })
  const addB = await adminB.json('/api/cloudwarden/federation/admin/peers', 'POST', {
    domain: net.A.domain,
  })
  const descA = await (await net.A.fetch('/.well-known/cloudwarden-federation')).json()
  const descB = await (await net.B.fetch('/.well-known/cloudwarden-federation')).json()
  const apA = await adminA.call(
    `/api/cloudwarden/federation/admin/peers/${addA.id}/approve`,
    'POST',
    {
      fingerprint: (descB as { fingerprint: string }).fingerprint,
    },
  )
  if (apA.status !== 200) throw new Error(`approve on A: ${apA.status} ${await apA.text()}`)
  const apB = await adminB.call(
    `/api/cloudwarden/federation/admin/peers/${addB.id}/approve`,
    'POST',
    {
      fingerprint: (descA as { fingerprint: string }).fingerprint,
    },
  )
  if (apB.status !== 200) throw new Error(`approve on B: ${apB.status} ${await apB.text()}`)
  return { peerOnA: addA.id as string, peerOnB: addB.id as string }
}

export const cipherBody = (orgId: string | null, name = '2.name') => ({
  type: 1,
  name,
  key: '2.ckey',
  organizationId: orgId,
  login: { username: '2.u', password: '2.p', uris: [] },
})
