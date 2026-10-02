import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { Hono } from 'hono'
import { describe, expect, it } from 'vitest'
import type { Env } from '../src/env'
import { ApiError } from '../src/errors'
import type { Fetcher } from '../src/icons/fetch'
import { createIcons } from '../src/routes/icons'
import { createReports, mapPasskeyDirectory } from '../src/routes/reports'
import { BASE, json } from './helpers'
import {
  type Actor,
  actor,
  addMember,
  createOrg,
  linkParams,
  loginCipher,
  mailbox,
} from './org-helpers'

const ctx = {
  waitUntil: (p: Promise<unknown>) => void p.catch(() => {}),
  passThroughOnException() {},
} as unknown as ExecutionContext

const upload = (a: Actor, path: string, bytes: Uint8Array, key = '2.fkey') => {
  const fd = new FormData()
  fd.append('key', key)
  fd.append('data', new Blob([bytes]), '2.fname')
  return SELF.fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${a.token}` },
    body: fd,
  })
}

/** A personal item with one uploaded attachment. */
async function itemWithAttachment(a: Actor, name = '2.item') {
  const item = await a.json('/api/ciphers', 'POST', loginCipher(name))
  const res = await upload(a, `/api/ciphers/${item.id}/attachment`, new Uint8Array([1, 2, 3]))
  expect(res.status).toBe(200)
  const withAtt = (await res.json()) as { attachments: { id: string }[] }
  return { cipherId: item.id as string, attachmentId: withAtt.attachments[0]?.id as string }
}

describe('profile settings', () => {
  it('stores the avatar colour and returns it in the profile and sync', async () => {
    const a = await actor('w2-avatar@example.com')
    expect((await a.json('/api/accounts/profile')).avatarColor).toBeNull()
    const res = await a.call('/api/accounts/avatar', 'PUT', { avatarColor: '#aabbcc' })
    expect(res.status).toBe(200)
    expect(((await res.json()) as { avatarColor: string }).avatarColor).toBe('#aabbcc')
    expect((await a.json('/api/sync')).profile.avatarColor).toBe('#aabbcc')
    expect((await a.call('/api/accounts/avatar', 'PUT', { avatarColor: 'red;' })).status).toBe(400)
    expect(
      (await a.json('/api/accounts/avatar', 'PUT', { avatarColor: null })).avatarColor,
    ).toBeNull()
    const anon = await SELF.fetch(`${BASE}/api/accounts/avatar`, { method: 'PUT' })
    expect(anon.status).toBe(401)
  })

  it('returns the account keys and organisations', async () => {
    const a = await actor('w2-keys@example.com')
    expect(await a.json('/api/accounts/keys')).toMatchObject({
      key: '2.encryptedSymmetricKey',
      publicKey: 'public-key',
      privateKey: '2.pk',
      object: 'keys',
    })
    const org = await createOrg(a)
    for (const path of ['/api/accounts/organizations', '/api/organizations']) {
      const list = await a.json(path)
      expect(list.object).toBe('list')
      expect(list.data.map((o: { id: string }) => o.id)).toEqual([org.id])
    }
    expect((await SELF.fetch(`${BASE}/api/accounts/keys`)).status).toBe(401)
    expect((await SELF.fetch(`${BASE}/api/organizations`)).status).toBe(401)
  })

  it('answers identity alive and the /api registration email alias', async () => {
    const alive = await SELF.fetch(`${BASE}/identity/alive`)
    expect(alive.status).toBe(200)
    const bad = await json('/api/accounts/register/verification-email-clicked', {
      email: 'w2-new@example.com',
      emailVerificationToken: 'nope',
    })
    expect(bad.status).toBe(400)
  })
})

describe('devices', () => {
  it('registers, reads and updates a device of the caller only', async () => {
    const a = await actor('w2-dev@example.com')
    const b = await actor('w2-dev-other@example.com')
    const made = await a.json('/api/devices', 'POST', {
      type: 8,
      name: 'cli',
      identifier: 'w2-dev-ident',
      pushToken: null,
    })
    expect(made).toMatchObject({
      name: 'cli',
      type: 8,
      identifier: 'w2-dev-ident',
      object: 'device',
    })
    expect((await a.json(`/api/devices/${made.id}`)).id).toBe(made.id)
    expect((await b.call(`/api/devices/${made.id}`)).status).toBe(404)
    const upd = await a.json(`/api/devices/${made.id}`, 'PUT', {
      type: 9,
      name: 'renamed',
      identifier: 'ignored',
    })
    expect(upd).toMatchObject({ name: 'renamed', type: 9, identifier: 'w2-dev-ident' })
    expect(
      (await b.call(`/api/devices/${made.id}`, 'PUT', { type: 1, name: 'x', identifier: 'y' }))
        .status,
    ).toBe(404)
    expect((await a.call('/api/devices', 'POST', { type: 8 })).status).toBe(400)
  })
})

describe('attachments', () => {
  it('reports unassigned organisation items to admins only', async () => {
    const owner = await actor('w2-unassigned@example.com')
    const user = await actor('w2-unassigned-user@example.com')
    const org = await createOrg(owner)
    await addMember(owner, org.id, user, {
      collections: [
        { id: org.defaultCollectionId, readOnly: false, hidePasswords: false, manage: false },
      ],
    })
    expect(await owner.json('/api/ciphers/has-unassigned-ciphers')).toBe(false)
    const item = await owner.json('/api/ciphers', 'POST', loginCipher())
    await owner.call(`/api/ciphers/${item.id}/share`, 'PUT', {
      cipher: loginCipher('2.o', { organizationId: org.id }),
      collectionIds: [org.defaultCollectionId],
    })
    const removed = await owner.call(`/api/ciphers/${item.id}/collections-admin`, 'PUT', {
      collectionIds: [],
    })
    expect(removed.status).toBe(200)
    expect(await owner.json('/api/ciphers/has-unassigned-ciphers')).toBe(true)
    expect(await user.json('/api/ciphers/has-unassigned-ciphers')).toBe(false)
  })

  it('lets an approved emergency viewer read attachment metadata', async () => {
    const mb = mailbox()
    const grantor = await actor('w2-ea-grantor@example.com', mb)
    const grantee = await actor('w2-ea-grantee@example.com', mb)
    const { cipherId, attachmentId } = await itemWithAttachment(grantor)
    await grantor.call('/api/emergency-access/invite', 'POST', {
      email: grantee.email,
      type: 0,
      waitTimeDays: 1,
    })
    const p = linkParams(mb.sent.at(-1))
    const id = p.get('id') as string
    await grantee.call(`/api/emergency-access/${id}/accept`, 'POST', { token: p.get('token') })
    await grantor.call(`/api/emergency-access/${id}/confirm`, 'POST', { key: '4.k' })
    const path = `/api/emergency-access/${id}/${cipherId}/attachment/${attachmentId}`
    expect((await grantee.call(path)).status).toBe(400)
    await grantee.call(`/api/emergency-access/${id}/initiate`, 'POST')
    await grantor.call(`/api/emergency-access/${id}/approve`, 'POST')
    expect(await grantee.json(path)).toMatchObject({ id: attachmentId, object: 'attachment' })
    expect((await grantor.call(path)).status).toBe(404)
    const view = await grantee.json(`/api/emergency-access/${id}/view`, 'POST')
    expect(view.ciphers[0].attachments).toHaveLength(1)
  })
})

describe('reports', () => {
  const token = async (email: string) => (await actor(email)).token
  const call = (f: Fetcher, path: string, t: string, overrides: Record<string, unknown> = {}) =>
    new Hono<Env>()
      .onError((e) => new Response(null, { status: e instanceof ApiError ? e.status : 500 }))
      .route('/', createReports(f))
      .request(path, { headers: { Authorization: `Bearer ${t}` } }, { ...env, ...overrides }, ctx)

  it('proxies HIBP only when a key is configured', async () => {
    const t = await token('w2-hibp@example.com')
    const seen: { url: string; key: string | null }[] = []
    const fetcher: Fetcher = async (url, init) => {
      seen.push({ url, key: new Headers(init?.headers).get('hibp-api-key') })
      if (url.includes('clean')) return new Response('', { status: 404 })
      return Response.json([{ Name: 'Breach', PwnCount: 5 }])
    }
    expect((await call(fetcher, '/api/hibp/breach?username=a%40example.com', t)).status).toBe(400)
    expect(seen).toHaveLength(0)
    const hit = await call(fetcher, '/api/hibp/breach?username=a%40example.com', t, {
      HIBP_API_KEY: 'k',
    })
    expect(await hit.json()).toEqual([{ Name: 'Breach', PwnCount: 5 }])
    expect(seen[0]).toMatchObject({ key: 'k' })
    expect(seen[0]?.url).toContain('breachedaccount/a%40example.com')
    const clean = await call(fetcher, '/api/hibp/breach?username=clean', t, { HIBP_API_KEY: 'k' })
    expect(await clean.json()).toEqual([])
    expect(
      (await call(fetcher, '/api/hibp/breach?username=x', 'bad', { HIBP_API_KEY: 'k' })).status,
    ).toBe(401)
  })

  it('maps the passkey directory', async () => {
    expect(
      mapPasskeyDirectory({
        'example.com': { passwordless: 'allowed', documentation: 'https://example.com/docs' },
        'example.org': { mfa: 'allowed' },
      }),
    ).toEqual([
      {
        domainName: 'example.com',
        instructions: 'https://example.com/docs',
        passwordless: true,
        mfa: false,
      },
      { domainName: 'example.org', instructions: '', passwordless: false, mfa: true },
    ])
    const t = await token('w2-passkeys@example.com')
    const fetcher: Fetcher = async () => Response.json({ 'example.net': { mfa: 'required' } })
    const res = await call(fetcher, '/api/reports/passkey-directory', t)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual([
      { domainName: 'example.net', instructions: '', passwordless: false, mfa: true },
    ])
    expect((await call(fetcher, '/api/reports/passkey-directory', 'bad')).status).toBe(401)
  })
})

describe('GET /icons/change-password-uri', () => {
  const run = (f: Fetcher, uri: string) =>
    new Hono<Env>()
      .route('/', createIcons(f))
      .request(`/icons/change-password-uri?uri=${encodeURIComponent(uri)}`, {}, env, ctx)

  it('returns the well-known URL when the site supports it', async () => {
    const host = `cpw-${crypto.randomUUID().slice(0, 8)}.example.com`
    const fetcher: Fetcher = async (url) =>
      new Response('', { status: url.endsWith('/.well-known/change-password') ? 200 : 404 })
    const res = await run(fetcher, `https://${host}/login`)
    expect(await res.json()).toEqual({ uri: `https://${host}/.well-known/change-password` })
  })

  it('returns null for sites answering 200 to everything, misses and refused hosts', async () => {
    const all200: Fetcher = async () => new Response('ok')
    const host = `cpw-${crypto.randomUUID().slice(0, 8)}.example.com`
    expect(await (await run(all200, `https://${host}`)).json()).toEqual({ uri: null })
    const none: Fetcher = async () => new Response('', { status: 404 })
    const other = `cpw-${crypto.randomUUID().slice(0, 8)}.example.com`
    expect(await (await run(none, other)).json()).toEqual({ uri: null })
    let called = false
    const spy: Fetcher = async () => {
      called = true
      return new Response('ok')
    }
    expect(await (await run(spy, 'http://127.0.0.1/')).json()).toEqual({ uri: null })
    expect(called).toBe(false)
  })
})
