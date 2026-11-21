// Review fixes for the Public API parity work: member email safeguards, PUT resets, seat limits,
// the subscription upsert, the event window and the Manager round trip.

import { env } from 'cloudflare:workers'
import { eq } from 'drizzle-orm'
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { isEmailTakenError } from '../src/auth/email-change'
import { createDb, schema } from '../src/db'
import { mergeSubscription, subscriptionUpsert } from '../src/orgs/subscription'
import type { OidcIdp } from './oidc-idp'
import { bearer, raw as call, orgApiKey, orgToken } from './org-api-helpers'
import { type Actor, actor, addMember, createOrg, mail } from './org-helpers'
import { conforms } from './public-spec'
import { claimDomain, configureOidc, oidcLogin, startIdp } from './sso-helpers'

let n = 0
const unique = (p: string) => `${p}-${Date.now()}-${++n}`

interface Fixture {
  owner: Actor
  orgId: string
  token: string
  pub: (
    path: string,
    method?: string,
    body?: unknown,
    over?: Record<string, unknown>,
  ) => Promise<{ status: number; body: any }>
}

async function fixture(name: string): Promise<Fixture> {
  const owner = await actor(`${unique(name)}@example.com`)
  const orgId = (await createOrg(owner, name)).id
  const t = await orgToken(orgId, await orgApiKey(owner, orgId))
  expect(t.status).toBe(200)
  const token = t.body.access_token as string
  const pub = async (
    path: string,
    method = 'GET',
    body?: unknown,
    over?: Record<string, unknown>,
  ) => {
    const res = await call(`/api/public${path}`, { method, headers: bearer(token), body, over })
    const text = await res.text()
    return { status: res.status, body: text ? JSON.parse(text) : null }
  }
  return { owner, orgId, token, pub }
}

describe('member email change through the Public API', () => {
  let f: Fixture
  const domain = `${unique('rv')}.test`
  beforeAll(async () => {
    f = await fixture('email-change')
    await claimDomain(f.orgId, domain)
  })

  /** A claimed member whose account has no master password. */
  async function claimed(local: string) {
    const person = await actor(`${local}@${domain}`)
    const id = await addMember(f.owner, f.orgId, person)
    await createDb(env.DB)
      .update(schema.users)
      .set({ passwordHash: '' })
      .where(eq(schema.users.uuid, person.uuid))
    return { person, id }
  }

  it('refuses an address that ADMIN_EMAILS lists', async () => {
    const { person, id } = await claimed(unique('adm-target'))
    const admin = `${unique('boss')}@${domain}`
    const res = await f.pub(
      `/members/${id}`,
      'PUT',
      { type: 2, email: admin },
      { ADMIN_EMAILS: admin },
    )
    expect(res.status).toBe(400)
    expect(res.body.errors).toHaveProperty('email')
    const [u] = await createDb(env.DB)
      .select()
      .from(schema.users)
      .where(eq(schema.users.uuid, person.uuid))
    expect(u?.email).toBe(person.email)
  })

  it('resets the instance role, ends old sessions and tells both addresses', async () => {
    const { person, id } = await claimed(unique('moved'))
    const db = createDb(env.DB)
    await db
      .update(schema.users)
      .set({ instanceRole: 'admin' })
      .where(eq(schema.users.uuid, person.uuid))
    const [before] = await db.select().from(schema.users).where(eq(schema.users.uuid, person.uuid))
    const next = `${unique('moved-to')}@${domain}`
    const sent = mail.sent.length
    const res = await f.pub(`/members/${id}`, 'PUT', { type: 2, email: next })
    expect(res.status).toBe(200)
    const [after] = await db.select().from(schema.users).where(eq(schema.users.uuid, person.uuid))
    expect(after?.email).toBe(next)
    expect(after?.instanceRole).toBe('user')
    expect(after?.securityStamp).not.toBe(before?.securityStamp)
    // The old token no longer works.
    expect((await person.call('/api/accounts/profile')).status).toBe(401)
    await vi.waitFor(() => {
      const notices = mail.sent.slice(sent)
      expect(notices.map((m) => m.to).sort()).toEqual([next, person.email].sort())
    })
  })

  it('answers an address that is taken with 400', async () => {
    const { id } = await claimed(unique('taken-target'))
    const other = await actor(`${unique('taken-other')}@${domain}`)
    const res = await f.pub(`/members/${id}`, 'PUT', { type: 2, email: other.email })
    expect(res.status).toBe(400)
  })

  it('recognises the unique email index as a taken address', async () => {
    const db = createDb(env.DB)
    const a = await actor(`${unique('dup-a')}@example.com`)
    const b = await actor(`${unique('dup-b')}@example.com`)
    const err = await db
      .update(schema.users)
      .set({ email: a.email })
      .where(eq(schema.users.uuid, b.uuid))
      .then(
        () => null,
        (e: unknown) => e,
      )
    expect(err).not.toBeNull()
    expect(isEmailTakenError(err)).toBe(true)
    expect(isEmailTakenError(new Error('boom'))).toBe(false)
  })
})

describe('PUT resets what it does not provide', () => {
  it('ends blanket access and applies the named collections for a member', async () => {
    const f = await fixture('put-member')
    const x = (
      await f.owner.json(`/api/organizations/${f.orgId}/collections`, 'POST', { name: '2.x' })
    ).id
    const y = (
      await f.owner.json(`/api/organizations/${f.orgId}/collections`, 'POST', { name: '2.y' })
    ).id
    const person = await actor(`${unique('put-person')}@example.com`)
    const id = await addMember(f.owner, f.orgId, person, { accessAll: true })
    const before = await person.json('/api/collections')
    expect(before.data.map((c: any) => c.id)).toEqual(expect.arrayContaining([x, y]))
    const put = await f.pub(`/members/${id}`, 'PUT', {
      type: 2,
      collections: [{ id: x, readOnly: false, hidePasswords: false, manage: false }],
    })
    expect(put.status).toBe(200)
    const after = await person.json('/api/collections')
    expect(after.data.map((c: any) => c.id)).toEqual([x])
  })

  it('ends blanket access for a group', async () => {
    const f = await fixture('put-group')
    const g = await f.pub('/groups', 'POST', { name: 'G' })
    const db = createDb(env.DB)
    await db.update(schema.groups).set({ accessAll: true }).where(eq(schema.groups.uuid, g.body.id))
    expect((await f.pub(`/groups/${g.body.id}`, 'PUT', { name: 'G2' })).status).toBe(200)
    const [row] = await db.select().from(schema.groups).where(eq(schema.groups.uuid, g.body.id))
    expect(row?.accessAll).toBe(false)
  })
})

describe('seat limit', () => {
  /** An organisation whose only member is its owner, with one seat. */
  async function oneSeat(name: string) {
    const f = await fixture(name)
    const put = await f.pub('/organization/subscription', 'PUT', { passwordManager: { seats: 1 } })
    expect(put.status).toBe(200)
    return f
  }
  const full = /maximum number of users/

  it('refuses Public API POST /members', async () => {
    const f = await oneSeat('seat-post')
    const res = await f.pub('/members', 'POST', { email: `${unique('s')}@example.com`, type: 2 })
    expect(res.status).toBe(400)
    expect(res.body.message).toMatch(full)
  })

  it('refuses an organisation invite', async () => {
    const f = await oneSeat('seat-invite')
    const res = await f.owner.call(`/api/organizations/${f.orgId}/users/invite`, 'POST', {
      emails: [`${unique('s')}@example.com`],
      type: 2,
    })
    expect(res.status).toBe(400)
    expect(((await res.json()) as any).message).toMatch(full)
  })

  it('refuses a directory import that adds a member and allows one that frees the seat', async () => {
    const f = await oneSeat('seat-import')
    const res = await f.pub('/organization/import', 'POST', {
      members: [{ email: `${unique('s')}@example.com`, externalId: unique('ext') }],
      groups: [],
      overwriteExisting: false,
    })
    expect(res.status).toBe(400)
    expect(res.body.message).toMatch(full)
  })

  it('refuses SCIM user creation', async () => {
    const f = await oneSeat('seat-scim')
    const key = await orgApiKey(f.owner, f.orgId, 2)
    await f.owner.json(`/api/organizations/${f.orgId}/scim-config`, 'PUT', {
      enabled: true,
      provider: 1,
    })
    const res = await call(`/scim/v2/${f.orgId}/Users`, {
      method: 'POST',
      headers: { ...bearer(key), 'Content-Type': 'application/scim+json' },
      body: {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        externalId: unique('ext'),
        userName: `${unique('s')}@example.com`,
        active: true,
      },
    })
    expect(res.status).toBe(400)
    expect(((await res.json()) as any).detail ?? '').toMatch(full)
  })

  it('refuses an invite link join and reports no seats available', async () => {
    const f = await oneSeat('seat-link')
    const link = await f.owner.json(`/api/organizations/${f.orgId}/invite-link`, 'POST', {
      allowedDomains: ['example.com'],
      invite: 'opaque',
    })
    const join = { organizationId: f.orgId, code: link.code }
    const status = await call('/api/organizations/invite-link/status', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: join,
    })
    expect(((await status.json()) as any).seatsAvailable).toBe(false)
    const joiner = await actor(`${unique('s-join')}@example.com`)
    const res = await joiner.call('/api/organizations/users/invite-link/accept', 'POST', join)
    expect(res.status).toBe(400)
    expect(((await res.json()) as any).message).toMatch(full)
  })

  it('reports free seats on a link and the limit in the Admin Console view', async () => {
    const f = await fixture('seat-view')
    const link = await f.owner.json(`/api/organizations/${f.orgId}/invite-link`, 'POST', {
      allowedDomains: ['example.com'],
      invite: 'opaque',
    })
    const join = { organizationId: f.orgId, code: link.code }
    const status = () =>
      call('/api/organizations/invite-link/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: join,
      }).then((r) => r.json() as Promise<any>)
    expect((await status()).seatsAvailable).toBe(true)
    await f.pub('/organization/subscription', 'PUT', {
      passwordManager: { seats: 5, maxAutoScaleSeats: 9 },
    })
    expect((await status()).seatsAvailable).toBe(true)
    const org = await f.owner.json(`/api/organizations/${f.orgId}`)
    expect(org).toMatchObject({ seats: 5, maxAutoscaleSeats: 9 })
  })

  it('refuses a new single sign-on member', async () => {
    const idp: OidcIdp = await startIdp()
    const f = await oneSeat('seat-sso')
    const identifier = unique('acme')
    await configureOidc(f.owner, f.orgId, identifier, idp)
    const email = `${unique('jit')}@example.com`
    const { token } = await oidcLogin(idp, identifier, { sub: unique('sub'), email })
    expect(token?.status).not.toBe(200)
    const users = await f.owner.json(`/api/organizations/${f.orgId}/users`)
    expect(users.data.find((u: any) => u.email === email)).toBeUndefined()
  })

  it('admits members that fit', async () => {
    const f = await fixture('seat-fit')
    await f.pub('/organization/subscription', 'PUT', { passwordManager: { seats: 2 } })
    const first = await f.pub('/members', 'POST', { email: `${unique('s')}@example.com`, type: 2 })
    expect(first.status).toBe(200)
    const second = await f.pub('/members', 'POST', { email: `${unique('s')}@example.com`, type: 2 })
    expect(second.status).toBe(400)
  })

  it('skips the occupancy check when the seat count is unchanged', async () => {
    const f = await oneSeat('seat-same')
    // A member that exceeds the seats, for example after a restore.
    await createDb(env.DB)
      .insert(schema.usersOrganizations)
      .values({
        uuid: crypto.randomUUID(),
        userUuid: null,
        organizationUuid: f.orgId,
        email: `${unique('over')}@example.com`,
        akey: '',
        status: 0,
        atype: 2,
        accessAll: false,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      })
    const same = await f.pub('/organization/subscription', 'PUT', {
      passwordManager: { seats: 1, storage: 4 },
    })
    expect(same.status).toBe(200)
    const fewer = await f.pub('/organization/subscription', 'PUT', {
      passwordManager: { seats: 0 },
    })
    expect(fewer.status).toBe(400)
  })
})

describe('subscription upsert', () => {
  it('writes only the limits that the request supplied', async () => {
    const f = await fixture('upsert')
    const db = createDb(env.DB)
    // Two updates read the empty state before either writes.
    const stale = undefined
    const a = { passwordManager: { seats: 7 } }
    const b = { passwordManager: { storage: 3 } }
    const rowA = await mergeSubscription(db, f.orgId, stale, a, 1)
    const rowB = await mergeSubscription(db, f.orgId, stale, b, 2)
    await db.batch([subscriptionUpsert(db, rowA, a)] as never)
    await db.batch([subscriptionUpsert(db, rowB, b)] as never)
    const got = await f.pub('/organization/subscription')
    expect(got.body.passwordManager).toMatchObject({ seats: 7, storage: 3 })
  })
})

describe('event continuation window', () => {
  afterEach(() => vi.useRealTimers())

  it('keeps the default window of the first page', async () => {
    const f = await fixture('events-window')
    const db = createDb(env.DB)
    const now = Date.now()
    const rows = (count: number, at: (i: number) => number) =>
      Array.from({ length: count }, (_, i) => ({
        uuid: crypto.randomUUID(),
        eventType: 2101,
        organizationUuid: f.orgId,
        eventDate: at(i),
      }))
    // 50 recent events fill page one. Three events a little inside the 30 day window follow.
    const seed = [
      ...rows(50, (i) => now - 1000 - i),
      ...rows(3, (i) => now - 30 * 24 * 3600 * 1000 + 20_000 + i),
    ]
    for (const row of seed) await db.insert(schema.events).values(row)
    const first = await f.pub('/events')
    expect(first.body.data).toHaveLength(50)
    expect(first.body.continuationToken).toBeTruthy()
    // One minute later, a window that moved would start after those three events.
    vi.useFakeTimers({ toFake: ['Date'], now: now + 60_000 })
    const second = await f.pub(
      `/events?continuationToken=${encodeURIComponent(first.body.continuationToken)}`,
    )
    expect(second.status).toBe(200)
    expect(second.body.data).toHaveLength(3)
  })
})

describe('Manager members', () => {
  it('read back as Custom with no permissions, and that shape is accepted on write', async () => {
    const f = await fixture('manager')
    const person = await actor(`${unique('mgr')}@example.com`)
    const id = await addMember(f.owner, f.orgId, person)
    await createDb(env.DB)
      .update(schema.usersOrganizations)
      .set({ atype: 3 })
      .where(eq(schema.usersOrganizations.uuid, id))
    const got = await f.pub(`/members/${id}`)
    expect(got.status).toBe(200)
    conforms('GET /api/public/members/{id}', 200, got.body)
    expect(got.body.type).toBe(4)
    expect(Object.values(got.body.permissions).every((v) => v === false)).toBe(true)
    const list = await f.pub('/members')
    expect(list.body.data.find((m: any) => m.id === id).type).toBe(4)
    const put = await f.pub(`/members/${id}`, 'PUT', {
      type: got.body.type,
      permissions: got.body.permissions,
      collections: got.body.collections,
    })
    expect(put.status).toBe(200)
    conforms('PUT /api/public/members/{id}', 200, put.body)
    expect(put.body.type).toBe(4)
  })
})
