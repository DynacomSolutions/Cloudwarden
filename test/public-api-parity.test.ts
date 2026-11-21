// Public API parity with the published reference (TASKS #24.429): the organization subscription
// pair, and the field and behaviour fixes for members, groups, policies, events and import.

import { env } from 'cloudflare:workers'
import { eq } from 'drizzle-orm'
import { beforeAll, describe, expect, it } from 'vitest'
import { createDb, schema } from '../src/db'
import { bearer, raw as call, orgApiKey, orgToken } from './org-api-helpers'
import { type Actor, actor, addMember, createOrg } from './org-helpers'
import { conforms } from './public-spec'
import { claimDomain } from './sso-helpers'

let owner: Actor
let orgId: string
let token: string
const DAY = 24 * 3600 * 1000

const pub = async (path: string, method = 'GET', body?: unknown, prefix = '/api/public') => {
  const res = await call(`${prefix}${path}`, { method, headers: bearer(token), body })
  const text = await res.text()
  return { status: res.status, body: text ? JSON.parse(text) : null }
}

beforeAll(async () => {
  owner = await actor('parity-owner@example.com')
  orgId = (await createOrg(owner, 'Parity Org')).id
  const t = await orgToken(orgId, await orgApiKey(owner, orgId))
  expect(t.status).toBe(200)
  token = t.body.access_token
})

describe('organization subscription', () => {
  it('requires an organisation token', async () => {
    const res = await call('/api/public/organization/subscription')
    expect(res.status).toBe(401)
  })

  it('answers with no limits set, on both path layouts', async () => {
    for (const prefix of ['/api/public', '/public']) {
      const got = await pub('/organization/subscription', 'GET', undefined, prefix)
      expect(got.status).toBe(200)
      conforms('GET /api/public/organization/subscription', 200, got.body)
      expect(got.body.passwordManager).toEqual({
        seats: null,
        maxAutoScaleSeats: null,
        storage: null,
      })
    }
  })

  it('stores limits, merges partial updates and reads them back', async () => {
    const put = await pub('/organization/subscription', 'PUT', {
      passwordManager: { seats: 25, maxAutoScaleSeats: 40, storage: 10 },
      secretsManager: { seats: 5, serviceAccounts: 20, maxAutoScaleServiceAccounts: 30 },
    })
    expect(put.status).toBe(200)
    const part = await pub('/organization/subscription', 'PUT', {
      passwordManager: { storage: 12, seats: null },
    })
    expect(part.status).toBe(200)
    const got = await pub('/organization/subscription')
    conforms('GET /api/public/organization/subscription', 200, got.body)
    expect(got.body).toEqual({
      passwordManager: { seats: 25, maxAutoScaleSeats: 40, storage: 12 },
      secretsManager: {
        seats: 5,
        maxAutoScaleSeats: null,
        serviceAccounts: 20,
        maxAutoScaleServiceAccounts: 30,
      },
    })
    // The cloud layout reads the same row.
    const cloud = await pub('/organization/subscription', 'GET', undefined, '/public')
    expect(cloud.body).toEqual(got.body)
    // An empty body changes nothing.
    expect((await pub('/organization/subscription', 'PUT', {})).status).toBe(200)
    expect((await pub('/organization/subscription')).body).toEqual(got.body)
  })

  it('refuses values the limits cannot hold', async () => {
    const used = (await pub('/members')).body.data.length
    expect(used).toBeGreaterThan(0)
    const tooFew = await pub('/organization/subscription', 'PUT', {
      passwordManager: { seats: used - 1 },
    })
    expect(tooFew.status).toBe(400)
    conforms('PUT /api/public/organization/subscription', 400, tooFew.body)
    expect(tooFew.body.errors).toHaveProperty(['passwordManager.seats'])
    const below = await pub('/organization/subscription', 'PUT', {
      passwordManager: { maxAutoScaleSeats: 3 },
    })
    expect(below.status).toBe(400)
    expect(below.body.errors).toHaveProperty(['passwordManager.maxAutoScaleSeats'])
    const negative = await pub('/organization/subscription', 'PUT', {
      passwordManager: { storage: -1 },
    })
    expect(negative.status).toBe(400)
    const fraction = await pub('/organization/subscription', 'PUT', {
      secretsManager: { serviceAccounts: 1.5 },
    })
    expect(fraction.status).toBe(400)
    // A refused update stores nothing.
    expect((await pub('/organization/subscription')).body.passwordManager.seats).toBe(25)
  })
})

describe('members', () => {
  it('has no accessAll, no manageCiphers and the published permissions', async () => {
    const created = await pub('/members', 'POST', {
      email: 'parity-custom@example.com',
      name: 'Ignored Name',
      type: 4,
      permissions: { accessEventLogs: true, manageAccessRules: true, manageCiphers: true },
    })
    expect(created.status).toBe(200)
    conforms('POST /api/public/members', 200, created.body)
    expect(created.body).not.toHaveProperty('accessAll')
    expect(Object.keys(created.body.permissions).sort()).toEqual(
      [
        'accessEventLogs',
        'accessImportExport',
        'accessReports',
        'createNewCollections',
        'editAnyCollection',
        'deleteAnyCollection',
        'manageGroups',
        'managePolicies',
        'manageSso',
        'manageUsers',
        'manageResetPassword',
        'manageScim',
        'manageAccessRules',
      ].sort(),
    )
    expect(created.body.permissions).toMatchObject({
      accessEventLogs: true,
      manageAccessRules: true,
    })
    const list = await pub('/members')
    expect(list.body).not.toHaveProperty('continuationToken')
    expect(list.body.data.every((m: any) => !('accessAll' in m))).toBe(true)
  })

  it('refuses the Manager type', async () => {
    const res = await pub('/members', 'POST', { email: 'parity-mgr@example.com', type: 3 })
    expect(res.status).toBe(400)
    expect(res.body.errors).toHaveProperty('type')
    const ok = await pub('/members', 'POST', { email: 'parity-mgr2@example.com', type: 2 })
    expect((await pub(`/members/${ok.body.id}`, 'PUT', { type: 3 })).status).toBe(400)
  })

  it('resets blanket access when a member is updated and applies the named collections', async () => {
    const m = await pub('/members', 'POST', { email: 'parity-all@example.com', type: 2 })
    const db = createDb(env.DB)
    await db
      .update(schema.usersOrganizations)
      .set({ accessAll: true })
      .where(eq(schema.usersOrganizations.uuid, m.body.id))
    const put = await pub(`/members/${m.body.id}`, 'PUT', { type: 2, externalId: 'reset' })
    expect(put.status).toBe(200)
    const [row] = await db
      .select()
      .from(schema.usersOrganizations)
      .where(eq(schema.usersOrganizations.uuid, m.body.id))
    expect(row?.accessAll).toBe(false)
  })

  it('returns the SSO external id of a linked member', async () => {
    const person = await actor('parity-sso@example.com')
    const id = await addMember(owner, orgId, person)
    expect((await pub(`/members/${id}`)).body.ssoExternalId).toBeNull()
    await createDb(env.DB).insert(schema.ssoUsers).values({
      organizationUuid: orgId,
      userUuid: person.uuid,
      externalId: 'idp-sub-1',
      createdAt: Date.now(),
    })
    const got = await pub(`/members/${id}`)
    conforms('GET /api/public/members/{id}', 200, got.body)
    expect(got.body.ssoExternalId).toBe('idp-sub-1')
    expect((await pub('/members')).body.data.find((m: any) => m.id === id).ssoExternalId).toBe(
      'idp-sub-1',
    )
  })

  it('changes name and email of a claimed member only', async () => {
    const person = await actor('parity-claim@example.com')
    const id = await addMember(owner, orgId, person)
    // Not claimed: a different name or email address is refused, the same one is accepted.
    const same = await pub(`/members/${id}`, 'PUT', {
      type: 2,
      email: 'parity-claim@example.com',
    })
    expect(same.status).toBe(200)
    const refusedName = await pub(`/members/${id}`, 'PUT', { type: 2, name: 'New Name' })
    expect(refusedName.status).toBe(400)
    expect(refusedName.body.errors).toHaveProperty('name')
    const refusedEmail = await pub(`/members/${id}`, 'PUT', {
      type: 2,
      email: 'parity-claim2@example.com',
    })
    expect(refusedEmail.status).toBe(400)
    expect(refusedEmail.body.errors).toHaveProperty('email')

    await claimDomain(orgId, 'example.com')
    // Claimed, but the account has a master password: the name changes, the email does not.
    const named = await pub(`/members/${id}`, 'PUT', { type: 2, name: 'New Name' })
    expect(named.status).toBe(200)
    expect(named.body.name).toBe('New Name')
    const withPassword = await pub(`/members/${id}`, 'PUT', {
      type: 2,
      email: 'parity-claim2@example.com',
    })
    expect(withPassword.status).toBe(400)

    const db = createDb(env.DB)
    await db
      .update(schema.users)
      .set({ passwordHash: '' })
      .where(eq(schema.users.uuid, person.uuid))
    const offDomain = await pub(`/members/${id}`, 'PUT', { type: 2, email: 'x@other.test' })
    expect(offDomain.status).toBe(400)
    const moved = await pub(`/members/${id}`, 'PUT', {
      type: 2,
      email: 'Parity-Claim2@Example.com',
    })
    expect(moved.status).toBe(200)
    conforms('PUT /api/public/members/{id}', 200, moved.body)
    expect(moved.body.email).toBe('parity-claim2@example.com')
    const taken = await pub(`/members/${id}`, 'PUT', { type: 2, email: owner.email })
    expect(taken.status).toBe(400)
  }, 400_000)
})

describe('groups, collections and policies', () => {
  it('has no accessAll on groups and no continuationToken on lists', async () => {
    const g = await pub('/groups', 'POST', { name: 'Parity group', accessAll: true })
    expect(g.status).toBe(200)
    expect(g.body).not.toHaveProperty('accessAll')
    const [row] = await createDb(env.DB)
      .select()
      .from(schema.groups)
      .where(eq(schema.groups.uuid, g.body.id))
    expect(row?.accessAll).toBe(false)
    for (const path of ['/groups', '/collections', '/policies', '/members']) {
      const list = await pub(path)
      expect(list.body, path).not.toHaveProperty('continuationToken')
      expect(list.body.object).toBe('list')
    }
  })

  it('accepts policy types 0 to 22 only', async () => {
    expect((await pub('/policies/23', 'PUT', { enabled: false })).status).toBe(400)
    expect((await pub('/policies/23')).status).toBe(400)
    expect((await pub('/policies/-1')).status).toBe(400)
    const high = await pub('/policies/22', 'PUT', { enabled: true })
    expect(high.status).toBe(200)
    expect(high.body.type).toBe(22)
  })

  it('accepts metadata and checks the data of known policies', async () => {
    const ok = await pub('/policies/5', 'PUT', {
      enabled: false,
      data: null,
      metadata: { defaultUserCollectionName: '2.encrypted' },
    })
    expect(ok.status).toBe(200)
    const badMeta = await pub('/policies/5', 'PUT', {
      enabled: false,
      metadata: { defaultUserCollectionName: 7 },
    })
    expect(badMeta.status).toBe(400)
    expect(badMeta.body.errors).toHaveProperty(['metadata.defaultUserCollectionName'])
    const badData = await pub('/policies/1', 'PUT', {
      enabled: true,
      data: { minLength: 'long', requireUpper: 'yes' },
    })
    expect(badData.status).toBe(400)
    expect(Object.keys(badData.body.errors)).toEqual(
      expect.arrayContaining(['data.minLength', 'data.requireUpper']),
    )
    const good = await pub('/policies/1', 'PUT', {
      enabled: true,
      data: { minLength: 12, requireUpper: true, other: 'kept' },
    })
    expect(good.status).toBe(200)
    expect(good.body.data).toMatchObject({ minLength: 12, other: 'kept' })
  })
})

describe('events', () => {
  const ids = {
    acting: crypto.randomUUID(),
    item: crypto.randomUUID(),
    secret: crypto.randomUUID(),
    project: crypto.randomUUID(),
  }
  const seed = async (rows: Partial<typeof schema.events.$inferInsert>[]) => {
    const db = createDb(env.DB)
    for (const r of rows) {
      await db.insert(schema.events).values({
        uuid: crypto.randomUUID(),
        eventType: 2101,
        organizationUuid: orgId,
        eventDate: Date.now(),
        ...r,
      })
    }
  }
  const dates = async (query: string) =>
    (await pub(`/events${query}`)).body.data.map((e: any) => Date.parse(e.date))

  beforeAll(async () => {
    const now = Date.now()
    await seed([
      { eventDate: now - 5 * DAY, secretUuid: ids.secret, projectUuid: ids.project },
      { eventDate: now - 10 * DAY, actingUserUuid: ids.acting, cipherUuid: ids.item },
      { eventDate: now - 40 * DAY, secretUuid: ids.secret },
      { eventDate: now - 200 * DAY, projectUuid: ids.project },
      { eventDate: now - 500 * DAY, secretUuid: ids.secret },
    ])
  })

  it('defaults to the last 30 days', async () => {
    const all = await dates('')
    expect(all.length).toBeGreaterThan(0)
    expect(all.every((d: number) => d >= Date.now() - 31 * DAY)).toBe(true)
    // With only an end date, the window is the 30 days before it.
    const end = new Date(Date.now() - 100 * DAY).toISOString()
    expect(await dates(`?end=${encodeURIComponent(end)}`)).toEqual([])
    // Ends 190 days ago: the window runs from 220 to 190 days ago and holds the 200 day old event.
    const end2 = new Date(Date.now() - 190 * DAY).toISOString()
    expect(await dates(`?end=${encodeURIComponent(end2)}`)).toHaveLength(1)
  })

  it('honours start, swaps an inverted range and limits it to 367 days', async () => {
    const start = encodeURIComponent(new Date(Date.now() - 50 * DAY).toISOString())
    const end = encodeURIComponent(new Date(Date.now() - 1 * DAY).toISOString())
    const normal = await dates(`?start=${start}&end=${end}`)
    expect(normal.length).toBeGreaterThanOrEqual(3)
    expect(await dates(`?start=${end}&end=${start}`)).toEqual(normal)
    const wide = encodeURIComponent(new Date(Date.now() - 400 * DAY).toISOString())
    const tooWide = await pub(`/events?start=${wide}`)
    expect(tooWide.status).toBe(400)
    expect(tooWide.body).toMatchObject({
      object: 'error',
      message: 'Date range must be < 367 days.',
    })
    const bad = await pub('/events?start=yesterday')
    expect(bad.status).toBe(400)
    const ok = encodeURIComponent(new Date(Date.now() - 360 * DAY).toISOString())
    const long = await pub(`/events?start=${ok}`)
    expect(long.status).toBe(200)
    conforms('GET /api/public/events', 200, long.body)
  })

  it('filters by secret and project, and the first filter present wins', async () => {
    const start = encodeURIComponent(new Date(Date.now() - 300 * DAY).toISOString())
    const bySecret = (await pub(`/events?start=${start}&secretId=${ids.secret}`)).body.data
    expect(bySecret).toHaveLength(2)
    expect(bySecret.every((e: any) => e.secretId === ids.secret)).toBe(true)
    const byProject = (await pub(`/events?start=${start}&projectId=${ids.project}`)).body.data
    expect(byProject).toHaveLength(2)
    expect(byProject.every((e: any) => e.projectId === ids.project)).toBe(true)
    // actingUserId beats itemId, itemId beats secretId, secretId beats projectId.
    const acting = (
      await pub(`/events?start=${start}&actingUserId=${ids.acting}&secretId=${ids.secret}`)
    ).body.data
    expect(acting).toHaveLength(1)
    expect(acting[0].actingUserId).toBe(ids.acting)
    const item = (await pub(`/events?start=${start}&itemId=${ids.item}&secretId=${ids.secret}`))
      .body.data
    expect(item).toHaveLength(1)
    expect(item[0].itemId).toBe(ids.item)
    const secret = (
      await pub(`/events?start=${start}&secretId=${ids.secret}&projectId=${ids.project}`)
    ).body.data
    expect(secret).toHaveLength(2)
    expect(secret.every((e: any) => e.secretId === ids.secret)).toBe(true)
    // An unknown secret or project lists nothing.
    const none = await pub(`/events?secretId=${crypto.randomUUID()}`)
    expect(none.body.data).toEqual([])
  })
})

describe('directory import', () => {
  it('requires overwriteExisting', async () => {
    const missing = await pub('/organization/import', 'POST', { members: [], groups: [] })
    expect(missing.status).toBe(400)
    expect(missing.body.errors).toHaveProperty('overwriteExisting')
    const nullValue = await pub('/organization/import', 'POST', {
      members: [],
      overwriteExisting: null,
    })
    expect(nullValue.status).toBe(400)
    const ok = await pub('/organization/import', 'POST', {
      members: [],
      groups: [],
      overwriteExisting: false,
    })
    expect(ok.status).toBe(200)
  })
})
