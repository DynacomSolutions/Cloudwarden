import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { actor, addMember, createOrg, linkParams, loginCipher, mailbox } from './org-helpers'

it('stops a custom user manager escalating through update or invite', async () => {
  const mb = mailbox()
  const owner = await actor('sec-owner@example.com', mb)
  const custom = await actor('sec-custom@example.com', mb)
  const plain = await actor('sec-plain@example.com', mb)
  const { id } = await createOrg(owner)
  const customId = await addMember(
    owner,
    id,
    custom,
    { type: 4, permissions: { manageUsers: true } },
    mb,
  )
  const plainId = await addMember(owner, id, plain, { type: 2 }, mb)

  // No self-edit, even to the same values.
  const self = await custom.call(`/api/organizations/${id}/users/${customId}`, 'PUT', {
    type: 4,
    accessAll: true,
    permissions: { manageUsers: true, managePolicies: true },
  })
  expect(self.status).toBe(403)
  // No granting what they do not hold, to others or through invites.
  const grant = (extra: object) =>
    custom.call(`/api/organizations/${id}/users/${plainId}`, 'PUT', { type: 2, ...extra })
  expect((await grant({ accessAll: true })).status).toBe(403)
  const invite = (body: object) =>
    custom.call(`/api/organizations/${id}/users/invite`, 'POST', {
      emails: ['sec-new@example.com'],
      ...body,
    })
  expect((await invite({ type: 4, permissions: { managePolicies: true } })).status).toBe(403)
  expect((await invite({ type: 2, accessAll: true })).status).toBe(403)
  expect((await invite({ type: 1 })).status).toBe(403)
  // What they do hold is fine.
  expect((await invite({ type: 4, permissions: { manageUsers: true } })).status).toBe(200)
  expect((await grant({})).status).toBe(200)
})

it('limits group and reinvite changes to what the actor may manage', async () => {
  const mb = mailbox()
  const owner = await actor('sec2-owner@example.com', mb)
  const custom = await actor('sec2-custom@example.com', mb)
  const admin = await actor('sec2-admin@example.com', mb)
  const { id } = await createOrg(owner)
  const customId = await addMember(
    owner,
    id,
    custom,
    { type: 4, permissions: { manageUsers: true, manageGroups: true } },
    mb,
  )
  const adminId = await addMember(owner, id, admin, { type: 1 }, mb)
  const group = await owner.json(`/api/organizations/${id}/groups`, 'POST', { name: 'G' })
  const wide = await owner.json(`/api/organizations/${id}/groups`, 'POST', {
    name: 'W',
    accessAll: true,
  })

  const put = (target: string) =>
    custom.call(`/api/organizations/${id}/users/${target}/groups`, 'PUT', { groupIds: [group.id] })
  expect((await put(customId)).status).toBe(403)
  expect((await put(adminId)).status).toBe(403)

  expect(
    (await custom.call(`/api/organizations/${id}/groups`, 'POST', { name: 'X', accessAll: true }))
      .status,
  ).toBe(403)
  expect(
    (
      await custom.call(`/api/organizations/${id}/groups/${wide.id}`, 'PUT', {
        name: 'W',
        accessAll: false,
      })
    ).status,
  ).toBe(403)
  expect(
    (await custom.call(`/api/organizations/${id}/groups/${wide.id}/users`, 'PUT', [customId]))
      .status,
  ).toBe(403)
  expect(
    (await admin.call(`/api/organizations/${id}/groups`, 'POST', { name: 'Y', accessAll: true }))
      .status,
  ).toBe(200)

  expect(
    (await custom.call(`/api/organizations/${id}/users/${adminId}/reinvite`, 'POST')).status,
  ).toBe(403)
})

it('keeps group collections when an update omits them', async () => {
  const owner = await actor('sec3-owner@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  const group = await owner.json(`/api/organizations/${id}/groups`, 'POST', {
    name: 'G',
    collections: [{ id: defaultCollectionId, readOnly: true }],
  })
  await owner.call(`/api/organizations/${id}/groups/${group.id}`, 'PUT', { name: 'Renamed' })
  const details = await owner.json(`/api/organizations/${id}/groups/${group.id}/details`)
  expect(details.collections).toHaveLength(1)
  await owner.call(`/api/organizations/${id}/groups/${group.id}`, 'PUT', {
    name: 'Renamed',
    collections: [],
  })
  expect(
    (await owner.json(`/api/organizations/${id}/groups/${group.id}/details`)).collections,
  ).toHaveLength(0)
})

it('requires manage access to change the collections of an item', async () => {
  const owner = await actor('sec4-owner@example.com')
  const member = await actor('sec4-member@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  await addMember(owner, id, member, {
    type: 2,
    collections: [{ id: defaultCollectionId, readOnly: false, manage: false }],
  })
  const other = await owner.json(`/api/organizations/${id}/collections`, 'POST', {
    name: '2.other',
  })
  const item = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.i', { organizationId: id }),
    collectionIds: [defaultCollectionId],
  })
  const body = { collectionIds: [defaultCollectionId] }
  expect((await member.call(`/api/ciphers/${item.id}/collections_v2`, 'PUT', body)).status).toBe(
    403,
  )
  expect(
    (
      await member.call('/api/ciphers/bulk-collections', 'POST', {
        organizationId: id,
        cipherIds: [item.id],
        collectionIds: [other.id],
      })
    ).status,
  ).toBeGreaterThanOrEqual(403)
  expect((await owner.call(`/api/ciphers/${item.id}/collections_v2`, 'PUT', body)).status).toBe(200)
})

it('only stores whitelisted client event types', async () => {
  const owner = await actor('sec5-owner@example.com')
  const { id } = await createOrg(owner)
  const now = new Date().toISOString()
  await owner.call('/events/collect', 'POST', [
    { type: 1500, organizationId: id, date: now },
    { type: 1700, organizationId: id, date: now },
    { type: 1114, organizationId: id, date: now },
  ])
  const rows = await env.DB.prepare(
    'select event_type t from events where organization_uuid = ? order by event_type',
  )
    .bind(id)
    .all<{ t: number }>()
  expect(rows.results.map((r) => r.t)).toEqual([1114])
})

it('removes the grantor from organisations they do not own on takeover', async () => {
  const mb = mailbox()
  const grantor = await actor('sec6-grantor@example.com', mb)
  const grantee = await actor('sec6-grantee@example.com', mb)
  const boss = await actor('sec6-boss@example.com', mb)
  const owned = await createOrg(grantor, 'Mine')
  const theirs = await createOrg(boss, 'Theirs')
  await addMember(boss, theirs.id, grantor, { type: 1 }, mb)

  await grantor.call('/api/emergency-access/invite', 'POST', {
    email: grantee.email,
    type: 1,
    waitTimeDays: 1,
  })
  const p = linkParams(mb.sent.find((m) => m.to === grantee.email))
  const eid = p.get('id')
  await grantee.call(`/api/emergency-access/${eid}/accept`, 'POST', { token: p.get('token') })
  await grantor.call(`/api/emergency-access/${eid}/confirm`, 'POST', { key: '4.k' })
  await grantee.call(`/api/emergency-access/${eid}/initiate`, 'POST')
  await grantor.call(`/api/emergency-access/${eid}/approve`, 'POST')
  const res = await grantee.call(`/api/emergency-access/${eid}/password`, 'POST', {
    newMasterPasswordHash: 'taken-over',
    key: '2.k',
  })
  expect(res.status).toBe(200)
  const rows = await env.DB.prepare(
    'select organization_uuid o from users_organizations where user_uuid = ?',
  )
    .bind(grantor.uuid)
    .all<{ o: string }>()
  expect(rows.results.map((r) => r.o)).toEqual([owned.id])
})
