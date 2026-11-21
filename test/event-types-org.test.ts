// Organisation, member, invite link and attachment event types added for the Public API list.

import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { describe, expect, it } from 'vitest'
import {
  type Actor,
  actor,
  addMember,
  createOrg,
  linkParams,
  loginCipher,
  mailbox,
} from './org-helpers'

/** Event rows of an organisation, oldest first. */
async function orgEvents(orgId: string, from = 0, to = 9999) {
  const res = await env.DB.prepare(
    `select event_type t, user_uuid u, acting_user_uuid a, organization_user_uuid m, policy_uuid p, cipher_uuid c
       from events where organization_uuid = ? and event_type between ? and ? order by event_date, rowid`,
  )
    .bind(orgId, from, to)
    .all<{
      t: number
      u: string | null
      a: string | null
      m: string | null
      p: string | null
      c: string | null
    }>()
  return res.results
}
const typesOf = async (orgId: string, from?: number, to?: number) =>
  (await orgEvents(orgId, from, to)).map((e) => e.t)

describe('collection management settings (1609 to 1617)', () => {
  it('records one event per changed setting and a summary', async () => {
    const owner = await actor('etc-owner@example.com')
    const { id } = await createOrg(owner)
    const put = (v: boolean[]) =>
      owner.call(`/api/organizations/${id}/collection-management`, 'PUT', {
        limitCollectionCreation: v[0],
        limitCollectionDeletion: v[1],
        limitItemDeletion: v[2],
        allowAdminAccessToAllCollectionItems: v[3],
      })
    expect((await put([false, false, false, false])).status).toBe(200)
    const base = (await typesOf(id, 1609, 1617)).length

    expect((await put([true, true, true, true])).status).toBe(200)
    const on = (await typesOf(id, 1609, 1617)).slice(base)
    expect(on.sort()).toEqual([1609, 1610, 1612, 1614, 1616])

    // Unchanged settings record nothing.
    expect((await put([true, true, true, true])).status).toBe(200)
    expect((await typesOf(id, 1609, 1617)).length).toBe(base + on.length)

    expect((await put([false, true, false, true])).status).toBe(200)
    const off = (await typesOf(id, 1609, 1617)).slice(base + on.length)
    expect(off.sort()).toEqual([1609, 1611, 1615])
  })
})

describe('invite link events (1524, 1526, 1624 to 1630)', () => {
  it('records link management and joining', async () => {
    const owner = await actor('etl-owner@example.com')
    const { id } = await createOrg(owner, 'Linked')
    const base = `/api/organizations/${id}/invite-link`
    const link = await owner.json(base, 'POST', {
      allowedDomains: ['example.com'],
      invite: 'opaque',
      supportsConfirmation: true,
    })
    expect(await typesOf(id, 1624, 1630)).toEqual([1624, 1629])
    await owner.json(base, 'PUT', { allowedDomains: ['example.com', 'example.org'] })
    await owner.json(`${base}/refresh`, 'POST', { invite: 'opaque2' })
    // The setting stays on, so refreshing records no toggle.
    expect(await typesOf(id, 1624, 1630)).toEqual([1624, 1629, 1625, 1628])
    await owner.json(`${base}/support-confirm`, 'PUT', {
      invite: 'o3',
      supportsConfirmation: false,
    })
    await owner.json(`${base}/support-confirm`, 'PUT', {
      invite: 'o3',
      supportsConfirmation: false,
    })
    expect(await typesOf(id, 1624, 1630)).toEqual([1624, 1629, 1625, 1628, 1630])
    await owner.json(`${base}/support-confirm`, 'PUT', { invite: 'o4', supportsConfirmation: true })

    const fresh = await owner.json(base)
    expect(fresh.code).not.toBe(link.code)
    const joiner = await actor('etl-joiner@example.com')
    const join = (extra: Record<string, unknown> = {}) => ({
      organizationId: id,
      code: fresh.code,
      ...extra,
    })
    expect(
      (await joiner.call('/api/organizations/users/invite-link/accept', 'POST', join())).status,
    ).toBe(200)
    await owner.call(`/api/organizations/${id}/policies/18`, 'PUT', { enabled: true })
    const confirmer = await actor('etl-confirmer@example.com')
    expect(
      (
        await confirmer.call(
          '/api/organizations/users/invite-link/confirm',
          'POST',
          join({ orgUserKey: '4.key' }),
        )
      ).status,
    ).toBe(200)

    const types = await orgEvents(id, 1500, 1530)
    expect(types.map((e) => e.t)).toEqual(expect.arrayContaining([1524, 1526]))
    // Joining through the link is not recorded as an administrator's confirmation.
    expect(types.some((e) => e.t === 1501)).toBe(false)
    const accepted = types.find((e) => e.t === 1524)
    const confirmed = types.find((e) => e.t === 1526)
    expect(accepted).toMatchObject({ u: joiner.uuid, a: joiner.uuid })
    expect(confirmed).toMatchObject({ u: confirmer.uuid, a: confirmer.uuid })

    expect((await owner.call(base, 'DELETE')).status).toBe(200)
    expect((await typesOf(id, 1624, 1630)).at(-1)).toBe(1626)
  })
})

describe('policy events (1520, 1620, 1621)', () => {
  it('records automatic confirmation on and off once per change', async () => {
    const owner = await actor('etp-owner@example.com')
    const { id } = await createOrg(owner)
    const put = (enabled: boolean) =>
      owner.call(`/api/organizations/${id}/policies/18`, 'PUT', { enabled })
    await put(true)
    await put(true)
    await put(false)
    expect(await typesOf(id, 1620, 1621)).toEqual([1620, 1621])
    // Each write still records the policy update.
    expect((await typesOf(id, 1700, 1700)).length).toBe(3)
  })

  it('records a revocation for each member the two-step login policy removes', async () => {
    const owner = await actor('etp2-owner@example.com')
    const member = await actor('etp2-member@example.com')
    const { id } = await createOrg(owner)
    const ouId = await addMember(owner, id, member)
    const res = await owner.call(`/api/organizations/${id}/policies/0`, 'PUT', { enabled: true })
    expect(res.status).toBe(200)
    const revoked = (await orgEvents(id, 1520, 1520)).filter((e) => e.m === ouId)
    expect(revoked).toHaveLength(1)
    expect(revoked[0]).toMatchObject({ u: member.uuid, a: owner.uuid })
    expect(revoked[0]?.p).toBeTruthy()
    // The owner stays, and no other member is named.
    expect(await typesOf(id, 1520, 1520)).toHaveLength(1)
  })
})

describe('member events (1516, 1517, 1518)', () => {
  it('records leaving, revoking oneself and automatic confirmation', async () => {
    const mb = mailbox()
    const owner = await actor('etm-owner@example.com', mb)
    const leaver = await actor('etm-leaver@example.com', mb)
    const reviver = await actor('etm-revoker@example.com', mb)
    const auto = await actor('etm-auto@example.com', mb)
    const { id } = await createOrg(owner)
    const leaverId = await addMember(owner, id, leaver, {}, mb)
    const reviverId = await addMember(owner, id, reviver, {}, mb)

    expect((await leaver.call(`/api/organizations/${id}/leave`, 'POST')).status).toBe(200)
    expect((await reviver.call(`/api/organizations/${id}/users/revoke-self`, 'PUT')).status).toBe(
      200,
    )
    const events = await orgEvents(id, 1500, 1530)
    expect(events.find((e) => e.t === 1516)).toMatchObject({
      m: leaverId,
      u: leaver.uuid,
      a: leaver.uuid,
    })
    expect(events.find((e) => e.t === 1518)).toMatchObject({
      m: reviverId,
      u: reviver.uuid,
      a: reviver.uuid,
    })
    // Neither is recorded as an administrator's removal or revocation.
    expect(events.some((e) => e.t === 1503 || e.t === 1511)).toBe(false)

    await owner.call(`/api/organizations/${id}/policies/18`, 'PUT', { enabled: true })
    const before = mb.sent.length
    await owner.call(`/api/organizations/${id}/users/invite`, 'POST', {
      emails: [auto.email],
      type: 2,
    })
    const p = linkParams(mb.sent[before])
    const autoId = p.get('organizationUserId') as string
    await auto.call(`/api/organizations/${id}/users/${autoId}/accept`, 'POST', {
      token: p.get('token'),
    })
    expect(
      (
        await owner.call(`/api/organizations/${id}/users/${autoId}/auto-confirm`, 'POST', {
          key: '4.k',
        })
      ).status,
    ).toBe(200)
    const confirmed = (await orgEvents(id, 1500, 1530)).filter((e) => e.m === autoId)
    expect(confirmed.map((e) => e.t)).toContain(1517)
    expect(confirmed.map((e) => e.t)).not.toContain(1501)
  }, 600_000)
})

describe('vault events (1601, 1603, 1103, 1104)', () => {
  it('records opening the whole vault and purging it', async () => {
    const owner = await actor('etv-owner@example.com')
    const member = await actor('etv-member@example.com')
    const { id } = await createOrg(owner)
    await addMember(owner, id, member)
    expect(
      (await owner.call(`/api/ciphers/organization-details?organizationId=${id}`)).status,
    ).toBe(200)
    // A member without access to everything is refused and records nothing.
    expect(
      (await member.call(`/api/ciphers/organization-details?organizationId=${id}`)).status,
    ).toBe(403)
    expect(await typesOf(id, 1603, 1603)).toEqual([1603])

    const wrong = await owner.call(`/api/ciphers/purge?organizationId=${id}`, 'POST', {
      masterPasswordHash: 'wrong',
    })
    expect(wrong.status).toBe(400)
    expect(await typesOf(id, 1601, 1601)).toEqual([])
    const purge = await owner.call(`/api/ciphers/purge?organizationId=${id}`, 'POST', {
      masterPasswordHash: 'client-derived-hash',
    })
    expect(purge.status).toBe(200)
    const [purged] = await orgEvents(id, 1601, 1601)
    expect(purged).toMatchObject({ a: owner.uuid })
  })

  it('records an attachment added to an organisation item and removed again', async () => {
    const owner = await actor('etv-att-owner@example.com')
    const { id, defaultCollectionId } = await createOrg(owner)
    const item = await owner.json('/api/ciphers/create', 'POST', {
      cipher: loginCipher('2.att', { organizationId: id }),
      collectionIds: [defaultCollectionId],
    })
    const slot = (await (
      await owner.call(`/api/ciphers/${item.id}/attachment/v2`, 'POST', {
        fileName: '2.fname',
        key: '2.fkey',
        fileSize: 2,
      })
    ).json()) as { attachmentId: string; url: string }
    // Reserving the slot records nothing: the event follows the finished upload.
    expect(await typesOf(id, 1103, 1104)).toEqual([])
    const fd = new FormData()
    fd.append('data', new Blob([new Uint8Array([1, 2])]), '2.enc-name')
    const up = await SELF.fetch(slot.url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${owner.token}` },
      body: fd,
    })
    expect(up.status).toBe(200)
    expect(await typesOf(id, 1103, 1104)).toEqual([1103])
    expect(
      (await owner.call(`/api/ciphers/${item.id}/attachment/${slot.attachmentId}`, 'DELETE'))
        .status,
    ).toBe(200)
    const events = await orgEvents(id, 1103, 1104)
    expect(events.map((e) => e.t)).toEqual([1103, 1104])
    expect(events.every((e) => e.c === item.id && e.a === owner.uuid)).toBe(true)
    const forItem = await owner.json(`/api/ciphers/${item.id}/events`)
    expect(forItem.data.map((e: any) => e.type)).toContain(1103)
  })
})

it('accepts the client events of the web and browser clients for an organisation', async () => {
  const owner = await actor('etc-client-owner@example.com')
  const { id } = await createOrg(owner)
  const now = new Date().toISOString()
  const client = [1522, 1602, 1627]
  const res = await owner.call(
    '/events/collect',
    'POST',
    client.map((type) => ({ type, organizationId: id, date: now })),
  )
  expect(res.status).toBe(200)
  expect(await typesOf(id, 1500, 1699)).toEqual(expect.arrayContaining(client))
})
