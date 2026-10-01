import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { actor, addMember, createOrg, loginCipher } from './org-helpers'

it('records server events on write paths and filters them', async () => {
  const owner = await actor('ev-owner@example.com')
  const member = await actor('ev-member@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  const memberId = await addMember(owner, id, member, {
    type: 2,
    collections: [{ id: defaultCollectionId, readOnly: false }],
  })
  const item = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.ev', { organizationId: id }),
    collectionIds: [defaultCollectionId],
  })
  await owner.call(`/api/ciphers/${item.id}`, 'PUT', loginCipher('2.ev2', { organizationId: id }))
  await owner.call(`/api/organizations/${id}/policies/7`, 'PUT', { enabled: true })
  await owner.json(`/api/organizations/${id}/groups`, 'POST', { name: 'G' })

  const events = await owner.json(`/api/organizations/${id}/events`)
  const types = events.data.map((e: any) => e.type)
  for (const t of [1500, 1501, 1100, 1101, 1700, 1400]) expect(types).toContain(t)
  expect(events.continuationToken).toBeNull()
  const created = events.data.find((e: any) => e.type === 1100)
  expect(created).toMatchObject({
    cipherId: item.id,
    organizationId: id,
    actingUserId: owner.uuid,
    object: 'event',
  })
  expect(created.date).toMatch(/^\d{4}-\d\d-\d\dT/)
  // Newest first.
  const dates = events.data.map((e: any) => Date.parse(e.date))
  expect([...dates].sort((a, b) => b - a)).toEqual(dates)
  const forMember = await owner.json(`/api/organizations/${id}/users/${memberId}/events`)
  expect(forMember.data.some((e: any) => e.type === 1501)).toBe(true)

  const forCipher = await owner.json(`/api/ciphers/${item.id}/events`)
  expect(forCipher.data.map((e: any) => e.type).sort()).toEqual([1100, 1101])
  expect((await member.call(`/api/ciphers/${item.id}/events`)).status).toBe(403)
  expect((await member.call(`/api/organizations/${id}/events`)).status).toBe(403)

  // Date filters.
  const future = new Date(Date.now() + 3600_000).toISOString()
  expect(
    (await owner.json(`/api/organizations/${id}/events?start=${encodeURIComponent(future)}`)).data,
  ).toHaveLength(0)
})

it('accepts client events and drops the ones it cannot place', async () => {
  const owner = await actor('cl-owner@example.com')
  const member = await actor('cl-member@example.com')
  const other = await actor('cl-other@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  await addMember(owner, id, member, { type: 2, collections: [{ id: defaultCollectionId }] })
  const item = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.cl', { organizationId: id }),
    collectionIds: [defaultCollectionId],
  })
  const personal = await member.json('/api/ciphers', 'POST', loginCipher('2.p'))
  const now = new Date().toISOString()
  const res = await member.call('/events/collect', 'POST', [
    { type: 1107, cipherId: item.id, date: now },
    { type: 1111, cipherId: item.id, date: now },
    { type: 1107, cipherId: personal.id, date: now },
    { type: 1107, cipherId: crypto.randomUUID(), date: now },
    { type: 1602, organizationId: id, date: now },
  ])
  expect(res.status).toBe(200)
  // Someone with no access to the item cannot add events for it.
  expect(
    (await other.call('/events/collect', 'POST', [{ type: 1107, cipherId: item.id, date: now }]))
      .status,
  ).toBe(200)
  expect((await owner.call('/events/collect', 'POST', 'not an array')).status).toBe(400)

  const events = await owner.json(`/api/organizations/${id}/events`)
  const client = events.data.filter((e: any) => e.type >= 1107 && e.type !== 1500 && e.type < 1200)
  expect(client.map((e: any) => e.type).sort()).toEqual([1107, 1111])
  expect(events.data.some((e: any) => e.type === 1602)).toBe(true)
  expect(events.data.some((e: any) => e.cipherId === personal.id)).toBe(false)
})

it('paginates with a continuation token', async () => {
  const owner = await actor('pg-owner@example.com')
  const { id } = await createOrg(owner)
  const base = Date.now() - 1_000_000
  const stmts = Array.from({ length: 120 }, (_, i) =>
    env.DB.prepare(
      'insert into events (uuid, event_type, organization_uuid, event_date) values (?, 1101, ?, ?)',
    ).bind(crypto.randomUUID(), id, base + Math.floor(i / 2)),
  )
  await env.DB.batch(stmts)

  const seen: string[] = []
  let token: string | null = null
  let pages = 0
  do {
    const q: string = token ? `?continuationToken=${encodeURIComponent(token)}` : ''
    const page: any = await owner.json(`/api/organizations/${id}/events${q}`)
    expect(page.data.length).toBeLessThanOrEqual(50)
    seen.push(...page.data.map((e: any) => `${e.date}|${e.organizationId}`))
    token = page.continuationToken
    pages++
  } while (token && pages < 10)
  // 120 seeded (two per timestamp, so ties exercise the cursor) plus the creation events.
  expect(pages).toBeGreaterThanOrEqual(3)
  expect(seen.length).toBeGreaterThanOrEqual(120)
  const rows = await env.DB.prepare('select count(*) n from events where organization_uuid = ?')
    .bind(id)
    .first<{ n: number }>()
  expect(seen.length).toBe(rows?.n)
})

it('lists a user their own events', async () => {
  const user = await actor('own-ev@example.com')
  const res = await user.json('/api/events')
  expect(res).toMatchObject({ object: 'list', data: [] })
})
