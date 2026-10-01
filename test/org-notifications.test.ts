import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'
import { BASE } from './helpers'
import { actor, addMember, createOrg, loginCipher } from './org-helpers'

const RS = '\x1e'

/** Connects a member's websocket and returns the notifications received so far. */
async function listen(token: string) {
  const res = await SELF.fetch(`${BASE}/notifications/hub?access_token=${token}`, {
    headers: { Upgrade: 'websocket' },
  })
  const ws = res.webSocket as WebSocket
  const raw: string[] = []
  ws.addEventListener('message', (e) => {
    raw.push(e.data as string)
  })
  ws.accept()
  ws.send(`{"protocol":"json","version":1}${RS}`)
  await until(() => raw.length > 0)
  raw.length = 0
  return {
    ws,
    types: () =>
      raw.map((m) => JSON.parse(m.slice(0, -1)).arguments?.[0] as { Type: number; Payload: any }),
  }
}

async function until(fn: () => boolean, ms = 3000) {
  const end = Date.now() + ms
  while (!fn()) {
    if (Date.now() > end) throw new Error('timed out')
    await new Promise((r) => setTimeout(r, 10))
  }
}

it('pushes organisation changes to the members who can see them', async () => {
  const owner = await actor('push-owner@example.com')
  const member = await actor('push-member@example.com')
  const outsider = await actor('push-outsider@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  const memberOrgUser = await addMember(owner, id, member, {
    type: 2,
    collections: [{ id: defaultCollectionId, readOnly: false }],
  })
  const m = await listen(member.token)
  const o = await listen(outsider.token)

  const item = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.push', { organizationId: id }),
    collectionIds: [defaultCollectionId],
  })
  await until(() => m.types().some((t) => t.Type === 1))
  const created = m.types().find((t) => t.Type === 1)
  expect(created?.Payload).toMatchObject({
    Id: item.id,
    UserId: member.uuid,
    OrganizationId: id,
    CollectionIds: [defaultCollectionId],
  })

  await owner.call(`/api/ciphers/${item.id}`, 'PUT', loginCipher('2.push2', { organizationId: id }))
  await until(() => m.types().some((t) => t.Type === 0))
  await owner.call(`/api/ciphers/${item.id}/delete`, 'PUT')
  await until(() => m.types().some((t) => t.Type === 9))
  await owner.call(`/api/ciphers/${item.id}`, 'DELETE')
  await until(() => m.types().some((t) => t.Type === 2))

  // Structural changes trigger a full sync.
  await owner.json(`/api/organizations/${id}/collections`, 'POST', { name: '2.new' })
  await until(() => m.types().some((t) => t.Type === 5))

  // Confirming a member tells them about the organisation key.
  const late = await actor('push-late@example.com')
  const l = await listen(late.token)
  await addMember(owner, id, late, { type: 2 })
  await until(() => l.types().some((t) => t.Type === 6))
  expect(memberOrgUser).toBeTruthy()

  // Someone outside the organisation heard nothing.
  expect(o.types()).toEqual([])
  for (const x of [m, o, l]) x.ws.close(1000)
})
