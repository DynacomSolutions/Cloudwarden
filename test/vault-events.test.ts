import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'
import { authed, BASE, createSession, login } from './helpers'

const RS = '\x1e'
const cipher = (name = '2.n') => ({ type: 2, name, secureNote: { type: 0 } })

interface Event {
  Type: number
  ContextId: string | null
  Payload: Record<string, unknown>
}

/** Two devices of one user, each listening on the hub. `a` makes the changes. */
async function twoDevices(email: string) {
  const a = await createSession(email, { deviceIdentifier: 'dev-a' })
  const b = (await (
    await login(email, 'client-derived-hash', { deviceIdentifier: 'dev-b' })
  ).json()) as { access_token: string }
  const listen = async (token: string) => {
    const res = await SELF.fetch(`${BASE}/notifications/hub?access_token=${token}`, {
      headers: { Upgrade: 'websocket' },
    })
    const ws = res.webSocket as WebSocket
    const events: Event[] = []
    let ready = false
    ws.addEventListener('message', (e) => {
      const data = e.data as string
      if (!ready) {
        ready = true
        return
      }
      events.push(JSON.parse(data.slice(0, -1)).arguments[0])
    })
    ws.accept()
    ws.send(`{"protocol":"json","version":1}${RS}`)
    while (!ready) await new Promise((r) => setTimeout(r, 5))
    return { ws, events }
  }
  const la = await listen(a.access_token)
  const lb = await listen(b.access_token)
  const call = (path: string, method = 'GET', body?: unknown) =>
    authed(path, a.access_token, method, body)
  const next = async (n = 1) => {
    const end = Date.now() + 3000
    while (lb.events.length < n && Date.now() < end) await new Promise((r) => setTimeout(r, 10))
    return lb.events.splice(0, n)
  }
  const close = () => {
    la.ws.close(1000)
    lb.ws.close(1000)
  }
  return { call, next, close, own: la.events, other: lb.events }
}

const j = async (res: Response) => (await res.json()) as any

it('announces cipher, folder and settings changes to other devices only', async () => {
  const t = await twoDevices('ev-main@example.com')
  const created = await j(await t.call('/api/ciphers', 'POST', cipher()))
  const [create] = await t.next()
  expect(create).toMatchObject({ Type: 1, ContextId: 'dev-a', Payload: { Id: created.id } })

  await t.call(`/api/ciphers/${created.id}`, 'PUT', cipher('2.renamed'))
  expect((await t.next())[0]).toMatchObject({ Type: 0, Payload: { Id: created.id } })

  await t.call(`/api/ciphers/${created.id}/delete`, 'PUT')
  expect((await t.next())[0]).toMatchObject({ Type: 0 })
  await t.call(`/api/ciphers/${created.id}/restore`, 'PUT')
  expect((await t.next())[0]).toMatchObject({ Type: 0 })
  await t.call(`/api/ciphers/${created.id}`, 'DELETE')
  expect((await t.next())[0]).toMatchObject({ Type: 9, Payload: { Id: created.id } })

  const folder = await j(await t.call('/api/folders', 'POST', { name: '2.f' }))
  expect((await t.next())[0]).toMatchObject({ Type: 7, Payload: { Id: folder.id } })
  await t.call(`/api/folders/${folder.id}`, 'PUT', { name: '2.g' })
  expect((await t.next())[0]).toMatchObject({ Type: 8 })
  await t.call(`/api/folders/${folder.id}`, 'DELETE')
  expect((await t.next())[0]).toMatchObject({ Type: 3 })

  await t.call('/api/settings/domains', 'PUT', { equivalentDomains: [['a.example', 'b.example']] })
  expect((await t.next())[0]).toMatchObject({ Type: 10 })

  // The device that made the changes heard nothing.
  expect(t.own).toHaveLength(0)
  t.close()
})

it('announces moves, imports and purges', async () => {
  const t = await twoDevices('ev-bulk@example.com')
  const a = await j(await t.call('/api/ciphers', 'POST', cipher()))
  await t.next()
  await t.call('/api/ciphers/move', 'PUT', { ids: [a.id], folderId: null })
  expect((await t.next())[0]).toMatchObject({ Type: 0, Payload: { Id: a.id } })

  await t.call('/api/ciphers/import', 'POST', {
    folders: [{ name: '2.f' }],
    ciphers: [cipher()],
    folderRelationships: [{ key: 0, value: 0 }],
  })
  expect((await t.next())[0]).toMatchObject({ Type: 5 })

  await t.call('/api/ciphers/purge', 'POST', { masterPasswordHash: 'client-derived-hash' })
  expect((await t.next())[0]).toMatchObject({ Type: 5 })

  // Many ids collapse to one SyncCiphers event.
  const ids = []
  for (let i = 0; i < 12; i++)
    ids.push((await j(await t.call('/api/ciphers', 'POST', cipher()))).id)
  await t.next(12)
  await t.call('/api/ciphers/delete', 'PUT', { ids })
  expect(await t.next()).toEqual([expect.objectContaining({ Type: 4 })])
  t.close()
})

it('does not notify for failed writes', async () => {
  const t = await twoDevices('ev-fail@example.com')
  const res = await t.call('/api/ciphers/nope', 'PUT', cipher())
  expect(res.status).toBe(404)
  await new Promise((r) => setTimeout(r, 50))
  expect(t.other).toHaveLength(0)
  t.close()
})

it('announces Send create, update and delete', async () => {
  const t = await twoDevices('ev-send@example.com')
  const send = {
    type: 0,
    key: '2.key',
    name: '2.name',
    text: { text: '2.text', hidden: false },
    deletionDate: new Date(Date.now() + 86_400_000).toISOString(),
    disabled: false,
    hideEmail: false,
  }
  const created = await j(await t.call('/api/sends', 'POST', send))
  expect((await t.next())[0]).toMatchObject({ Type: 12, Payload: { Id: created.id } })
  await t.call(`/api/sends/${created.id}`, 'PUT', send)
  expect((await t.next())[0]).toMatchObject({ Type: 13, Payload: { Id: created.id } })
  await t.call(`/api/sends/${created.id}`, 'DELETE')
  expect((await t.next())[0]).toMatchObject({ Type: 14, Payload: { Id: created.id } })
  expect(t.own).toHaveLength(0)
  t.close()
})
