// Send event types 2500 to 2511: created, edited, deleted and accessed, text and file.
import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { authed, createSession, json } from './helpers'
import { actor, addMember, createOrg } from './org-helpers'

const day = 86_400_000
const textSend = (extra: Record<string, unknown> = {}) => ({
  type: 0,
  name: '2.sendname',
  notes: '2.notes',
  key: '2.sendkey',
  text: { text: '2.secret', hidden: false },
  deletionDate: new Date(Date.now() + day).toISOString(),
  disabled: false,
  ...extra,
})
const fileSend = (extra: Record<string, unknown> = {}) => ({
  type: 1,
  name: '2.file',
  key: '2.sendkey',
  file: { fileName: '2.f.txt' },
  fileLength: 4,
  deletionDate: new Date(Date.now() + day).toISOString(),
  disabled: false,
  ...extra,
})

/** Event rows about a Send, oldest first. */
async function rowsOf(sendId: string) {
  const res = await env.DB.prepare(
    'select event_type t, user_uuid u, acting_user_uuid a, organization_uuid o from events where send_uuid = ? order by event_date, rowid',
  )
    .bind(sendId)
    .all<{ t: number; u: string | null; a: string | null; o: string | null }>()
  return res.results
}

const mk = async (token: string, path: string, body: unknown) => {
  const res = await authed(path, token, 'POST', body)
  expect(res.status).toBe(200)
  return (await res.json()) as any
}

it('records create, edit, access and delete of a text Send', async () => {
  const s = await createSession('se-text@example.com')
  const me = (await (await authed('/api/accounts/profile', s.access_token)).json()) as {
    id: string
  }
  const made = await mk(s.access_token, '/api/sends', textSend())
  expect((await authed(`/api/sends/${made.id}`, s.access_token, 'PUT', textSend())).status).toBe(
    200,
  )
  // A recipient opens it: nobody is signed in, so there is no acting user.
  expect((await json(`/api/sends/access/${made.accessId}`, {})).status).toBe(200)
  expect((await authed(`/api/sends/${made.id}`, s.access_token, 'DELETE')).status).toBe(200)

  const rows = await rowsOf(made.id)
  expect(rows.map((r) => r.t)).toEqual([2500, 2506, 2510, 2508])
  expect(rows.map((r) => r.a)).toEqual([me.id, me.id, null, me.id])
  expect(rows.every((r) => r.u === me.id && r.o === null)).toBe(true)
  // The owner reads them in their own feed, with the Send id.
  const feed = (await (await authed('/api/events', s.access_token)).json()) as any
  expect(
    feed.data
      .filter((e: any) => e.sendId === made.id)
      .map((e: any) => e.type)
      .sort(),
  ).toEqual([2500, 2506, 2508, 2510])
})

it('names the protection in the created event', async () => {
  const s = await createSession('se-auth@example.com')
  const plain = await mk(s.access_token, '/api/sends', textSend())
  const pw = await mk(s.access_token, '/api/sends', textSend({ password: 'hunter2' }))
  const file = await mk(s.access_token, '/api/sends/file/v2', fileSend())
  const filePw = await mk(s.access_token, '/api/sends/file/v2', fileSend({ password: 'hunter2' }))
  expect((await rowsOf(plain.id)).map((r) => r.t)).toEqual([2500])
  expect((await rowsOf(pw.id)).map((r) => r.t)).toEqual([2502])
  expect((await rowsOf(file.sendResponse.id)).map((r) => r.t)).toEqual([2503])
  expect((await rowsOf(filePw.sendResponse.id)).map((r) => r.t)).toEqual([2505])
  // Dropping the password is an edit.
  expect((await authed(`/api/sends/${pw.id}/remove-password`, s.access_token, 'PUT')).status).toBe(
    200,
  )
  expect((await rowsOf(pw.id)).map((r) => r.t)).toEqual([2502, 2506])
  expect(
    (await authed(`/api/sends/${file.sendResponse.id}`, s.access_token, 'DELETE')).status,
  ).toBe(200)
  expect((await rowsOf(file.sendResponse.id)).map((r) => r.t)).toEqual([2503, 2509])
})

it('copies Send events to the organisation log and reads them by Send', async () => {
  const owner = await actor('se-org-owner@example.com')
  const member = await actor('se-org-member@example.com')
  const { id: orgId } = await createOrg(owner)
  const ouId = await addMember(owner, orgId, member)
  const made = await member.json('/api/sends', 'POST', textSend())
  const other = await member.json('/api/sends', 'POST', textSend())

  const log = await owner.json(`/api/organizations/${orgId}/sends/${made.id}/events`)
  expect(log.data).toHaveLength(1)
  expect(log.data[0]).toMatchObject({
    type: 2500,
    sendId: made.id,
    userId: member.uuid,
    actingUserId: member.uuid,
    organizationId: orgId,
    organizationUserId: ouId,
  })
  expect(log.data.some((e: any) => e.sendId === other.id)).toBe(false)
  // The member's own feed lists the event once.
  const own = await member.json('/api/events')
  expect(own.data.filter((e: any) => e.sendId === made.id)).toHaveLength(1)
  // Only members who read event logs may see it.
  expect((await member.call(`/api/organizations/${orgId}/sends/${made.id}/events`)).status).toBe(
    403,
  )
})
