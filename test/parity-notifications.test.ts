// Notification centre, security tasks and Secrets Manager access requests (TASKS #231).
import { beforeAll, describe, expect, it } from 'vitest'
import { withEnv } from './helpers'
import { type Actor, actor, addMember, createOrg, loginCipher, mailbox } from './org-helpers'

const NIL = '00000000-0000-4000-8000-000000000000'
const mb = mailbox()

let admin: Actor
let owner: Actor
let member: Actor
let other: Actor
let orgId: string
let collectionId: string

/** Calls the instance admin API as `who`, with `who` listed as an instance admin. */
const asAdmin = (who: Actor, path: string, method = 'GET', body?: unknown) =>
  withEnv(
    { ADMIN_ENABLED: 'true', ADMIN_EMAILS: who.email, EMAIL: mb.EMAIL, MAIL_FROM: mb.MAIL_FROM },
    path,
    {
      method,
      headers: {
        Authorization: `Bearer ${who.token}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    },
  )

beforeAll(async () => {
  admin = await actor('pn-admin@example.com', mb)
  owner = await actor('pn-owner@example.com', mb)
  member = await actor('pn-member@example.com', mb)
  other = await actor('pn-other@example.com', mb)
  const org = await createOrg(owner, 'PN Org')
  orgId = org.id
  collectionId = org.defaultCollectionId
  await addMember(
    owner,
    orgId,
    member,
    { collections: [{ id: collectionId, readOnly: false, hidePasswords: false, manage: false }] },
    mb,
  )
})

describe('notification centre', () => {
  let personal: string
  let orgWide: string

  it('lets only instance admins create notifications', async () => {
    const body = { title: 'Hello', body: 'Welcome' }
    expect(
      (await asAdmin(admin, '/api/cloudwarden/admin/notifications', 'POST', body)).status,
    ).toBe(201)
    // Not an admin: the admin list names someone else.
    const denied = await withEnv(
      { ADMIN_ENABLED: 'true', ADMIN_EMAILS: admin.email },
      '/api/cloudwarden/admin/notifications',
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${member.token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      },
    )
    expect(denied.status).toBe(403)
    const res = await asAdmin(admin, '/api/cloudwarden/admin/notifications', 'POST', {
      title: 'Personal',
      body: 'Just for you',
      priority: 2,
      userId: member.uuid,
    })
    expect(res.status).toBe(201)
    const created = (await res.json()) as any
    expect(created).toMatchObject({ title: 'Personal', priority: 2, global: false, readDate: null })
    personal = created.id
    const org = (await (
      await asAdmin(admin, '/api/cloudwarden/admin/notifications', 'POST', {
        title: 'Org',
        body: 'For members',
        organizationId: orgId,
      })
    ).json()) as any
    orgWide = org.id
    expect(
      (
        await asAdmin(admin, '/api/cloudwarden/admin/notifications', 'POST', {
          ...body,
          userId: NIL,
        })
      ).status,
    ).toBe(404)
    expect(
      (await asAdmin(admin, '/api/cloudwarden/admin/notifications', 'POST', { title: '' })).status,
    ).toBe(400)
  })

  it('lists the notifications addressed to each user', async () => {
    const mine = await member.json('/api/notifications')
    expect(mine.object).toBe('list')
    const ids = mine.data.map((n: any) => n.id)
    expect(ids).toContain(personal)
    expect(ids).toContain(orgWide)
    expect(mine.data[0].id).toBe(personal) // highest priority first
    expect(mine.data.find((n: any) => n.title === 'Hello')).toMatchObject({ global: true })
    const theirs = (await other.json('/api/notifications')).data.map((n: any) => n.id)
    expect(theirs).not.toContain(personal)
    expect(theirs).not.toContain(orgWide)
    expect((await other.call(`/api/notifications/${personal}/read`, 'PATCH')).status).toBe(404)
  })

  it('pages with a continuation token', async () => {
    const first = await member.json('/api/notifications?pageSize=1')
    expect(first.data).toHaveLength(1)
    expect(first.continuationToken).toBeTruthy()
    const second = await member.json(
      `/api/notifications?pageSize=1&continuationToken=${first.continuationToken}`,
    )
    expect(second.data[0].id).not.toBe(first.data[0].id)
  })

  it('marks notifications read and deleted per user', async () => {
    expect((await member.call(`/api/notifications/${orgWide}/read`, 'PATCH')).status).toBe(200)
    const read = await member.json('/api/notifications?readStatusFilter=true')
    expect(read.data.map((n: any) => n.id)).toEqual([orgWide])
    expect(read.data[0].readDate).toBeTruthy()
    const unread = await member.json('/api/notifications?readStatusFilter=false')
    expect(unread.data.map((n: any) => n.id)).not.toContain(orgWide)
    // The owner's state is separate.
    const ownerView = (await owner.json('/api/notifications')).data.find(
      (n: any) => n.id === orgWide,
    )
    expect(ownerView.readDate).toBe(null)

    expect((await member.call(`/api/notifications/${personal}/delete`, 'DELETE')).status).toBe(200)
    expect((await member.call(`/api/notifications/${orgWide}/delete`, 'PATCH')).status).toBe(200)
    const live = (await member.json('/api/notifications')).data.map((n: any) => n.id)
    expect(live).not.toContain(personal)
    expect(live).not.toContain(orgWide)
    const deleted = await member.json('/api/notifications?deletedStatusFilter=true')
    expect(deleted.data.map((n: any) => n.id).sort()).toEqual([personal, orgWide].sort())
    expect((await member.call('/api/notifications/not-a-uuid/read', 'PATCH')).status).toBe(404)
  })

  it('requires authentication', async () => {
    expect((await withEnv({}, '/api/notifications', {})).status).toBe(401)
  })
})

describe('security tasks', () => {
  let cipherId: string
  let taskId: string

  beforeAll(async () => {
    const item = await owner.json('/api/ciphers/create', 'POST', {
      cipher: loginCipher('2.atrisk', { organizationId: orgId }),
      collectionIds: [collectionId],
    })
    cipherId = item.id
  })

  it('lets organisation admins create tasks', async () => {
    const body = { tasks: [{ type: 0, cipherId }] }
    expect((await member.call(`/api/tasks/${orgId}/bulk-create`, 'POST', body)).status).toBe(403)
    expect((await other.call(`/api/tasks/${orgId}/bulk-create`, 'POST', body)).status).toBe(404)
    expect(
      (
        await owner.call(`/api/tasks/${orgId}/bulk-create`, 'POST', {
          tasks: [{ type: 0, cipherId: NIL }],
        })
      ).status,
    ).toBe(400)
    const created = await owner.json(`/api/tasks/${orgId}/bulk-create`, 'POST', body)
    expect(created.data).toHaveLength(1)
    expect(created.data[0]).toMatchObject({ organizationId: orgId, cipherId, type: 0, status: 0 })
    taskId = created.data[0].id
  })

  it('shows tasks to members who can edit the item', async () => {
    const mine = await member.json('/api/tasks')
    expect(mine.data.map((t: any) => t.id)).toEqual([taskId])
    expect((await member.json('/api/tasks?status=1')).data).toEqual([])
    expect((await other.json('/api/tasks')).data).toEqual([])
    expect((await other.call(`/api/tasks/${taskId}/complete`, 'PATCH')).status).toBe(404)
    expect((await member.call('/api/tasks?status=7')).status).toBe(400)
  })

  it('completes tasks and reports organisation metrics', async () => {
    expect((await member.call(`/api/tasks/${taskId}/complete`, 'PATCH')).status).toBe(200)
    expect((await member.json('/api/tasks?status=1')).data.map((t: any) => t.id)).toEqual([taskId])
    const org = await owner.json(`/api/tasks/organization?organizationId=${orgId}&status=1`)
    expect(org.data.map((t: any) => t.id)).toEqual([taskId])
    expect((await member.call(`/api/tasks/organization?organizationId=${orgId}`)).status).toBe(403)
    expect(await owner.json(`/api/tasks/${orgId}/metrics`)).toMatchObject({
      completedTasks: 1,
      totalTasks: 1,
    })
  })
})

describe('Secrets Manager access requests', () => {
  it('emails the owners and admins', async () => {
    const before = mb.sent.length
    const res = await member.call('/api/request-access/request-sm-access', 'POST', {
      OrganizationId: orgId,
      EmailContent: 'Please let me in.',
    })
    expect(res.status).toBe(200)
    const sent = mb.sent.slice(before)
    expect(sent.map((m) => m.to)).toEqual([owner.email])
    expect(sent[0]?.text).toContain('Please let me in.')
    expect(sent[0]?.text).toContain(member.email)
  })

  it('refuses outsiders', async () => {
    const res = await other.call('/api/request-access/request-sm-access', 'POST', {
      organizationId: orgId,
      emailContent: 'Hi',
    })
    expect(res.status).toBe(404)
  })
})
