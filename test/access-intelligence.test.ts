import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { expect, it, vi } from 'vitest'
import { purgeExpired } from '../src/vault/purge'
import { BASE } from './helpers'
import { type Actor, actor, addMember, createOrg, loginCipher } from './org-helpers'

// Each test registers accounts and organisations, which can stall for minutes on a loaded host.
vi.setConfig({ testTimeout: 900_000 })

const R = '/api/reports'
const metrics = {
  totalApplicationCount: 5,
  totalAtRiskApplicationCount: 2,
  totalCriticalApplicationCount: 1,
  totalCriticalAtRiskApplicationCount: 1,
  totalMemberCount: 7,
  totalAtRiskMemberCount: 3,
  totalCriticalMemberCount: 2,
  totalCriticalAtRiskMemberCount: 1,
  totalPasswordCount: 40,
  totalAtRiskPasswordCount: 9,
  totalCriticalPasswordCount: 4,
  totalCriticalAtRiskPasswordCount: 2,
}
const UNKNOWN = '00000000-0000-4000-8000-000000000000'

/** Accounts are registered once: each one costs a password hash, and tests make many organisations. */
let accounts:
  | Promise<Record<'owner' | 'admin' | 'custom' | 'plain' | 'outsider', Actor>>
  | undefined
const people = () =>
  (accounts ??= (async () => ({
    owner: await actor('ai-owner@example.com'),
    admin: await actor('ai-admin@example.com'),
    custom: await actor('ai-custom@example.com'),
    plain: await actor('ai-plain@example.com'),
    outsider: await actor('ai-outsider@example.com'),
  }))())

/** A new organisation with an owner, an admin, a custom member with access to reports, and others. */
async function setup(_tag: string) {
  const { owner, admin, custom, plain, outsider } = await people()
  const org = await createOrg(owner)
  // createOrg reads the first collection of the owner's sync, which is another organisation's
  // once the owner has several.
  const collections = (await owner.json(`/api/organizations/${org.id}/collections`)) as {
    data: { id: string }[]
  }
  org.defaultCollectionId = collections.data[0]?.id as string
  await addMember(owner, org.id, admin, { type: 1 })
  await addMember(owner, org.id, custom, { type: 4, permissions: { accessReports: true } })
  await addMember(owner, org.id, plain, { type: 4, permissions: { accessEventLogs: true } })
  return {
    owner,
    admin,
    custom,
    plain,
    outsider,
    orgId: org.id,
    defaultCollectionId: org.defaultCollectionId,
  }
}

const digest = async (data: ArrayBuffer | Uint8Array) =>
  Buffer.from(await crypto.subtle.digest('SHA-256', data)).toString('hex')

const upload = (url: string, token: string, bytes: Uint8Array) => {
  const fd = new FormData()
  fd.append('data', new Blob([bytes]), 'report.bin')
  return SELF.fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: fd,
  })
}

const addV1 = (who: Actor, orgId: string, extra: Record<string, unknown> = {}) =>
  who.call(`${R}/organizations/${orgId}`, 'POST', {
    reportData: '2.reportdata',
    contentEncryptionKey: '2.reportkey',
    summaryData: '2.summary',
    applicationData: '2.apps',
    metrics,
    ...extra,
  })

it('answers 404 to members without the reports permission and to outsiders', async () => {
  const t = await setup('auth')
  for (const who of [t.plain, t.outsider]) {
    for (const [path, method, body] of [
      [`${R}/member-access/${t.orgId}`, 'GET'],
      [`${R}/member-cipher-details/${t.orgId}`, 'GET'],
      [`${R}/password-health-report-applications/${t.orgId}`, 'GET'],
      [`${R}/organizations/${t.orgId}/latest`, 'GET'],
      [`${R}/organizations/${t.orgId}`, 'POST', { reportData: 'x' }],
      [`${R}/organizations/${t.orgId}/data/summary`, 'GET'],
    ] as [string, string, unknown?][]) {
      expect((await who.call(path, method, body)).status, `${method} ${path}`).toBe(404)
    }
  }
  // Owners, admins and custom members with the permission pass.
  for (const who of [t.owner, t.admin, t.custom]) {
    expect((await who.call(`${R}/member-access/${t.orgId}`)).status).toBe(200)
  }
  expect((await SELF.fetch(`${BASE}${R}/member-access/${t.orgId}`)).status).toBe(401)
  expect((await t.owner.call(`${R}/member-access/not-a-uuid`)).status).toBe(404)
})

it('reports member access from real grants', async () => {
  const t = await setup('access')
  const member = await actor('ai-access-member@example.com')
  const group = await t.owner.json(`/api/organizations/${t.orgId}/groups`, 'POST', {
    name: 'Team',
    accessAll: false,
    collections: [
      { id: t.defaultCollectionId, readOnly: true, hidePasswords: true, manage: false },
    ],
    users: [],
  })
  const memberId = await addMember(t.owner, t.orgId, member, { type: 2, groups: [group.id] })
  const item = await t.owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.item', { organizationId: t.orgId }),
    collectionIds: [t.defaultCollectionId],
  })
  expect(memberId).toBeTruthy()

  const rows = (await t.custom.json(`${R}/member-access/${t.orgId}`)) as any[]
  const mine = rows.filter((r) => r.email === member.email)
  expect(mine).toHaveLength(1)
  expect(mine[0]).toMatchObject({
    userGuid: member.uuid,
    twoFactorEnabled: false,
    accountRecoveryEnabled: false,
    usesKeyConnector: false,
    collectionId: t.defaultCollectionId,
    groupId: group.id,
    groupName: 'Team',
    collectionName: '2.defaultCollection',
    readOnly: true,
    hidePasswords: true,
    manage: false,
    cipherIds: [item.id],
  })
  // A member without any grant still appears once, with no collection.
  const none = rows.filter((r) => r.email === t.plain.email)
  expect(none).toHaveLength(1)
  expect(none[0]).toMatchObject({ collectionId: null, cipherIds: [] })

  const details = (await t.owner.json(`${R}/member-cipher-details/${t.orgId}`)) as any[]
  const forMember = details.find((r) => r.email === member.email)
  expect(forMember).toMatchObject({
    userGuid: member.uuid,
    userName: expect.any(String),
    usesKeyConnector: false,
    cipherIds: [item.id],
  })
  expect(details.find((r) => r.email === t.plain.email).cipherIds).toEqual([])
})

it('gives access-all members every collection and item, and counts two-factor and recovery', async () => {
  const t = await setup('all')
  const item = await t.owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.item', { organizationId: t.orgId }),
    collectionIds: [t.defaultCollectionId],
  })
  const stray = await t.owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.stray', { organizationId: t.orgId }),
    collectionIds: [t.defaultCollectionId],
  })
  expect(stray.id).not.toBe(item.id)
  const rows = (await t.owner.json(`${R}/member-access/${t.orgId}`)) as any[]
  const owner = rows.filter((r) => r.email === t.owner.email)
  expect(owner.length).toBeGreaterThan(0)
  const details = (await t.owner.json(`${R}/member-cipher-details/${t.orgId}`)) as any[]
  const ownerItems = details.find((r) => r.email === t.owner.email)?.cipherIds as string[]
  expect(ownerItems).toEqual(expect.arrayContaining([item.id, stray.id]))

  await env.DB.prepare(
    "insert into twofactor (uuid, user_uuid, atype, enabled, data, last_used) values ('tf1', ?, 0, 1, '{}', 0)",
  )
    .bind(t.owner.uuid)
    .run()
  const again = (await t.owner.json(`${R}/member-access/${t.orgId}`)) as any[]
  expect(again.find((r) => r.email === t.owner.email).twoFactorEnabled).toBe(true)
  expect(again.find((r) => r.email === t.admin.email).twoFactorEnabled).toBe(false)
})

it('keeps critical applications: add, list and drop', async () => {
  const t = await setup('apps')
  const added = (await (
    await t.custom.call(`${R}/password-health-report-applications`, 'POST', [
      { organizationId: t.orgId, url: 'example.com' },
      { organizationId: t.orgId, url: 'example.org' },
    ])
  ).json()) as any[]
  expect(added).toHaveLength(2)
  expect(added[0]).toMatchObject({ organizationId: t.orgId, uri: 'example.com' })
  expect(added[0].id).toBeTruthy()
  expect(added[0].creationDate).toBeTruthy()
  expect(added[0].revisionDate).toBeTruthy()

  const listed = (await t.admin.json(
    `${R}/password-health-report-applications/${t.orgId}`,
  )) as any[]
  expect(listed.map((a) => a.uri)).toEqual(['example.com', 'example.org'])

  // Members without the permission cannot add (the whole request is refused).
  expect(
    (
      await t.plain.call(`${R}/password-health-report-applications`, 'POST', [
        { organizationId: t.orgId, url: 'example.net' },
      ])
    ).status,
  ).toBe(404)
  expect(
    (
      await t.plain.call(`${R}/password-health-report-application`, 'DELETE', {
        organizationId: t.orgId,
        passwordHealthReportApplicationIds: [added[0].id],
      })
    ).status,
  ).toBe(404)

  const drop = await t.custom.call(`${R}/password-health-report-application`, 'DELETE', {
    organizationId: t.orgId,
    passwordHealthReportApplicationIds: [added[0].id, UNKNOWN],
  })
  expect(drop.status).toBe(200)
  const left = (await t.owner.json(`${R}/password-health-report-applications/${t.orgId}`)) as any[]
  expect(left.map((a) => a.uri)).toEqual(['example.org'])

  // Another organisation's applications are untouched by an id from this one.
  const other = await setup('apps2')
  const otherAdded = (await (
    await other.owner.call(`${R}/password-health-report-applications`, 'POST', [
      { organizationId: other.orgId, url: 'example.io' },
    ])
  ).json()) as any[]
  await t.owner.call(`${R}/password-health-report-application`, 'DELETE', {
    organizationId: t.orgId,
    passwordHealthReportApplicationIds: [otherAdded[0].id],
  })
  expect(
    (await other.owner.json(`${R}/password-health-report-applications/${other.orgId}`)) as any[],
  ).toHaveLength(1)

  // Dropping from an organisation with none is a 400, as in the official server.
  await t.owner.call(`${R}/password-health-report-application`, 'DELETE', {
    organizationId: t.orgId,
    passwordHealthReportApplicationIds: [left[0].id],
  })
  const empty = await t.owner.call(`${R}/password-health-report-application`, 'DELETE', {
    organizationId: t.orgId,
    passwordHealthReportApplicationIds: [left[0].id],
  })
  expect(empty.status).toBe(400)
})

it('creates, reads, updates and deletes an inline report', async () => {
  const t = await setup('inline')
  const none = await t.owner.call(`${R}/organizations/${t.orgId}/latest`)
  expect(none.status).toBe(404)

  const res = await addV1(t.custom, t.orgId)
  expect(res.status).toBe(200)
  const created = (await res.json()) as any
  expect(created).toMatchObject({
    organizationId: t.orgId,
    reportData: '2.reportdata',
    contentEncryptionKey: '2.reportkey',
    summaryData: '2.summary',
    applicationData: '2.apps',
    reportFile: null,
    reportFileDownloadUrl: null,
    fileUploadType: null,
  })
  expect(created.creationDate).toBeTruthy()

  const get = (await t.admin.json(`${R}/organizations/${t.orgId}/${created.id}`)) as any
  expect(get).toMatchObject({ id: created.id, reportData: '2.reportdata' })
  const latest = (await t.owner.json(`${R}/organizations/${t.orgId}/latest`)) as any
  expect(latest.id).toBe(created.id)

  // A second report becomes the latest.
  const second = (await (await addV1(t.owner, t.orgId, { reportData: '2.second' })).json()) as any
  expect(((await t.owner.json(`${R}/organizations/${t.orgId}/latest`)) as any).id).toBe(second.id)

  // Full update (PATCH): metrics are required, strings replace the stored ones.
  const bad = await t.owner.call(`${R}/organizations/${t.orgId}/${created.id}`, 'PATCH', {
    summaryData: '2.s',
  })
  expect(bad.status).toBe(400)
  const patched = await t.owner.call(`${R}/organizations/${t.orgId}/${created.id}`, 'PATCH', {
    contentEncryptionKey: '2.newkey',
    summaryData: '2.newsummary',
    applicationData: '2.newapps',
    reportMetrics: metrics,
  })
  expect(patched.status).toBe(200)
  expect(await patched.json()).toMatchObject({
    id: created.id,
    contentEncryptionKey: '2.newkey',
    summaryData: '2.newsummary',
    applicationData: '2.newapps',
  })

  expect((await t.plain.call(`${R}/organizations/${t.orgId}/${created.id}`)).status).toBe(404)
  // A report of another organisation is not reachable through this one.
  const other = await setup('inline2')
  expect((await other.owner.call(`${R}/organizations/${other.orgId}/${created.id}`)).status).toBe(
    404,
  )
  expect((await t.owner.call(`${R}/organizations/${t.orgId}/${UNKNOWN}`)).status).toBe(404)

  const del = await t.owner.call(`${R}/organizations/${t.orgId}/${created.id}`, 'DELETE')
  expect(del.status).toBe(200)
  expect((await t.owner.call(`${R}/organizations/${t.orgId}/${created.id}`)).status).toBe(404)
  expect(await env.ATTACHMENTS.head(`org-reports/${t.orgId}/${created.id}/data`)).toBeNull()
})

it('reads and patches summary data, and lists summaries by date range', async () => {
  const t = await setup('summary')
  const a = (await (await addV1(t.owner, t.orgId, { summaryData: '2.a' })).json()) as any
  const b = (await (await addV1(t.owner, t.orgId, { summaryData: '2.b' })).json()) as any

  const one = (await t.custom.json(`${R}/organizations/${t.orgId}/data/summary/${a.id}`)) as any
  expect(one).toMatchObject({
    organizationId: t.orgId,
    encryptedData: '2.a',
    encryptionKey: '2.reportkey',
  })
  expect(Date.parse(one.date)).not.toBeNaN()

  const patched = await t.owner.call(
    `${R}/organizations/${t.orgId}/data/summary/${a.id}`,
    'PATCH',
    { summaryData: '2.a2', metrics },
  )
  expect(patched.status).toBe(200)
  expect(await patched.json()).toMatchObject({ id: a.id, summaryData: '2.a2' })
  expect(
    ((await t.owner.json(`${R}/organizations/${t.orgId}/data/summary/${a.id}`)) as any)
      .encryptedData,
  ).toBe('2.a2')

  const start = new Date(Date.now() - 3600_000).toISOString()
  const end = new Date(Date.now() + 3600_000).toISOString()
  const range = (await t.owner.json(
    `${R}/organizations/${t.orgId}/data/summary?startDate=${encodeURIComponent(start)}&endDate=${encodeURIComponent(end)}`,
  )) as any[]
  expect(range.map((r) => r.encryptedData)).toEqual(['2.a2', '2.b'])
  expect(range[0]).toMatchObject({ organizationId: t.orgId, encryptionKey: '2.reportkey' })

  const past = (await t.owner.json(
    `${R}/organizations/${t.orgId}/data/summary?startDate=2000-01-01T00:00:00Z&endDate=2000-02-01T00:00:00Z`,
  )) as any[]
  expect(past).toEqual([])
  expect(
    (await t.owner.call(`${R}/organizations/${t.orgId}/data/summary?startDate=nonsense`)).status,
  ).toBe(400)
  expect(b.id).not.toBe(a.id)
  expect((await t.plain.call(`${R}/organizations/${t.orgId}/data/summary/${a.id}`)).status).toBe(
    404,
  )
  expect((await t.owner.call(`${R}/organizations/${t.orgId}/data/summary/${UNKNOWN}`)).status).toBe(
    404,
  )
})

it('reads and patches application data', async () => {
  const t = await setup('appdata')
  const rep = (await (await addV1(t.owner, t.orgId)).json()) as any
  expect(await t.custom.json(`${R}/organizations/${t.orgId}/data/application/${rep.id}`)).toEqual({
    applicationData: '2.apps',
  })
  const patched = await t.custom.call(
    `${R}/organizations/${t.orgId}/data/application/${rep.id}`,
    'PATCH',
    { applicationData: '2.apps2' },
  )
  expect(patched.status).toBe(200)
  expect(await patched.json()).toMatchObject({ id: rep.id, applicationData: '2.apps2' })
  expect(await t.owner.json(`${R}/organizations/${t.orgId}/data/application/${rep.id}`)).toEqual({
    applicationData: '2.apps2',
  })
  expect(
    (await t.plain.call(`${R}/organizations/${t.orgId}/data/application/${rep.id}`)).status,
  ).toBe(404)
  expect(
    (await t.owner.call(`${R}/organizations/${t.orgId}/data/application/${UNKNOWN}`)).status,
  ).toBe(404)
})

const reserve = async (who: Actor, orgId: string, size: number) => {
  const res = await who.call(`${R}/organizations/${orgId}`, 'POST', {
    contentEncryptionKey: '2.reportkey',
    summaryData: '2.summary',
    applicationData: '2.apps',
    metrics,
    fileSize: size,
  })
  return { status: res.status, body: (await res.json()) as any }
}

it('uploads a report file, serves it back and renews an upload slot', async () => {
  const t = await setup('file')
  const bytes = new Uint8Array(300_000).map((_, i) => i % 251)
  const { status, body } = await reserve(t.custom, t.orgId, bytes.length)
  expect(status).toBe(200)
  expect(body.fileUploadType).toBe(0)
  const report = body.reportResponse
  expect(report.reportFile).toMatchObject({ size: 300_000, validated: false })
  expect(report.reportFileDownloadUrl).toBeNull()
  expect(body.reportFileUploadUrl).toBe(
    `${BASE}${R}/organizations/${t.orgId}/${report.id}/file?reportFileId=${report.reportFile.id}`,
  )

  // Not downloadable and not "latest" before the upload finishes.
  expect(
    (await t.owner.call(`${R}/organizations/${t.orgId}/${report.id}/file/download`)).status,
  ).toBe(404)
  expect((await t.owner.call(`${R}/organizations/${t.orgId}/latest`)).status).toBe(404)

  // Renew answers the same slot while the file is missing.
  const renewed = (await t.custom.json(
    `${R}/organizations/${t.orgId}/${report.id}/file/renew?reportFileId=${report.reportFile.id}`,
  )) as any
  expect(renewed.reportFileUploadUrl).toBe(body.reportFileUploadUrl)
  expect(
    (await t.custom.call(`${R}/organizations/${t.orgId}/${report.id}/file/renew`)).status,
  ).toBe(400)
  expect(
    (
      await t.custom.call(
        `${R}/organizations/${t.orgId}/${report.id}/file/renew?reportFileId=other`,
      )
    ).status,
  ).toBe(404)

  // Other members cannot upload; the owner of the slot can.
  expect((await upload(body.reportFileUploadUrl, t.plain.token, bytes)).status).toBe(404)
  expect((await upload(body.reportFileUploadUrl, t.custom.token, bytes)).status).toBe(200)
  // A second upload and a renew of a finished file are refused.
  expect((await upload(body.reportFileUploadUrl, t.custom.token, bytes)).status).toBe(404)
  expect(
    (
      await t.custom.call(
        `${R}/organizations/${t.orgId}/${report.id}/file/renew?reportFileId=${report.reportFile.id}`,
      )
    ).status,
  ).toBe(404)

  const get = (await t.owner.json(`${R}/organizations/${t.orgId}/${report.id}`)) as any
  expect(get.reportFile).toMatchObject({ validated: true, size: 300_000 })
  expect(get.reportFileDownloadUrl).toBe(
    `${BASE}${R}/organizations/${t.orgId}/${report.id}/file/download`,
  )
  expect(get.fileUploadType).toBe(0)
  const latest = (await t.owner.json(`${R}/organizations/${t.orgId}/latest`)) as any
  expect(latest.id).toBe(report.id)

  const dl = await t.admin.call(`${R}/organizations/${t.orgId}/${report.id}/file/download`)
  expect(dl.status).toBe(200)
  expect(new Uint8Array(await dl.arrayBuffer())).toEqual(bytes)
  expect(
    (await t.plain.call(`${R}/organizations/${t.orgId}/${report.id}/file/download`)).status,
  ).toBe(404)

  // Deleting the report removes its blob.
  const key = `org-reports/${t.orgId}/${report.id}/${report.reportFile.id}`
  expect(await env.ATTACHMENTS.head(key)).not.toBeNull()
  expect((await t.owner.call(`${R}/organizations/${t.orgId}/${report.id}`, 'DELETE')).status).toBe(
    200,
  )
  await new Promise((r) => setTimeout(r, 50))
  expect(await env.ATTACHMENTS.head(key)).toBeNull()
})

it('accepts a file within the size leeway and spans several parts', async () => {
  const t = await setup('big')
  // 9 MiB crosses the 8 MiB part size; the declared size is 100 KiB off, inside the 1 MiB leeway.
  const bytes = new Uint8Array(9 * 1024 * 1024).map((_, i) => (i * 7) % 253)
  const { body } = await reserve(t.owner, t.orgId, bytes.length - 100 * 1024)
  expect((await upload(body.reportFileUploadUrl, t.owner.token, bytes)).status).toBe(200)
  const dl = await t.owner.call(
    `${R}/organizations/${t.orgId}/${body.reportResponse.id}/file/download`,
  )
  // Digests: comparing 9 million elements one by one exhausts the test worker's memory.
  expect(await digest(await dl.arrayBuffer())).toBe(await digest(bytes))
  const get = (await t.owner.json(`${R}/organizations/${t.orgId}/${body.reportResponse.id}`)) as any
  expect(get.reportFile.size).toBe(bytes.length)
})

it('drops the report when the uploaded file does not match its declared size', async () => {
  const t = await setup('mismatch')
  const { body } = await reserve(t.owner, t.orgId, 5 * 1024 * 1024)
  const res = await upload(body.reportFileUploadUrl, t.owner.token, new Uint8Array(100))
  expect(res.status).toBe(400)
  expect(
    (await t.owner.call(`${R}/organizations/${t.orgId}/${body.reportResponse.id}`)).status,
  ).toBe(404)
  const key = `org-reports/${t.orgId}/${body.reportResponse.id}/${body.reportResponse.reportFile.id}`
  expect(await env.ATTACHMENTS.head(key)).toBeNull()
})

it('refuses an oversized or invalid file request and caps unfinished uploads', async () => {
  const t = await setup('limits')
  expect((await reserve(t.owner, t.orgId, 101 * 1024 * 1024)).status).toBe(413)
  expect((await reserve(t.owner, t.orgId, 0)).status).toBe(400)
  for (let i = 0; i < 10; i++) expect((await reserve(t.owner, t.orgId, 10)).status).toBe(200)
  expect((await reserve(t.owner, t.orgId, 10)).status).toBe(400)
})

it('purges unfinished report uploads and erases report blobs with the organisation', async () => {
  const t = await setup('purge')
  const { body } = await reserve(t.owner, t.orgId, 10)
  const id = body.reportResponse.id as string
  const done = (await (await addV1(t.owner, t.orgId)).json()) as any
  expect(done.id).toBeTruthy()
  const result = await purgeExpired(env, Date.now() + 2 * 24 * 3600_000)
  expect(result.reports).toBeGreaterThanOrEqual(1)
  expect((await t.owner.call(`${R}/organizations/${t.orgId}/${id}`)).status).toBe(404)
  // The inline report has no file and is kept.
  expect((await t.owner.call(`${R}/organizations/${t.orgId}/${done.id}`)).status).toBe(200)

  const key = `org-reports/${t.orgId}/${done.id}/data`
  expect(await env.ATTACHMENTS.head(key)).not.toBeNull()
  const erased = await t.owner.call(`/api/organizations/${t.orgId}`, 'DELETE', {
    masterPasswordHash: 'client-derived-hash',
  })
  expect(erased.status).toBe(200)
  await new Promise((r) => setTimeout(r, 50))
  expect(await env.ATTACHMENTS.head(key)).toBeNull()
})

it('answers the Azure Event Grid handshake and refuses other events', async () => {
  const handshake = await SELF.fetch(`${BASE}${R}/organizations/file/validate/azure`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify([
      {
        eventType: 'Microsoft.EventGrid.SubscriptionValidationEvent',
        data: { validationCode: 'abc' },
      },
    ]),
  })
  expect(handshake.status).toBe(200)
  expect(await handshake.json()).toEqual({ validationResponse: 'abc' })
  const other = await SELF.fetch(`${BASE}${R}/organizations/file/validate/azure`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify([{ eventType: 'Microsoft.Storage.BlobCreated' }]),
  })
  expect(other.status).toBe(400)
})
