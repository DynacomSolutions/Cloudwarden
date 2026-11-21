import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { expect, it, vi } from 'vitest'
import { MAX_REPORT_FILE_BYTES, MAX_REPORTS_PER_ORG } from '../src/routes/access-intelligence'
import { purgeExpired } from '../src/vault/purge'
import { BASE } from './helpers'
import {
  type Actor,
  actor,
  addMember,
  createOrg,
  linkParams,
  loginCipher,
  mail,
} from './org-helpers'

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

const blobKeyOf = async (reportId: string) =>
  (
    (await env.DB.prepare('select blob_key from organization_reports where uuid = ?')
      .bind(reportId)
      .first()) as { blob_key: string }
  ).blob_key

const rowOf = async (reportId: string) =>
  (await env.DB.prepare('select * from organization_reports where uuid = ?')
    .bind(reportId)
    .first()) as Record<string, unknown> | null

/** Waits until the server has claimed the upload slot, so a hook never runs before the handler. */
const claimed = async (reportId: string) => {
  for (let i = 0; i < 600; i++) {
    if ((await rowOf(reportId))?.upload_started_at != null) return
    await new Promise((r) => setTimeout(r, 50))
  }
  throw new Error('the upload was never claimed')
}

const objectsOf = async (orgId: string, reportId: string) =>
  (await env.ATTACHMENTS.list({ prefix: `org-reports/${orgId}/${reportId}/` })).objects

/**
 * Uploads `bytes` as a multipart body in two halves. `between` runs after the first half is sent
 * and before the second; it may throw to make the body stream fail partway.
 */
const uploadInHalves = (
  url: string,
  token: string,
  bytes: Uint8Array,
  between: () => Promise<void> | void,
) => {
  const enc = new TextEncoder()
  const head = enc.encode(
    '--xyz\r\nContent-Disposition: form-data; name="data"; filename="r.bin"\r\nContent-Type: application/octet-stream\r\n\r\n',
  )
  const tail = enc.encode('\r\n--xyz--\r\n')
  const half = Math.floor(bytes.length / 2)
  let step = 0
  const body = new ReadableStream<Uint8Array>({
    async pull(ctrl) {
      if (step === 0) {
        step = 1
        ctrl.enqueue(head)
        ctrl.enqueue(bytes.subarray(0, half))
        return
      }
      try {
        await between()
      } catch (e) {
        return ctrl.error(e)
      }
      ctrl.enqueue(bytes.subarray(half))
      ctrl.enqueue(tail)
      ctrl.close()
    },
  })
  return SELF.fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'multipart/form-data; boundary=xyz',
    },
    body,
    duplex: 'half',
  } as RequestInit)
}

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
  const key = await blobKeyOf(report.id)
  expect(key).toContain(`org-reports/${t.orgId}/${report.id}/${report.reportFile.id}`)
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
  expect(await objectsOf(t.orgId, body.reportResponse.id)).toEqual([])
})

it('refuses an oversized or invalid file request and caps unfinished uploads', async () => {
  const t = await setup('limits')
  expect((await reserve(t.owner, t.orgId, 101 * 1024 * 1024)).status).toBe(413)
  // The whole multipart request must fit the 100 MB Worker body cap, so 100 MB itself is refused.
  expect((await reserve(t.owner, t.orgId, 100 * 1024 * 1024)).status).toBe(413)
  expect((await reserve(t.owner, t.orgId, MAX_REPORT_FILE_BYTES + 1)).status).toBe(413)
  expect((await reserve(t.owner, t.orgId, MAX_REPORT_FILE_BYTES)).status).toBe(200)
  expect((await reserve(t.owner, t.orgId, 0)).status).toBe(400)
  for (let i = 0; i < 9; i++) expect((await reserve(t.owner, t.orgId, 10)).status).toBe(200)
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

it('drops many critical applications at once, beyond the 100 parameter limit of D1', async () => {
  const t = await setup('manyapps')
  const added = (await (
    await t.owner.call(
      `${R}/password-health-report-applications`,
      'POST',
      Array.from({ length: 160 }, (_, i) => ({
        organizationId: t.orgId,
        url: `app${i}.example.com`,
      })),
    )
  ).json()) as { id: string }[]
  expect(added).toHaveLength(160)
  const ids = added.slice(0, 150).map((a) => a.id)
  const drop = await t.owner.call(`${R}/password-health-report-application`, 'DELETE', {
    organizationId: t.orgId,
    passwordHealthReportApplicationIds: [...ids, ids[0]],
  })
  expect(drop.status).toBe(200)
  const left = (await t.owner.json(`${R}/password-health-report-applications/${t.orgId}`)) as {
    uri: string
  }[]
  expect(left.map((a) => a.uri)).toEqual(
    Array.from({ length: 10 }, (_, i) => `app${i + 150}.example.com`),
  )
})

it('keeps the report slot when the upload stream fails, so the client can renew and retry', async () => {
  const t = await setup('streamfail')
  const bytes = new Uint8Array(300_000).map((_, i) => i % 241)
  const { body } = await reserve(t.owner, t.orgId, bytes.length)
  const id = body.reportResponse.id as string
  const failed = await uploadInHalves(body.reportFileUploadUrl, t.owner.token, bytes, async () => {
    await claimed(id)
    throw new Error('connection lost')
  }).catch(() => null)
  expect(failed?.status ?? 400).not.toBe(200)
  // The report is still there with its claim released and no object left behind.
  const row = await rowOf(id)
  expect(row).not.toBeNull()
  expect(row?.upload_started_at).toBeNull()
  expect(row?.file_validated).toBe(0)
  expect(await objectsOf(t.orgId, id)).toEqual([])
  const renew = await t.owner.call(
    `${R}/organizations/${t.orgId}/${id}/file/renew?reportFileId=${body.reportResponse.reportFile.id}`,
  )
  expect(renew.status).toBe(200)
  // The retry works.
  expect((await upload(body.reportFileUploadUrl, t.owner.token, bytes)).status).toBe(200)
  expect(
    ((await t.owner.json(`${R}/organizations/${t.orgId}/${id}`)) as any).reportFile.validated,
  ).toBe(true)
})

it('answers 409 and keeps only the winner blob when the claim was taken over', async () => {
  const t = await setup('takeover')
  const bytes = new Uint8Array(300_000).map((_, i) => i % 239)
  const { body } = await reserve(t.owner, t.orgId, bytes.length)
  const id = body.reportResponse.id as string
  const res = await uploadInHalves(body.reportFileUploadUrl, t.owner.token, bytes, async () => {
    // Another upload takes the claim over while this one still streams.
    await claimed(id)
    await env.DB.prepare('update organization_reports set upload_started_at = ? where uuid = ?')
      .bind(Date.now() + 5, id)
      .run()
  })
  expect(res.status).toBe(409)
  const row = await rowOf(id)
  expect(row?.file_validated).toBe(0)
  expect(row?.upload_started_at).not.toBeNull()
  // The losing upload removed its own object and nothing else.
  await new Promise((r) => setTimeout(r, 50))
  expect(await objectsOf(t.orgId, id)).toEqual([])

  // A report deleted during its upload leaves no object either.
  const second = await reserve(t.owner, t.orgId, bytes.length)
  const id2 = second.body.reportResponse.id as string
  const gone = await uploadInHalves(
    second.body.reportFileUploadUrl,
    t.owner.token,
    bytes,
    async () => {
      await claimed(id2)
      await env.DB.prepare('delete from organization_reports where uuid = ?').bind(id2).run()
    },
  )
  expect(gone.status).toBe(409)
  await new Promise((r) => setTimeout(r, 50))
  expect(await objectsOf(t.orgId, id2)).toEqual([])
})

it('sweeps orphaned report blobs and spares unfinished uploads that hold a live claim', async () => {
  const t = await setup('sweep')
  const kept = (await (await addV1(t.owner, t.orgId)).json()) as any
  const keptKey = `org-reports/${t.orgId}/${kept.id}/data`
  const stray = `org-reports/${t.orgId}/${crypto.randomUUID()}/stray`
  await env.ATTACHMENTS.put(stray, 'orphan')
  const later = Date.now() + 2 * 3600_000
  // The sweep takes one page of one prefix per run; three prefixes need at most a few runs.
  for (let i = 0; i < 6 && (await env.ATTACHMENTS.head(stray)); i++) {
    await purgeExpired(env, later)
  }
  expect(await env.ATTACHMENTS.head(stray)).toBeNull()
  expect(await env.ATTACHMENTS.head(keptKey)).not.toBeNull()

  const { body } = await reserve(t.owner, t.orgId, 10)
  const id = body.reportResponse.id as string
  const far = Date.now() + 2 * 24 * 3600_000
  await env.DB.prepare('update organization_reports set upload_started_at = ? where uuid = ?')
    .bind(far - 60_000, id)
    .run()
  await purgeExpired(env, far)
  expect(await rowOf(id)).not.toBeNull()
  await env.DB.prepare('update organization_reports set upload_started_at = null where uuid = ?')
    .bind(id)
    .run()
  await purgeExpired(env, far)
  expect(await rowOf(id)).toBeNull()
})

/** Inserts `count` filler reports with created_at from `base + 1` upward (milliseconds). */
const fillReports = (orgId: string, count: number, base: number) =>
  env.DB.prepare(
    `with recursive n(i) as (select 1 union all select i + 1 from n where i < ?)
     insert into organization_reports (uuid, organization_uuid, summary_data, created_at, updated_at)
     select 'filler-' || ? || '-' || i, ?, 's' || i, ? + i, ? + i from n`,
  )
    .bind(count, orgId, orgId, base, base)
    .run()

it('keeps only the newest reports of an organisation', async () => {
  const t = await setup('cap')
  const old = (await (await addV1(t.owner, t.orgId)).json()) as any
  const oldKey = `org-reports/${t.orgId}/${old.id}/data`
  expect(await env.ATTACHMENTS.head(oldKey)).not.toBeNull()
  await env.DB.prepare('update organization_reports set created_at = 1 where uuid = ?')
    .bind(old.id)
    .run()
  await fillReports(t.orgId, MAX_REPORTS_PER_ORG + 5, 1000)
  const fresh = (await (await addV1(t.owner, t.orgId)).json()) as any
  const list = (await t.owner.json(
    `${R}/organizations/${t.orgId}/data/summary?startDate=1970-01-01T00:00:00Z`,
  )) as { encryptedData: string }[]
  expect(list).toHaveLength(MAX_REPORTS_PER_ORG)
  // The oldest reports are gone, the newest stays, and the pruned report lost its blob.
  expect(list.some((r) => r.encryptedData === 's1')).toBe(false)
  expect(list.at(-1)?.encryptedData).toBe('2.summary')
  expect((await t.owner.call(`${R}/organizations/${t.orgId}/${old.id}`)).status).toBe(404)
  expect((await t.owner.call(`${R}/organizations/${t.orgId}/${fresh.id}`)).status).toBe(200)
  await new Promise((r) => setTimeout(r, 50))
  expect(await env.ATTACHMENTS.head(oldKey)).toBeNull()
})

it('lists the newest 1000 summaries, oldest first', async () => {
  const t = await setup('listlimit')
  await fillReports(t.orgId, 1005, 1000)
  const list = (await t.owner.json(
    `${R}/organizations/${t.orgId}/data/summary?startDate=1970-01-01T00:00:00Z`,
  )) as { encryptedData: string }[]
  expect(list).toHaveLength(1000)
  expect(list[0]?.encryptedData).toBe('s6')
  expect(list.at(-1)?.encryptedData).toBe('s1005')
})

it('reports only confirmed members, as the vault does', async () => {
  const t = await setup('confirmed')
  const invited = await actor('ai-unconfirmed@example.com')
  const before = mail.sent.length
  const inv = await t.owner.call(`/api/organizations/${t.orgId}/users/invite`, 'POST', {
    emails: [invited.email],
    type: 2,
    accessAll: true,
    collections: [],
    groups: [],
    permissions: null,
  })
  expect(inv.status).toBe(200)
  const params = linkParams(mail.sent[before])
  const memberId = params.get('organizationUserId')
  const accepted = await invited.call(
    `/api/organizations/${t.orgId}/users/${memberId}/accept`,
    'POST',
    { token: params.get('token') },
  )
  expect(accepted.status).toBe(200)
  // Accepted but not confirmed: the member cannot open any item, so the reports skip them.
  const rows = (await t.owner.json(`${R}/member-access/${t.orgId}`)) as { email: string }[]
  expect(rows.some((r) => r.email === invited.email)).toBe(false)
  expect(rows.some((r) => r.email === t.owner.email)).toBe(true)
  const details = (await t.owner.json(`${R}/member-cipher-details/${t.orgId}`)) as {
    email: string
  }[]
  expect(details.some((r) => r.email === invited.email)).toBe(false)
})
