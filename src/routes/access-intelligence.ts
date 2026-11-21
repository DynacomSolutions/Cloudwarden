// Access Intelligence (risk insights) reports under /api/reports (TASKS #435). Shapes follow the
// GPL SDK API crate (OrganizationReportsApi, ReportsApi). The encrypted report blob lives in R2;
// the small encrypted summary and application strings stay in D1. Reading and writing need the
// "access reports" permission (owners, admins and custom members holding it); anyone else
// gets 404, so the endpoints do not reveal which organisations exist.
import { and, desc, eq, gt, gte, inArray, lte, sql } from 'drizzle-orm'
import type { Context, Hono } from 'hono'
import { z } from 'zod'
import { requireAuth } from '../auth/middleware'
import { changes, createDb, type Db, runBatch, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { MAX_ENC_NAME } from '../limits'
import { can, getMember } from '../orgs/access'
import { memberAccessReport, memberCipherReport } from '../orgs/member-access'
import { parseBody } from '../validation'
import {
  baseUrl,
  deleteBlobs,
  MAX_UPLOAD_BYTES,
  orgReportKey,
  storeMultipartUploadWithin,
  UPLOAD_CLAIM_TTL_MS,
} from '../vault/blobs'

type Ctx = Context<Env>
type ReportRow = typeof schema.organizationReports.$inferSelect

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
/** Summary and application strings sit in D1 rows (about 2 MB each), so each is capped. */
const MAX_SMALL_DATA = 512_000
/** Inline report data of the original flow is stored in R2; this bounds one JSON request. */
const MAX_REPORT_DATA = 20_000_000
/** Request bodies other than the inline report data. */
const MAX_SMALL_BODY = 1_500_000
/** Unfinished file uploads allowed per organisation within the claim window. */
const MAX_PENDING_REPORTS = 10
const PENDING_WINDOW_MS = 24 * 60 * 60 * 1000
const MAX_APPLICATIONS_PER_REQUEST = 200
const MAX_APPLICATIONS_PER_ORG = 10_000
const MAX_LISTED_SUMMARIES = 1000
const FILE_UPLOAD_DIRECT = 0
/** The stored file may differ from its declared size by this much (1 MiB). */
const SIZE_LEEWAY = 1024 * 1024

const METRIC_KEYS = [
  'totalApplicationCount',
  'totalAtRiskApplicationCount',
  'totalCriticalApplicationCount',
  'totalCriticalAtRiskApplicationCount',
  'totalMemberCount',
  'totalAtRiskMemberCount',
  'totalCriticalMemberCount',
  'totalCriticalAtRiskMemberCount',
  'totalPasswordCount',
  'totalAtRiskPasswordCount',
  'totalCriticalPasswordCount',
  'totalCriticalAtRiskPasswordCount',
] as const

const metricsSchema = z.object(
  Object.fromEntries(METRIC_KEYS.map((k) => [k, z.number().int().nullish()])) as Record<
    (typeof METRIC_KEYS)[number],
    z.ZodOptional<z.ZodNullable<z.ZodNumber>>
  >,
)

const small = z.string().max(MAX_SMALL_DATA)
const key = z.string().max(MAX_ENC_NAME * 4)

const addSchema = z.object({
  reportData: z.string().max(MAX_REPORT_DATA).nullish(),
  contentEncryptionKey: key.nullish(),
  summaryData: small.nullish(),
  applicationData: small.nullish(),
  metrics: metricsSchema.nullish(),
  fileSize: z.number().int().nullish(),
})

const updateSchema = z.object({
  contentEncryptionKey: key.nullish(),
  summaryData: small.nullish(),
  applicationData: small.nullish(),
  reportMetrics: metricsSchema,
})

const summaryUpdateSchema = z.object({
  summaryData: small.nullish(),
  metrics: metricsSchema.nullish(),
})

const applicationUpdateSchema = z.object({ applicationData: small.nullish() })

const applicationAddSchema = z
  .array(z.object({ organizationId: z.string(), url: z.string().min(1).max(2048) }))
  .max(MAX_APPLICATIONS_PER_REQUEST)

const applicationDropSchema = z.object({
  organizationId: z.string(),
  passwordHealthReportApplicationIds: z.array(z.string()).max(MAX_APPLICATIONS_PER_REQUEST),
})

const idParam = (c: Ctx, name: string, what: string) => {
  const v = c.req.param(name) ?? ''
  if (!UUID.test(v)) throw new ApiError(404, `${what} not found.`)
  return v.toLowerCase()
}

const iso = (ms: number) => new Date(ms).toISOString()

/** The caller must hold the access-reports permission of the organisation; otherwise 404. */
async function requireReports(db: Db, userUuid: string, orgUuid: string) {
  const m = await getMember(db, userUuid, orgUuid)
  if (!can(m, 'accessReports')) throw new ApiError(404, 'Resource not found.')
}

async function loadReport(db: Db, orgUuid: string, reportUuid: string): Promise<ReportRow> {
  const [row] = await db
    .select()
    .from(schema.organizationReports)
    .where(
      and(
        eq(schema.organizationReports.uuid, reportUuid),
        eq(schema.organizationReports.organizationUuid, orgUuid),
      ),
    )
    .limit(1)
  if (!row) throw new ApiError(404, 'Report not found.')
  return row
}

/** Authorises the caller and returns the report of the path. */
async function authorisedReport(c: Ctx, db: Db) {
  const orgUuid = idParam(c, 'org', 'Organization')
  const reportUuid = idParam(c, 'report', 'Report')
  await requireReports(db, c.var.user.uuid, orgUuid)
  return loadReport(db, orgUuid, reportUuid)
}

const reportBase = (c: Ctx, r: ReportRow) =>
  `${baseUrl(c.env)}/api/reports/organizations/${r.organizationUuid}/${r.uuid}`

const hasFile = (r: ReportRow) => r.fileId != null

/** Inline report data of the original flow, read back from R2. */
async function inlineData(c: Ctx, r: ReportRow): Promise<string | null> {
  if (hasFile(r) || !r.blobKey) return null
  const object = await c.env.ATTACHMENTS.get(r.blobKey)
  return object ? await object.text() : null
}

/** OrganizationReportResponseModel. */
async function reportJson(c: Ctx, r: ReportRow, withData: boolean) {
  const validated = hasFile(r) && r.fileValidated
  return {
    id: r.uuid,
    organizationId: r.organizationUuid,
    reportData: withData ? await inlineData(c, r) : null,
    contentEncryptionKey: r.contentEncryptionKey,
    summaryData: r.summaryData,
    applicationData: r.applicationData,
    reportFile: hasFile(r)
      ? { id: r.fileId, fileName: r.fileName, size: r.fileSize, validated: r.fileValidated }
      : null,
    reportFileDownloadUrl: validated ? `${reportBase(c, r)}/file/download` : null,
    fileUploadType: validated ? FILE_UPLOAD_DIRECT : null,
    creationDate: iso(r.createdAt),
    revisionDate: iso(r.updatedAt),
  }
}

/** OrganizationReportFileResponseModel: where to upload the file of a report. */
async function fileJson(c: Ctx, r: ReportRow) {
  return {
    reportFileUploadUrl: `${reportBase(c, r)}/file?reportFileId=${r.fileId}`,
    reportResponse: await reportJson(c, r, false),
    fileUploadType: FILE_UPLOAD_DIRECT,
  }
}

/** A report whose file flow never finished is not a usable "latest" report. */
const complete = sql`(${schema.organizationReports.fileId} is null or ${schema.organizationReports.fileValidated} = 1)`

export function registerAccessIntelligence(r: Hono<Env>) {
  const writeDb = (c: Ctx) => createDb(c.env.DB_PRIMARY ?? c.env.DB)

  // ----- Member reports -----

  r.get('/api/reports/member-access/:org', requireAuth, async (c) => {
    const orgUuid = idParam(c, 'org', 'Organization')
    const db = createDb(c.env.DB)
    await requireReports(db, c.var.user.uuid, orgUuid)
    return c.json(await memberAccessReport(db, orgUuid))
  })

  r.get('/api/reports/member-cipher-details/:org', requireAuth, async (c) => {
    const orgUuid = idParam(c, 'org', 'Organization')
    const db = createDb(c.env.DB)
    await requireReports(db, c.var.user.uuid, orgUuid)
    return c.json(await memberCipherReport(db, orgUuid))
  })

  // ----- Password health applications (critical applications) -----

  const appJson = (a: typeof schema.passwordHealthReportApplications.$inferSelect) => ({
    id: a.uuid,
    organizationId: a.organizationUuid,
    uri: a.uri,
    creationDate: iso(a.createdAt),
    revisionDate: iso(a.updatedAt),
  })

  r.get('/api/reports/password-health-report-applications/:org', requireAuth, async (c) => {
    const orgUuid = idParam(c, 'org', 'Organization')
    const db = createDb(c.env.DB)
    await requireReports(db, c.var.user.uuid, orgUuid)
    const rows = await db
      .select()
      .from(schema.passwordHealthReportApplications)
      .where(eq(schema.passwordHealthReportApplications.organizationUuid, orgUuid))
      .orderBy(schema.passwordHealthReportApplications.createdAt)
    return c.json(rows.map(appJson))
  })

  r.post('/api/reports/password-health-report-applications', requireAuth, async (c) => {
    const body = await parseBody(c, applicationAddSchema, MAX_SMALL_BODY)
    const db = writeDb(c)
    const orgs = [...new Set(body.map((a) => a.organizationId.toLowerCase()))]
    for (const org of orgs) {
      if (!UUID.test(org)) throw new ApiError(404, 'Organization not found.')
      await requireReports(db, c.var.user.uuid, org)
    }
    for (const org of orgs) {
      const [n] = await db
        .select({ n: sql<number>`count(*)` })
        .from(schema.passwordHealthReportApplications)
        .where(eq(schema.passwordHealthReportApplications.organizationUuid, org))
      const adding = body.filter((a) => a.organizationId.toLowerCase() === org).length
      if ((n?.n ?? 0) + adding > MAX_APPLICATIONS_PER_ORG) {
        throw new ApiError(400, 'Too many applications for this organization.')
      }
    }
    const now = Date.now()
    const rows = body.map((a) => ({
      uuid: crypto.randomUUID(),
      organizationUuid: a.organizationId.toLowerCase(),
      uri: a.url,
      createdAt: now,
      updatedAt: now,
    }))
    await runBatch(
      db,
      rows.map((row) => db.insert(schema.passwordHealthReportApplications).values(row)),
    )
    return c.json(rows.map(appJson))
  })

  r.delete('/api/reports/password-health-report-application', requireAuth, async (c) => {
    const body = await parseBody(c, applicationDropSchema, MAX_SMALL_BODY)
    const org = body.organizationId.toLowerCase()
    if (!UUID.test(org)) throw new ApiError(404, 'Organization not found.')
    const db = writeDb(c)
    await requireReports(db, c.var.user.uuid, org)
    const [n] = await db
      .select({ n: sql<number>`count(*)` })
      .from(schema.passwordHealthReportApplications)
      .where(eq(schema.passwordHealthReportApplications.organizationUuid, org))
    if (!n?.n) {
      throw new ApiError(400, 'This organization has no password health report applications.')
    }
    const ids = body.passwordHealthReportApplicationIds
      .map((i) => i.toLowerCase())
      .filter((i) => UUID.test(i))
    if (ids.length > 0) {
      await db
        .delete(schema.passwordHealthReportApplications)
        .where(
          and(
            eq(schema.passwordHealthReportApplications.organizationUuid, org),
            inArray(schema.passwordHealthReportApplications.uuid, ids),
          ),
        )
    }
    return c.body(null, 200)
  })

  // ----- Organisation reports -----
  // Literal paths come before the `:report` ones so `latest`, `data` and `file` are not read as ids.

  r.post('/api/reports/organizations/file/validate/azure', async (c) => {
    // Azure Event Grid callback of the official cloud. Files are checked in this server when the
    // upload ends, so only the handshake is answered; every other event is refused.
    const events = (await c.req.json().catch(() => null)) as
      | { eventType?: string; data?: { validationCode?: string } }[]
      | null
    const handshake = Array.isArray(events)
      ? events.find((e) => e?.eventType === 'Microsoft.EventGrid.SubscriptionValidationEvent')
      : undefined
    if (handshake?.data?.validationCode) {
      return c.json({ validationResponse: handshake.data.validationCode })
    }
    throw new ApiError(400, 'Azure blob storage is not used by this server.')
  })

  r.post('/api/reports/organizations/:org', requireAuth, async (c) => {
    const orgUuid = idParam(c, 'org', 'Organization')
    const body = await parseBody(c, addSchema, MAX_REPORT_DATA + MAX_SMALL_BODY)
    const db = writeDb(c)
    await requireReports(db, c.var.user.uuid, orgUuid)
    const uuid = crypto.randomUUID()
    const now = Date.now()
    const common = {
      uuid,
      organizationUuid: orgUuid,
      contentEncryptionKey: body.contentEncryptionKey ?? null,
      summaryData: body.summaryData ?? null,
      applicationData: body.applicationData ?? null,
      metrics: body.metrics ? JSON.stringify(body.metrics) : null,
      createdAt: now,
      updatedAt: now,
    }
    if (body.fileSize != null) {
      // File flow: reserve the report and tell the client where to upload the encrypted file.
      if (body.fileSize < 1) throw new ApiError(400, 'The file size is not valid.')
      if (body.fileSize > MAX_UPLOAD_BYTES) throw new ApiError(413, 'The file is too large.')
      const [pending] = await db
        .select({ n: sql<number>`count(*)` })
        .from(schema.organizationReports)
        .where(
          and(
            eq(schema.organizationReports.organizationUuid, orgUuid),
            sql`${schema.organizationReports.fileId} is not null`,
            eq(schema.organizationReports.fileValidated, false),
            gt(schema.organizationReports.createdAt, now - PENDING_WINDOW_MS),
          ),
        )
      if ((pending?.n ?? 0) >= MAX_PENDING_REPORTS) {
        throw new ApiError(400, 'Too many unfinished report uploads for this organization.')
      }
      const fileId = crypto.randomUUID().replaceAll('-', '')
      await db.insert(schema.organizationReports).values({
        ...common,
        blobKey: orgReportKey(orgUuid, uuid, fileId),
        fileId,
        fileName: `report-${uuid}`,
        fileSize: body.fileSize,
        fileValidated: false,
      })
      return c.json(await fileJson(c, await loadReport(db, orgUuid, uuid)))
    }
    // Original flow: the report data comes inline and is kept as a blob.
    const blobKey = body.reportData ? orgReportKey(orgUuid, uuid, 'data') : null
    if (blobKey) await c.env.ATTACHMENTS.put(blobKey, body.reportData ?? '')
    try {
      await db.insert(schema.organizationReports).values({ ...common, blobKey })
    } catch (e) {
      if (blobKey) deleteBlobs(c, [blobKey])
      throw e
    }
    return c.json(await reportJson(c, await loadReport(db, orgUuid, uuid), true))
  })

  r.get('/api/reports/organizations/:org/latest', requireAuth, async (c) => {
    const orgUuid = idParam(c, 'org', 'Organization')
    const db = createDb(c.env.DB)
    await requireReports(db, c.var.user.uuid, orgUuid)
    const [latest] = await db
      .select()
      .from(schema.organizationReports)
      .where(and(eq(schema.organizationReports.organizationUuid, orgUuid), complete))
      .orderBy(desc(schema.organizationReports.createdAt), desc(schema.organizationReports.uuid))
      .limit(1)
    if (!latest) throw new ApiError(404, 'Report not found.')
    return c.json(await reportJson(c, latest, true))
  })

  r.get('/api/reports/organizations/:org/data/summary', requireAuth, async (c) => {
    const orgUuid = idParam(c, 'org', 'Organization')
    const date = (name: string, fallback: number) => {
      const raw = c.req.query(name)
      if (!raw) return fallback
      const ms = Date.parse(raw)
      if (Number.isNaN(ms)) throw new ApiError(400, `${name} is not a valid date.`)
      return ms
    }
    const start = date('startDate', 0)
    const end = date('endDate', Date.now())
    const db = createDb(c.env.DB)
    await requireReports(db, c.var.user.uuid, orgUuid)
    const rows = await db
      .select()
      .from(schema.organizationReports)
      .where(
        and(
          eq(schema.organizationReports.organizationUuid, orgUuid),
          gte(schema.organizationReports.createdAt, start),
          lte(schema.organizationReports.createdAt, end),
        ),
      )
      .orderBy(schema.organizationReports.createdAt)
      .limit(MAX_LISTED_SUMMARIES)
    return c.json(rows.map((row) => summaryJson(row)))
  })

  const summaryJson = (row: ReportRow) => ({
    organizationId: row.organizationUuid,
    encryptedData: row.summaryData,
    encryptionKey: row.contentEncryptionKey,
    date: iso(row.createdAt),
  })

  r.get('/api/reports/organizations/:org/data/summary/:report', requireAuth, async (c) => {
    return c.json(summaryJson(await authorisedReport(c, createDb(c.env.DB))))
  })

  r.patch('/api/reports/organizations/:org/data/summary/:report', requireAuth, async (c) => {
    const body = await parseBody(c, summaryUpdateSchema, MAX_SMALL_BODY)
    const db = writeDb(c)
    const report = await authorisedReport(c, db)
    await db
      .update(schema.organizationReports)
      .set({
        ...(body.summaryData != null ? { summaryData: body.summaryData } : {}),
        ...(body.metrics ? { metrics: JSON.stringify(body.metrics) } : {}),
        updatedAt: Date.now(),
      })
      .where(eq(schema.organizationReports.uuid, report.uuid))
    return c.json(
      await reportJson(c, await loadReport(db, report.organizationUuid, report.uuid), false),
    )
  })

  r.get('/api/reports/organizations/:org/data/application/:report', requireAuth, async (c) => {
    const report = await authorisedReport(c, createDb(c.env.DB))
    return c.json({ applicationData: report.applicationData })
  })

  r.patch('/api/reports/organizations/:org/data/application/:report', requireAuth, async (c) => {
    const body = await parseBody(c, applicationUpdateSchema, MAX_SMALL_BODY)
    const db = writeDb(c)
    const report = await authorisedReport(c, db)
    await db
      .update(schema.organizationReports)
      .set({
        ...(body.applicationData != null ? { applicationData: body.applicationData } : {}),
        updatedAt: Date.now(),
      })
      .where(eq(schema.organizationReports.uuid, report.uuid))
    return c.json(
      await reportJson(c, await loadReport(db, report.organizationUuid, report.uuid), false),
    )
  })

  r.get('/api/reports/organizations/:org/:report/file/download', requireAuth, async (c) => {
    const report = await authorisedReport(c, createDb(c.env.DB))
    if (!hasFile(report) || !report.fileValidated || !report.blobKey) {
      throw new ApiError(404, 'Report file not found.')
    }
    const object = await c.env.ATTACHMENTS.get(report.blobKey)
    if (!object) throw new ApiError(404, 'Report file not found.')
    return new Response(object.body, {
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(object.size),
        'Content-Disposition': `attachment; filename="${report.fileName ?? 'report'}"`,
        'Cache-Control': 'private, no-store',
      },
    })
  })

  r.get('/api/reports/organizations/:org/:report/file/renew', requireAuth, async (c) => {
    const db = writeDb(c)
    const report = await authorisedReport(c, db)
    const fileId = c.req.query('reportFileId')
    if (!fileId) throw new ApiError(400, 'ReportFileId is required.')
    if (!hasFile(report) || report.fileId !== fileId || report.fileValidated) {
      throw new ApiError(404, 'Report file not found.')
    }
    return c.json(await fileJson(c, report))
  })

  r.post('/api/reports/organizations/:org/:report/file', requireAuth, async (c) => {
    const db = writeDb(c)
    const report = await authorisedReport(c, db)
    const fileId = c.req.query('reportFileId')
    if (!fileId) throw new ApiError(400, 'ReportFileId query parameter is required.')
    if (!hasFile(report) || report.fileId !== fileId || report.fileValidated || !report.blobKey) {
      throw new ApiError(404, 'Report file not found.')
    }
    const started = Date.now()
    const claim = await db
      .update(schema.organizationReports)
      .set({ uploadStartedAt: started })
      .where(
        and(
          eq(schema.organizationReports.uuid, report.uuid),
          eq(schema.organizationReports.fileValidated, false),
          sql`(${schema.organizationReports.uploadStartedAt} is null or ${schema.organizationReports.uploadStartedAt} < ${started - UPLOAD_CLAIM_TTL_MS})`,
        ),
      )
    if (changes(claim) === 0) throw new ApiError(409, 'An upload for this report is in progress.')
    let stored = 0
    try {
      // The client may declare the size of the file before it adds framing, so a small
      // difference is accepted. The stored length replaces the declared one.
      const declared = report.fileSize ?? 0
      stored = await storeMultipartUploadWithin(
        c,
        report.blobKey,
        Math.max(1, declared - SIZE_LEEWAY),
        Math.min(declared + SIZE_LEEWAY, MAX_UPLOAD_BYTES),
      )
    } catch (e) {
      // A file that does not match its declared size makes the whole report unusable.
      await db
        .delete(schema.organizationReports)
        .where(eq(schema.organizationReports.uuid, report.uuid))
      deleteBlobs(c, [report.blobKey])
      throw e
    }
    await db
      .update(schema.organizationReports)
      .set({ fileValidated: true, fileSize: stored, uploadStartedAt: null, updatedAt: Date.now() })
      .where(eq(schema.organizationReports.uuid, report.uuid))
    return c.body(null, 200)
  })

  r.get('/api/reports/organizations/:org/:report', requireAuth, async (c) => {
    const report = await authorisedReport(c, createDb(c.env.DB))
    return c.json(await reportJson(c, report, true))
  })

  r.patch('/api/reports/organizations/:org/:report', requireAuth, async (c) => {
    const body = await parseBody(c, updateSchema, MAX_SMALL_BODY)
    const db = writeDb(c)
    const report = await authorisedReport(c, db)
    await db
      .update(schema.organizationReports)
      .set({
        ...(body.contentEncryptionKey != null
          ? { contentEncryptionKey: body.contentEncryptionKey }
          : {}),
        ...(body.summaryData != null ? { summaryData: body.summaryData } : {}),
        ...(body.applicationData != null ? { applicationData: body.applicationData } : {}),
        metrics: JSON.stringify(body.reportMetrics),
        updatedAt: Date.now(),
      })
      .where(eq(schema.organizationReports.uuid, report.uuid))
    return c.json(
      await reportJson(c, await loadReport(db, report.organizationUuid, report.uuid), false),
    )
  })

  r.delete('/api/reports/organizations/:org/:report', requireAuth, async (c) => {
    const db = writeDb(c)
    const report = await authorisedReport(c, db)
    await db
      .delete(schema.organizationReports)
      .where(eq(schema.organizationReports.uuid, report.uuid))
    if (report.blobKey) deleteBlobs(c, [report.blobKey])
    return c.body(null, 200)
  })
}
