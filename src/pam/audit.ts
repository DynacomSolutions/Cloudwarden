import { and, eq, type SQL, sql } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'

export type AuditKind = string

/** An insert statement for one audit row; include it in the batch of the write it records. */
export const auditStatement = (
  db: Db,
  orgUuid: string,
  kind: AuditKind,
  actorUuid: string | null,
  refUuid: string | null = null,
  detail: string | null = null,
  now = Date.now(),
) =>
  db.insert(schema.pamAudit).values({
    uuid: crypto.randomUUID(),
    organizationUuid: orgUuid,
    kind,
    actorUuid,
    refUuid,
    detail,
    createdAt: now,
  })

/**
 * Like `auditStatement`, but the row exists only while `guard` holds for the access request
 * `requestUuid`. A batch that lost its race then leaves no audit row for the decision it did not make.
 */
export const auditStatementIf = (
  db: Db,
  requestUuid: string,
  guard: SQL,
  orgUuid: string,
  kind: AuditKind,
  actorUuid: string | null,
  refUuid: string | null,
  detail: string | null,
  now: number,
) =>
  db.insert(schema.pamAudit).select(
    db
      .select({
        uuid: sql<string>`${crypto.randomUUID()}`.as('uuid'),
        organizationUuid: sql<string>`${orgUuid}`.as('organization_uuid'),
        kind: sql<string>`${kind}`.as('kind'),
        actorUuid: sql<string | null>`${actorUuid}`.as('actor_uuid'),
        refUuid: sql<string | null>`${refUuid}`.as('ref_uuid'),
        detail: sql<string | null>`${detail}`.as('detail'),
        createdAt: sql<number>`${now}`.as('created_at'),
      })
      .from(schema.pamAccessRequests)
      .where(and(eq(schema.pamAccessRequests.uuid, requestUuid), guard)),
  )
