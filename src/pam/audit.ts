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
