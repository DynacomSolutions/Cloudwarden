// JSON views of the privileged access rows, in the shape of the SDK response models.
import type { schema } from '../db'
import { CONNECTOR_OFFLINE_AFTER_MS } from './constants'

export const iso = (ms: number | null | undefined) =>
  ms == null ? null : new Date(ms).toISOString()

export type ConnectorRow = typeof schema.pamAccessConnectors.$inferSelect
export type TargetRow = typeof schema.pamTargetSystems.$inferSelect
export type ConfigRow = typeof schema.pamRotationConfigs.$inferSelect
export type JobRow = typeof schema.pamRotationJobs.$inferSelect
export type AttemptRow = typeof schema.pamRotationAttempts.$inferSelect

export const list = (data: unknown[]) => ({ object: 'list', data, continuationToken: null })

export function connectorJson(c: ConnectorRow, assigned: string[], now = Date.now()) {
  return {
    object: 'pamAccessConnector',
    id: c.uuid,
    organizationId: c.organizationUuid,
    name: c.name,
    status: c.status,
    isConnected: c.lastHeartbeatAt != null && now - c.lastHeartbeatAt <= CONNECTOR_OFFLINE_AFTER_MS,
    lastHeartbeatAt: iso(c.lastHeartbeatAt),
    assignedTargetSystemIds: assigned,
    creationDate: iso(c.createdAt),
    revisionDate: iso(c.updatedAt),
  }
}

export const targetJson = (t: TargetRow) => ({
  object: 'pamTargetSystem',
  id: t.uuid,
  organizationId: t.organizationUuid,
  name: t.name,
  method: t.method,
  status: t.status,
  sealedData: t.sealedData,
  wrappedKey: t.wrappedKey,
  creationDate: iso(t.createdAt),
  revisionDate: iso(t.updatedAt),
})

export function attemptJson(a: AttemptRow) {
  return {
    id: a.uuid,
    jobId: a.jobUuid,
    claimedByAccessConnectorId: a.connectorUuid,
    cipherUpdated: a.cipherUpdated,
    status: a.status,
    failureReason: a.failureReason,
    syncState: a.syncState,
    sessionTermination: a.sessionTermination,
    creationDate: iso(a.createdAt),
    resolvedDate: iso(a.resolvedAt),
  }
}

export function jobJson(j: JobRow, attempts: AttemptRow[] = []) {
  return {
    id: j.uuid,
    rotationConfigId: j.configUuid,
    source: j.source,
    status: j.status,
    claimedByAccessConnectorId: j.claimedByConnectorUuid,
    claimedAt: iso(j.claimedAt),
    creationDate: iso(j.createdAt),
    nextClaimableAt: iso(j.nextClaimableAt),
    expiresAt: iso(j.expiresAt),
    attempts: attempts.map(attemptJson),
  }
}

export function configJson(
  c: ConfigRow,
  target: { name: string; method: number } | undefined,
  hasActiveJob: boolean,
) {
  return {
    object: 'pamRotationConfig',
    id: c.uuid,
    organizationId: c.organizationUuid,
    cipherId: c.cipherUuid,
    targetSystemId: c.targetSystemUuid,
    targetSystemName: target?.name ?? null,
    targetSystemMethod: target?.method ?? null,
    sealedData: c.sealedData,
    wrappedKey: c.wrappedKey,
    scheduleCron: c.scheduleCron,
    rotateOnAccessEnd: c.rotateOnAccessEnd,
    nextRotationAt: iso(c.nextRotationAt),
    enabled: c.enabled,
    lastRotationAt: iso(c.lastRotationAt),
    hasActiveJob,
    awaitingManualRotation: c.awaitingManualRotation,
    creationDate: iso(c.createdAt),
    revisionDate: iso(c.updatedAt),
  }
}
