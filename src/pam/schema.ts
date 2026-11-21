// Privileged access management: access connectors and credential rotation (docs/privileged-access.md).
// Re-exported by src/db/schema.ts so drizzle-kit and `schema.*` see these tables. Enum columns
// hold the integers of src/pam/constants.ts. Everything sealed or wrapped is client ciphertext.
import { sql } from 'drizzle-orm'
import { index, integer, primaryKey, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core'
import { ciphers, organizations } from '../db/schema'

/**
 * An access connector: a daemon that rotates credentials. It signs in with `apiKeyId` and a client
 * secret (only a SHA-256 of the secret is kept). `encryptedPayload` (the organisation key under
 * the connector's own key) and `key` are opaque client data, like a machine account token.
 */
export const pamAccessConnectors = sqliteTable(
  'pam_access_connectors',
  {
    uuid: text('uuid').primaryKey(),
    organizationUuid: text('organization_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    status: integer('status').notNull().default(0),
    apiKeyId: text('api_key_id').notNull(),
    clientSecretHash: text('client_secret_hash').notNull(),
    encryptedPayload: text('encrypted_payload').notNull(),
    key: text('key').notNull(),
    lastHeartbeatAt: integer('last_heartbeat_at'),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (t) => [
    index('pam_access_connectors_org_idx').on(t.organizationUuid),
    uniqueIndex('pam_access_connectors_api_key_unique').on(t.apiKeyId),
  ],
)

/** A system whose credentials get rotated. `sealedData` and `wrappedKey` stay null until sealed. */
export const pamTargetSystems = sqliteTable(
  'pam_target_systems',
  {
    uuid: text('uuid').primaryKey(),
    organizationUuid: text('organization_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    method: integer('method').notNull(),
    status: integer('status').notNull().default(2),
    sealedData: text('sealed_data'),
    wrappedKey: text('wrapped_key'),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (t) => [index('pam_target_systems_org_idx').on(t.organizationUuid)],
)

/** Which target systems a connector may work on. */
export const pamConnectorAssignments = sqliteTable(
  'pam_connector_assignments',
  {
    connectorUuid: text('connector_uuid')
      .notNull()
      .references(() => pamAccessConnectors.uuid, { onDelete: 'cascade' }),
    targetSystemUuid: text('target_system_uuid')
      .notNull()
      .references(() => pamTargetSystems.uuid, { onDelete: 'cascade' }),
    createdAt: integer('created_at').notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.connectorUuid, t.targetSystemUuid] }),
    index('pam_connector_assignments_target_idx').on(t.targetSystemUuid),
  ],
)

/** Rotation settings of one organisation item (one configuration per item). */
export const pamRotationConfigs = sqliteTable(
  'pam_rotation_configs',
  {
    uuid: text('uuid').primaryKey(),
    organizationUuid: text('organization_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    cipherUuid: text('cipher_uuid')
      .notNull()
      .references(() => ciphers.uuid, { onDelete: 'cascade' }),
    targetSystemUuid: text('target_system_uuid')
      .notNull()
      .references(() => pamTargetSystems.uuid),
    sealedData: text('sealed_data').notNull(),
    wrappedKey: text('wrapped_key').notNull(),
    scheduleCron: text('schedule_cron'),
    rotateOnAccessEnd: integer('rotate_on_access_end', { mode: 'boolean' })
      .notNull()
      .default(false),
    nextRotationAt: integer('next_rotation_at'),
    enabled: integer('enabled', { mode: 'boolean' }).notNull().default(true),
    lastRotationAt: integer('last_rotation_at'),
    awaitingManualRotation: integer('awaiting_manual_rotation', { mode: 'boolean' })
      .notNull()
      .default(false),
    lastOnDemandAt: integer('last_on_demand_at'),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (t) => [
    uniqueIndex('pam_rotation_configs_cipher_unique').on(t.cipherUuid),
    index('pam_rotation_configs_org_idx').on(t.organizationUuid),
    index('pam_rotation_configs_target_idx').on(t.targetSystemUuid),
    index('pam_rotation_configs_due_idx').on(t.nextRotationAt),
  ],
)

/**
 * One rotation job. The partial unique index allows one open job (Pending or Claimed) per
 * configuration, so queueing a job twice is a no-op and a claim race has one winner.
 */
export const pamRotationJobs = sqliteTable(
  'pam_rotation_jobs',
  {
    uuid: text('uuid').primaryKey(),
    configUuid: text('config_uuid')
      .notNull()
      .references(() => pamRotationConfigs.uuid, { onDelete: 'cascade' }),
    organizationUuid: text('organization_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    targetSystemUuid: text('target_system_uuid').notNull(),
    source: integer('source').notNull(),
    status: integer('status').notNull().default(0),
    claimedByConnectorUuid: text('claimed_by_connector_uuid').references(
      () => pamAccessConnectors.uuid,
      { onDelete: 'set null' },
    ),
    claimedAt: integer('claimed_at'),
    nextClaimableAt: integer('next_claimable_at').notNull(),
    expiresAt: integer('expires_at').notNull(),
    createdAt: integer('created_at').notNull(),
  },
  (t) => [
    uniqueIndex('pam_rotation_jobs_open_unique').on(t.configUuid).where(sql`${t.status} in (0, 1)`),
    index('pam_rotation_jobs_target_idx').on(t.targetSystemUuid, t.status),
    index('pam_rotation_jobs_org_idx').on(t.organizationUuid),
  ],
)

/** One try at a job by one connector. `cipherUpdated` is set once the rotated item is written. */
export const pamRotationAttempts = sqliteTable(
  'pam_rotation_attempts',
  {
    uuid: text('uuid').primaryKey(),
    jobUuid: text('job_uuid')
      .notNull()
      .references(() => pamRotationJobs.uuid, { onDelete: 'cascade' }),
    connectorUuid: text('connector_uuid').references(() => pamAccessConnectors.uuid, {
      onDelete: 'set null',
    }),
    cipherUpdated: integer('cipher_updated', { mode: 'boolean' }).notNull().default(false),
    status: integer('status').notNull().default(0),
    failureReason: text('failure_reason'),
    syncState: integer('sync_state'),
    sessionTermination: integer('session_termination'),
    createdAt: integer('created_at').notNull(),
    resolvedAt: integer('resolved_at'),
  },
  (t) => [index('pam_rotation_attempts_job_idx').on(t.jobUuid)],
)

/**
 * Audit trail of privileged access actions: connector registration, rotation steps, rejected
 * connector reports, access requests, decisions and leases. No foreign keys: rows outlive what they
 * describe. Event codes are not used because the Bitwarden event type list has none for this area.
 */
export const pamAudit = sqliteTable(
  'pam_audit',
  {
    uuid: text('uuid').primaryKey(),
    organizationUuid: text('organization_uuid').notNull(),
    kind: text('kind').notNull(),
    /** The member or connector that acted; null for the system (sweeps). */
    actorUuid: text('actor_uuid'),
    refUuid: text('ref_uuid'),
    detail: text('detail'),
    createdAt: integer('created_at').notNull(),
  },
  (t) => [index('pam_audit_org_idx').on(t.organizationUuid, t.createdAt)],
)
