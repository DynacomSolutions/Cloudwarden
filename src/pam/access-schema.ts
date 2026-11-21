// Privileged access: access rules, requests, decisions and leases (docs/privileged-access.md).
// Re-exported by src/pam/schema.ts. Status columns hold the integers of src/pam/constants.ts.
import { sql } from 'drizzle-orm'
import { index, integer, primaryKey, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core'
import { ciphers, collections, organizations, users } from '../db/schema'

/** An access rule: collections whose items need a lease, and the terms of that lease. */
export const pamAccessRules = sqliteTable(
  'pam_access_rules',
  {
    uuid: text('uuid').primaryKey(),
    organizationUuid: text('organization_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    description: text('description'),
    enabled: integer('enabled', { mode: 'boolean' }).notNull().default(true),
    /** JSON object. `approvalMode` ("Automatic" or "Human") picks who approves; see the docs. */
    conditions: text('conditions'),
    singleActiveLease: integer('single_active_lease', { mode: 'boolean' }).notNull().default(false),
    defaultLeaseSeconds: integer('default_lease_seconds').notNull(),
    maxLeaseSeconds: integer('max_lease_seconds').notNull(),
    allowsExtensions: integer('allows_extensions', { mode: 'boolean' }).notNull().default(false),
    maxExtensionSeconds: integer('max_extension_seconds'),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (t) => [index('pam_access_rules_org_idx').on(t.organizationUuid)],
)

/** Collections a rule covers. A collection belongs to at most one rule. */
export const pamRuleCollections = sqliteTable(
  'pam_rule_collections',
  {
    ruleUuid: text('rule_uuid')
      .notNull()
      .references(() => pamAccessRules.uuid, { onDelete: 'cascade' }),
    collectionUuid: text('collection_uuid')
      .notNull()
      .references(() => collections.uuid, { onDelete: 'cascade' }),
  },
  (t) => [
    primaryKey({ columns: [t.ruleUuid, t.collectionUuid] }),
    uniqueIndex('pam_rule_collections_collection_unique').on(t.collectionUuid),
  ],
)

/**
 * An access request, or a lease extension request when `extensionOfLeaseUuid` is set. Partial
 * unique indexes allow one pending request per member and item, and one pending extension per lease.
 */
export const pamAccessRequests = sqliteTable(
  'pam_access_requests',
  {
    uuid: text('uuid').primaryKey(),
    organizationUuid: text('organization_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    cipherUuid: text('cipher_uuid')
      .notNull()
      .references(() => ciphers.uuid, { onDelete: 'cascade' }),
    collectionUuid: text('collection_uuid').notNull(),
    ruleUuid: text('rule_uuid').notNull(),
    requesterUuid: text('requester_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    status: integer('status').notNull().default(0),
    reason: text('reason'),
    windowStart: integer('window_start'),
    windowEnd: integer('window_end'),
    durationSeconds: integer('duration_seconds').notNull(),
    submittedAt: integer('submitted_at').notNull(),
    /** Deadline to decide (pending) or to activate (approved). */
    expiresAt: integer('expires_at').notNull(),
    resolvedAt: integer('resolved_at'),
    extensionOfLeaseUuid: text('extension_of_lease_uuid'),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (t) => [
    index('pam_access_requests_org_idx').on(t.organizationUuid, t.status),
    index('pam_access_requests_requester_idx').on(t.requesterUuid),
    uniqueIndex('pam_access_requests_pending_unique')
      .on(t.requesterUuid, t.cipherUuid)
      .where(sql`${t.status} = 0 and ${t.extensionOfLeaseUuid} is null`),
    uniqueIndex('pam_access_requests_pending_extension_unique')
      .on(t.extensionOfLeaseUuid)
      .where(sql`${t.status} = 0 and ${t.extensionOfLeaseUuid} is not null`),
  ],
)

/** The decision on a request. One decision per request; automatic ones have no decider. */
export const pamAccessDecisions = sqliteTable(
  'pam_access_decisions',
  {
    uuid: text('uuid').primaryKey(),
    requestUuid: text('request_uuid')
      .notNull()
      .references(() => pamAccessRequests.uuid, { onDelete: 'cascade' }),
    deciderKind: integer('decider_kind').notNull(),
    deciderUserUuid: text('decider_user_uuid').references(() => users.uuid, {
      onDelete: 'set null',
    }),
    verdict: integer('verdict').notNull(),
    comment: text('comment'),
    decidedAt: integer('decided_at').notNull(),
  },
  (t) => [uniqueIndex('pam_access_decisions_request_unique').on(t.requestUuid)],
)

/**
 * A lease: time-boxed access to one item. `status` stores Active, Revoked or Cancelled. Expired is
 * derived at read time once `notAfter` has passed, and stored by the sweep. One lease per request.
 */
export const pamLeases = sqliteTable(
  'pam_leases',
  {
    uuid: text('uuid').primaryKey(),
    requestUuid: text('request_uuid')
      .notNull()
      .references(() => pamAccessRequests.uuid, { onDelete: 'cascade' }),
    organizationUuid: text('organization_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    cipherUuid: text('cipher_uuid')
      .notNull()
      .references(() => ciphers.uuid, { onDelete: 'cascade' }),
    collectionUuid: text('collection_uuid').notNull(),
    requesterUuid: text('requester_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    status: integer('status').notNull().default(0),
    notBefore: integer('not_before').notNull(),
    notAfter: integer('not_after').notNull(),
    revokedAt: integer('revoked_at'),
    revokedByUserUuid: text('revoked_by_user_uuid'),
    revocationReason: text('revocation_reason'),
    /** The extension request that last moved `notAfter`; makes applying an extension atomic. */
    lastExtensionRequestUuid: text('last_extension_request_uuid'),
    createdAt: integer('created_at').notNull(),
  },
  (t) => [
    uniqueIndex('pam_leases_request_unique').on(t.requestUuid),
    index('pam_leases_cipher_idx').on(t.cipherUuid, t.status),
    index('pam_leases_requester_idx').on(t.requesterUuid),
    index('pam_leases_org_idx').on(t.organizationUuid, t.status),
  ],
)
