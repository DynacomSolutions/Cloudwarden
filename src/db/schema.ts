import { index, integer, primaryKey, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core'

// Conventions: text UUID primary keys, integer timestamps in epoch milliseconds,
// booleans as integer 0/1. Derived from the Bitwarden API contract (TASKS #14); it will evolve.

const id = () => text('uuid').primaryKey()
const createdAt = () => integer('created_at').notNull()
const updatedAt = () => integer('updated_at').notNull()

export const users = sqliteTable(
  'users',
  {
    uuid: id(),
    email: text('email').notNull(),
    name: text('name').notNull(),
    passwordHash: text('password_hash').notNull(),
    salt: text('salt').notNull(),
    passwordIterations: integer('password_iterations').notNull(),
    passwordHint: text('password_hint'),
    akey: text('akey').notNull(),
    privateKey: text('private_key'),
    publicKey: text('public_key'),
    kdfType: integer('kdf_type').notNull().default(0),
    kdfIterations: integer('kdf_iterations').notNull().default(600000),
    kdfMemory: integer('kdf_memory'),
    kdfParallelism: integer('kdf_parallelism'),
    securityStamp: text('security_stamp').notNull(),
    stampException: text('stamp_exception'),
    totpRecover: text('totp_recover'),
    apiKey: text('api_key'),
    emailNew: text('email_new'),
    emailNewToken: text('email_new_token'),
    emailNewExpiresAt: integer('email_new_expires_at'),
    equivalentDomains: text('equivalent_domains').notNull().default('[]'),
    excludedGlobals: text('excluded_globals').notNull().default('[]'),
    clientKdfType: integer('client_kdf_type').notNull().default(0),
    clientKdfIter: integer('client_kdf_iter').notNull().default(600000),
    clientKdfMemory: integer('client_kdf_memory'),
    clientKdfParallelism: integer('client_kdf_parallelism'),
    verifiedAt: integer('verified_at'),
    lastVerifyingAt: integer('last_verifying_at'),
    loginVerifyCount: integer('login_verify_count').notNull().default(0),
    enabled: integer('enabled', { mode: 'boolean' }).notNull().default(true),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [uniqueIndex('users_email_unique').on(t.email)],
)

export const devices = sqliteTable(
  'devices',
  {
    uuid: id(),
    // Client-chosen device identifier. The same identifier may exist for several users.
    identifier: text('identifier').notNull(),
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    type: integer('type').notNull(),
    pushToken: text('push_token'),
    // SHA-256 (base64url) of the refresh token secret; empty string means revoked.
    refreshToken: text('refresh_token').notNull(),
    twofactorRemember: text('twofactor_remember'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('devices_user_idx').on(t.userUuid),
    uniqueIndex('devices_user_identifier_unique').on(t.userUuid, t.identifier),
  ],
)

/** Login-with-device requests. The access code is stored as a SHA-256 (base64url) digest. */
export const authRequests = sqliteTable(
  'auth_requests',
  {
    uuid: id(),
    // Null for decoy rows created for unknown emails, so those are indistinguishable.
    userUuid: text('user_uuid').references(() => users.uuid, { onDelete: 'cascade' }),
    // 0 authenticate and unlock, 1 unlock.
    type: integer('type').notNull(),
    requestDeviceIdentifier: text('request_device_identifier').notNull(),
    requestDeviceType: integer('request_device_type').notNull(),
    requestIp: text('request_ip'),
    publicKey: text('public_key').notNull(),
    accessCodeHash: text('access_code_hash').notNull(),
    // Null while pending, then the approving device's decision.
    approved: integer('approved', { mode: 'boolean' }),
    // User key encrypted to `publicKey` by the approving device.
    key: text('key'),
    masterPasswordHash: text('master_password_hash'),
    responseDeviceUuid: text('response_device_uuid'),
    responseDate: integer('response_date'),
    // Set when the request was redeemed for tokens; a request is single use.
    authenticatedAt: integer('authenticated_at'),
    createdAt: createdAt(),
  },
  (t) => [index('auth_requests_user_idx').on(t.userUuid)],
)

export const folders = sqliteTable(
  'folders',
  {
    uuid: id(),
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [index('folders_user_idx').on(t.userUuid)],
)

export const organizations = sqliteTable('organizations', {
  uuid: id(),
  name: text('name').notNull(),
  billingEmail: text('billing_email').notNull(),
  privateKey: text('private_key'),
  publicKey: text('public_key'),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
})

export const ciphers = sqliteTable(
  'ciphers',
  {
    uuid: id(),
    userUuid: text('user_uuid').references(() => users.uuid, { onDelete: 'cascade' }),
    organizationUuid: text('organization_uuid').references(() => organizations.uuid, {
      onDelete: 'cascade',
    }),
    atype: integer('atype').notNull(),
    name: text('name').notNull(),
    notes: text('notes'),
    fields: text('fields'),
    data: text('data').notNull(),
    passwordHistory: text('password_history'),
    reprompt: integer('reprompt'),
    key: text('akey'),
    favorite: integer('favorite', { mode: 'boolean' }).notNull().default(false),
    deletedAt: integer('deleted_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('ciphers_user_idx').on(t.userUuid),
    index('ciphers_organization_idx').on(t.organizationUuid),
  ],
)

export const foldersCiphers = sqliteTable(
  'folders_ciphers',
  {
    cipherUuid: text('cipher_uuid')
      .notNull()
      .references(() => ciphers.uuid, { onDelete: 'cascade' }),
    folderUuid: text('folder_uuid')
      .notNull()
      .references(() => folders.uuid, { onDelete: 'cascade' }),
  },
  (t) => [
    primaryKey({ columns: [t.cipherUuid, t.folderUuid] }),
    index('folders_ciphers_folder_idx').on(t.folderUuid),
  ],
)

export const attachments = sqliteTable(
  'attachments',
  {
    id: text('id').primaryKey(),
    cipherUuid: text('cipher_uuid')
      .notNull()
      .references(() => ciphers.uuid, { onDelete: 'cascade' }),
    fileName: text('file_name').notNull(),
    fileSize: integer('file_size').notNull(),
    key: text('akey'),
    r2Key: text('r2_key').notNull(),
    /** Set once the blob is stored; rows without it are pending uploads. */
    uploadedAt: integer('uploaded_at'),
    /** Claim taken by an upload in progress; stops a second upload racing the first. */
    uploadStartedAt: integer('upload_started_at'),
    createdAt: createdAt(),
  },
  (t) => [index('attachments_cipher_idx').on(t.cipherUuid)],
)

export const usersOrganizations = sqliteTable(
  'users_organizations',
  {
    uuid: id(),
    // Null while an invited address has no account yet; set when the invitation is accepted.
    userUuid: text('user_uuid').references(() => users.uuid, { onDelete: 'cascade' }),
    organizationUuid: text('organization_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    email: text('email'),
    // JSON of custom permissions (role 4); null for other roles.
    permissions: text('permissions'),
    accessAll: integer('access_all', { mode: 'boolean' }).notNull().default(false),
    akey: text('akey').notNull(),
    status: integer('status').notNull(),
    atype: integer('atype').notNull(),
    resetPasswordKey: text('reset_password_key'),
    externalId: text('external_id'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex('users_organizations_user_org_unique').on(t.userUuid, t.organizationUuid),
    index('users_organizations_org_idx').on(t.organizationUuid),
    index('users_organizations_email_idx').on(t.email),
  ],
)

export const collections = sqliteTable(
  'collections',
  {
    uuid: id(),
    organizationUuid: text('organization_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    externalId: text('external_id'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [index('collections_organization_idx').on(t.organizationUuid)],
)

export const ciphersCollections = sqliteTable(
  'ciphers_collections',
  {
    cipherUuid: text('cipher_uuid')
      .notNull()
      .references(() => ciphers.uuid, { onDelete: 'cascade' }),
    collectionUuid: text('collection_uuid')
      .notNull()
      .references(() => collections.uuid, { onDelete: 'cascade' }),
  },
  (t) => [
    primaryKey({ columns: [t.cipherUuid, t.collectionUuid] }),
    index('ciphers_collections_collection_idx').on(t.collectionUuid),
  ],
)

export const usersCollections = sqliteTable(
  'users_collections',
  {
    organizationUserUuid: text('organization_user_uuid')
      .notNull()
      .references(() => usersOrganizations.uuid, { onDelete: 'cascade' }),
    collectionUuid: text('collection_uuid')
      .notNull()
      .references(() => collections.uuid, { onDelete: 'cascade' }),
    readOnly: integer('read_only', { mode: 'boolean' }).notNull().default(false),
    hidePasswords: integer('hide_passwords', { mode: 'boolean' }).notNull().default(false),
    manage: integer('manage', { mode: 'boolean' }).notNull().default(false),
  },
  (t) => [
    primaryKey({ columns: [t.organizationUserUuid, t.collectionUuid] }),
    index('users_collections_collection_idx').on(t.collectionUuid),
  ],
)

export const sends = sqliteTable(
  'sends',
  {
    uuid: id(),
    userUuid: text('user_uuid').references(() => users.uuid, { onDelete: 'cascade' }),
    organizationUuid: text('organization_uuid').references(() => organizations.uuid, {
      onDelete: 'cascade',
    }),
    name: text('name').notNull(),
    notes: text('notes'),
    atype: integer('atype').notNull(),
    data: text('data').notNull(),
    akey: text('akey').notNull(),
    passwordHash: text('password_hash'),
    passwordSalt: text('password_salt'),
    passwordIter: integer('password_iter'),
    maxAccessCount: integer('max_access_count'),
    accessCount: integer('access_count').notNull().default(0),
    disabled: integer('disabled', { mode: 'boolean' }).notNull().default(false),
    hideEmail: integer('hide_email', { mode: 'boolean' }),
    r2Key: text('r2_key'),
    /** File Sends only: set once the blob is stored. */
    uploadedAt: integer('uploaded_at'),
    uploadStartedAt: integer('upload_started_at'),
    expirationDate: integer('expiration_date'),
    deletionDate: integer('deletion_date').notNull(),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('sends_user_idx').on(t.userUuid),
    index('sends_organization_idx').on(t.organizationUuid),
    index('sends_deletion_date_idx').on(t.deletionDate),
  ],
)

export const twofactor = sqliteTable(
  'twofactor',
  {
    uuid: id(),
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    atype: integer('atype').notNull(),
    enabled: integer('enabled', { mode: 'boolean' }).notNull().default(true),
    data: text('data').notNull(),
    lastUsed: integer('last_used').notNull().default(0),
  },
  (t) => [uniqueIndex('twofactor_user_type_unique').on(t.userUuid, t.atype)],
)

export const events = sqliteTable(
  'events',
  {
    uuid: id(),
    eventType: integer('event_type').notNull(),
    userUuid: text('user_uuid'),
    organizationUuid: text('organization_uuid'),
    cipherUuid: text('cipher_uuid'),
    collectionUuid: text('collection_uuid'),
    groupUuid: text('group_uuid'),
    policyUuid: text('policy_uuid'),
    organizationUserUuid: text('organization_user_uuid'),
    actingUserUuid: text('acting_user_uuid'),
    deviceType: integer('device_type'),
    ipAddress: text('ip_address'),
    eventDate: integer('event_date').notNull(),
  },
  (t) => [
    index('events_organization_idx').on(t.organizationUuid),
    index('events_user_idx').on(t.userUuid),
    index('events_date_idx').on(t.eventDate),
  ],
)

export const policies = sqliteTable(
  'policies',
  {
    uuid: id(),
    organizationUuid: text('organization_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    atype: integer('atype').notNull(),
    enabled: integer('enabled', { mode: 'boolean' }).notNull().default(false),
    // JSON object with the policy settings, or null.
    data: text('data'),
    updatedAt: updatedAt(),
  },
  (t) => [uniqueIndex('policies_org_type_unique').on(t.organizationUuid, t.atype)],
)

export const groups = sqliteTable(
  'groups',
  {
    uuid: id(),
    organizationUuid: text('organization_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    accessAll: integer('access_all', { mode: 'boolean' }).notNull().default(false),
    externalId: text('external_id'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [index('groups_organization_idx').on(t.organizationUuid)],
)

export const groupsUsers = sqliteTable(
  'groups_users',
  {
    groupUuid: text('group_uuid')
      .notNull()
      .references(() => groups.uuid, { onDelete: 'cascade' }),
    organizationUserUuid: text('organization_user_uuid')
      .notNull()
      .references(() => usersOrganizations.uuid, { onDelete: 'cascade' }),
  },
  (t) => [
    primaryKey({ columns: [t.groupUuid, t.organizationUserUuid] }),
    index('groups_users_member_idx').on(t.organizationUserUuid),
  ],
)

export const collectionsGroups = sqliteTable(
  'collections_groups',
  {
    collectionUuid: text('collection_uuid')
      .notNull()
      .references(() => collections.uuid, { onDelete: 'cascade' }),
    groupUuid: text('group_uuid')
      .notNull()
      .references(() => groups.uuid, { onDelete: 'cascade' }),
    readOnly: integer('read_only', { mode: 'boolean' }).notNull().default(false),
    hidePasswords: integer('hide_passwords', { mode: 'boolean' }).notNull().default(false),
    manage: integer('manage', { mode: 'boolean' }).notNull().default(false),
  },
  (t) => [
    primaryKey({ columns: [t.collectionUuid, t.groupUuid] }),
    index('collections_groups_group_idx').on(t.groupUuid),
  ],
)

/** Emergency access grants. `status`: 0 invited, 1 accepted, 2 confirmed, 3 initiated, 4 approved. */
export const emergencyAccess = sqliteTable(
  'emergency_access',
  {
    uuid: id(),
    grantorUuid: text('grantor_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    granteeUuid: text('grantee_uuid').references(() => users.uuid, { onDelete: 'cascade' }),
    email: text('email').notNull(),
    // The grantor's user key encrypted to the grantee's public key (set on confirm).
    keyEncrypted: text('key_encrypted'),
    atype: integer('atype').notNull(),
    status: integer('status').notNull(),
    waitTimeDays: integer('wait_time_days').notNull(),
    recoveryInitiatedAt: integer('recovery_initiated_at'),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index('emergency_access_grantor_idx').on(t.grantorUuid),
    index('emergency_access_grantee_idx').on(t.granteeUuid),
  ],
)

// ---------------------------------------------------------------------------
// Admin UI and invites (TASKS #140). Kept in one block at the end of the file.
// ---------------------------------------------------------------------------

/** Single-use magic-link tokens. Only the SHA-256 hash of the token is stored. */
export const adminLoginTokens = sqliteTable(
  'admin_login_tokens',
  {
    tokenHash: text('token_hash').primaryKey(),
    email: text('email').notNull(),
    expiresAt: integer('expires_at').notNull(),
    usedAt: integer('used_at'),
    createdAt: createdAt(),
  },
  (t) => [index('admin_login_tokens_expires_idx').on(t.expiresAt)],
)

/** Admin sessions. Only the SHA-256 hash of the cookie value is stored. */
export const adminSessions = sqliteTable(
  'admin_sessions',
  {
    sessionHash: text('session_hash').primaryKey(),
    subject: text('subject').notNull(),
    csrfToken: text('csrf_token').notNull(),
    expiresAt: integer('expires_at').notNull(),
    createdAt: createdAt(),
  },
  (t) => [index('admin_sessions_expires_idx').on(t.expiresAt)],
)

/** Fixed-window counters for admin login throttling. */
export const adminRateLimits = sqliteTable(
  'admin_rate_limits',
  {
    key: text('key').notNull(),
    windowStart: integer('window_start').notNull(),
    count: integer('count').notNull().default(0),
  },
  (t) => [primaryKey({ columns: [t.key, t.windowStart] })],
)

/** Email invitations created by an admin. Registration gating (TASKS #22) consumes these. */
export const invitations = sqliteTable(
  'invitations',
  {
    uuid: id(),
    email: text('email').notNull(),
    invitedBy: text('invited_by').notNull(),
    createdAt: createdAt(),
  },
  (t) => [uniqueIndex('invitations_email_unique').on(t.email)],
)
