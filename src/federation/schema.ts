// Federated organisations (TASKS #300 to #309, docs/federation.md). Re-exported by src/db/schema.ts
// so drizzle-kit and `schema.*` see these tables; kept here so federation stays in its own module.
import { index, integer, primaryKey, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core'
import { collections, folders, organizations, users, usersOrganizations } from '../db/schema'

/** This instance's signing identity. One row, id `self`; the private key is encrypted at rest. */
export const federationIdentity = sqliteTable('federation_identity', {
  id: text('id').primaryKey(),
  instanceId: text('instance_id').notNull(),
  publicKey: text('public_key').notNull(),
  privateKeyEnc: text('private_key_enc').notNull(),
  createdAt: integer('created_at').notNull(),
})

/**
 * A paired (or pairing) instance. `localApproved` is this side's admin decision after checking the
 * fingerprint; `remoteApproved` is set when the peer's signed pairing request arrives.
 */
export const federationPeers = sqliteTable(
  'federation_peers',
  {
    uuid: text('uuid').primaryKey(),
    instanceId: text('instance_id').notNull(),
    domain: text('domain').notNull(),
    publicKey: text('public_key').notNull(),
    fingerprint: text('fingerprint').notNull(),
    protocolVersion: integer('protocol_version').notNull(),
    /** `pending`, `active` or `suspended`. */
    status: text('status').notNull(),
    localApproved: integer('local_approved', { mode: 'boolean' }).notNull().default(false),
    remoteApproved: integer('remote_approved', { mode: 'boolean' }).notNull().default(false),
    lastSeenAt: integer('last_seen_at'),
    lastError: text('last_error'),
    /** User who asked for this peer from a collection's Access dialog (a non-admin request), if any. */
    requestedBy: text('requested_by'),
    /** True when this side trusted the peer without an admin step (an incoming pairing request). */
    acceptedAutomatically: integer('accepted_automatically', { mode: 'boolean' })
      .notNull()
      .default(false),
    /** Instance admin who approved the peer on this side, when an admin did. */
    approvedBy: text('approved_by'),
    /** Created by an incoming signed pairing request (as opposed to added by an admin or user). */
    incoming: integer('incoming', { mode: 'boolean' }).notNull().default(false),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (t) => [
    uniqueIndex('federation_peers_instance_unique').on(t.instanceId),
    uniqueIndex('federation_peers_domain_unique').on(t.domain),
  ],
)

/**
 * Rules an admin set to refuse peers (TASKS #381). `domain` holds the value: a host name, a suffix
 * pattern such as `*.example.net` (the name and everything under it), `instance:<id>` or
 * `fp:<64 hex>`. `kind` is `domain`, `instance` or `fingerprint`.
 */
export const federationBlockedDomains = sqliteTable('federation_blocked_domains', {
  domain: text('domain').primaryKey(),
  kind: text('kind').notNull().default('domain'),
  createdAt: integer('created_at').notNull(),
  createdBy: text('created_by'),
})

/** Domains an admin removed without blocking: their next incoming pairing request waits for approval. */
export const federationRemovedDomains = sqliteTable('federation_removed_domains', {
  domain: text('domain').primaryKey(),
  removedAt: integer('removed_at').notNull(),
})

/** Signature nonces seen recently, per peer; a repeat is a replay. */
export const federationNonces = sqliteTable(
  'federation_nonces',
  {
    peerUuid: text('peer_uuid')
      .notNull()
      .references(() => federationPeers.uuid, { onDelete: 'cascade' }),
    nonce: text('nonce').notNull(),
    expiresAt: integer('expires_at').notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.peerUuid, t.nonce] }),
    index('federation_nonces_expires_idx').on(t.expiresAt),
  ],
)

// ----- Hosting side (the instance that owns the organisation) -----

/**
 * Local stand-in account for a user of a peer. Its uuid equals the user's id on the peer so the
 * fingerprint phrase matches; it has no usable password and is only reachable through the peer.
 */
export const federationShadowUsers = sqliteTable(
  'federation_shadow_users',
  {
    userUuid: text('user_uuid')
      .primaryKey()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    peerUuid: text('peer_uuid')
      .notNull()
      .references(() => federationPeers.uuid, { onDelete: 'cascade' }),
    remoteEmail: text('remote_email').notNull(),
    createdAt: integer('created_at').notNull(),
  },
  (t) => [index('federation_shadow_users_peer_idx').on(t.peerUuid)],
)

/** Which organisation memberships belong to a peer's user (invited, accepted or confirmed). */
export const federationMembers = sqliteTable(
  'federation_members',
  {
    organizationUserUuid: text('organization_user_uuid')
      .primaryKey()
      .references(() => usersOrganizations.uuid, { onDelete: 'cascade' }),
    peerUuid: text('peer_uuid')
      .notNull()
      .references(() => federationPeers.uuid, { onDelete: 'cascade' }),
    remoteEmail: text('remote_email').notNull(),
    remoteUserUuid: text('remote_user_uuid'),
    /** Created by the collection sharing flow (TASKS #377): only these may be purged by a collection manager. */
    createdViaShare: integer('created_via_share', { mode: 'boolean' }).notNull().default(false),
    createdAt: integer('created_at').notNull(),
  },
  (t) => [index('federation_members_peer_idx').on(t.peerUuid)],
)

// ----- Serving side (the instance where the federated user has their account) -----

/** An invitation from a peer's organisation to a local user. */
export const federationInvitations = sqliteTable(
  'federation_invitations',
  {
    uuid: text('uuid').primaryKey(),
    peerUuid: text('peer_uuid')
      .notNull()
      .references(() => federationPeers.uuid, { onDelete: 'cascade' }),
    /** The organisation user id on the hosting instance. */
    remoteMemberUuid: text('remote_member_uuid').notNull(),
    organizationUuid: text('organization_uuid').notNull(),
    organizationName: text('organization_name').notNull(),
    inviterEmail: text('inviter_email'),
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    /** `pending`, `accepted` or `declined`. */
    status: text('status').notNull(),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (t) => [
    uniqueIndex('federation_invitations_remote_unique').on(t.peerUuid, t.remoteMemberUuid),
    index('federation_invitations_user_idx').on(t.userUuid),
  ],
)

/** Replica of a federated organisation as seen by one local user. JSON is as the hosting side sent it. */
export const federationReplicaOrgs = sqliteTable(
  'federation_replica_orgs',
  {
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    organizationUuid: text('organization_uuid').notNull(),
    peerUuid: text('peer_uuid')
      .notNull()
      .references(() => federationPeers.uuid, { onDelete: 'cascade' }),
    profileJson: text('profile_json').notNull(),
    collectionsJson: text('collections_json').notNull(),
    policiesJson: text('policies_json').notNull(),
    revisionDate: integer('revision_date').notNull(),
    syncedAt: integer('synced_at').notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.userUuid, t.organizationUuid] }),
    index('federation_replica_orgs_peer_idx').on(t.peerUuid),
  ],
)

export const federationReplicaCiphers = sqliteTable(
  'federation_replica_ciphers',
  {
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    cipherUuid: text('cipher_uuid').notNull(),
    organizationUuid: text('organization_uuid').notNull(),
    json: text('json').notNull(),
    digest: text('digest').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.userUuid, t.cipherUuid] }),
    index('federation_replica_ciphers_org_idx').on(t.userUuid, t.organizationUuid),
  ],
)

/** The local user's own folder for a federated item; folders never leave the serving instance. */
export const federationItemFolders = sqliteTable(
  'federation_item_folders',
  {
    userUuid: text('user_uuid')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    cipherUuid: text('cipher_uuid').notNull(),
    folderUuid: text('folder_uuid')
      .notNull()
      .references(() => folders.uuid, { onDelete: 'cascade' }),
  },
  (t) => [primaryKey({ columns: [t.userUuid, t.cipherUuid] })],
)

/**
 * Shares queued while the workspace awaits an instance admin's approval (TASKS #382). Nothing is
 * sent to the peer until the workspace is active; then each row is re-checked and either becomes
 * a normal federated invitation (the row is deleted) or is kept as `dropped`. When the request is
 * declined or expires the rows stay as `declined` or `expired` so the requester can see what
 * happened. No foreign key to the peer: the peer row is deleted in those cases.
 */
export const federationQueuedShares = sqliteTable(
  'federation_queued_shares',
  {
    uuid: text('uuid').primaryKey(),
    peerUuid: text('peer_uuid').notNull(),
    peerDomain: text('peer_domain').notNull(),
    organizationUuid: text('organization_uuid')
      .notNull()
      .references(() => organizations.uuid, { onDelete: 'cascade' }),
    collectionUuid: text('collection_uuid')
      .notNull()
      .references(() => collections.uuid, { onDelete: 'cascade' }),
    email: text('email').notNull(),
    readOnly: integer('read_only', { mode: 'boolean' }).notNull().default(false),
    hidePasswords: integer('hide_passwords', { mode: 'boolean' }).notNull().default(false),
    manage: integer('manage', { mode: 'boolean' }).notNull().default(false),
    /** The user who queued it; the invitation is sent as them, if they still may. */
    requestedBy: text('requested_by')
      .notNull()
      .references(() => users.uuid, { onDelete: 'cascade' }),
    /** `queued`, `retry`, `declined`, `expired` or `dropped`. */
    status: text('status').notNull(),
    note: text('note'),
    /** Failed sends that may succeed later (`retry`); the item is dropped after a few. */
    attempts: integer('attempts').notNull().default(0),
    createdAt: integer('created_at').notNull(),
    updatedAt: integer('updated_at').notNull(),
  },
  (t) => [
    index('federation_queued_shares_peer_idx').on(t.peerUuid),
    index('federation_queued_shares_collection_idx').on(t.collectionUuid),
    uniqueIndex('federation_queued_shares_unique').on(t.peerUuid, t.collectionUuid, t.email),
  ],
)
