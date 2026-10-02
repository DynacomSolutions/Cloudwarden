import { eq } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'
import { type Access, type Member, storedPermissions } from './access'
import { Status } from './constants'

export type OrgRow = typeof schema.organizations.$inferSelect

/** Plan and feature flags: every organisation behaves like a self-hosted enterprise one. */
const FEATURES = {
  useGroups: true,
  // Directory Connector and the Public API (TASKS #261, #262).
  useDirectory: true,
  useEvents: true,
  useTotp: true,
  use2fa: true,
  useApi: true,
  useResetPassword: false,
  // Secrets Manager API (TASKS #220); members still need `accessSecretsManager`.
  useSecretsManager: true,
  usePasswordManager: true,
  usePam: false,
  useRiskInsights: false,
  usePhishingBlocker: false,
  useMyItems: false,
  useInviteLinks: false,
}

export const orgJson = (o: OrgRow) => ({
  object: 'organization',
  id: o.uuid,
  name: o.name,
  businessName: null,
  businessAddress1: null,
  businessAddress2: null,
  businessAddress3: null,
  businessCountry: null,
  businessTaxNumber: null,
  billingEmail: o.billingEmail,
  planType: 0,
  seats: null,
  maxAutoscaleSeats: null,
  maxCollections: null,
  maxStorageGb: null,
  ...FEATURES,
  hasPublicAndPrivateKeys: Boolean(o.publicKey && o.privateKey),
  limitCollectionCreation: true,
  limitCollectionDeletion: true,
  limitItemDeletion: false,
  allowAdminAccessToAllCollectionItems: true,
})

/** One entry of the profile `organizations` array. */
export const profileOrgJson = (o: OrgRow, m: Member) => ({
  object: 'profileOrganization',
  id: o.uuid,
  name: o.name,
  usePolicies: true,
  ...FEATURES,
  useSso: false,
  useOrganizationDomains: false,
  useKeyConnector: false,
  useScim: true,
  useCustomPermissions: true,
  useActivateAutofillPolicy: true,
  useAutomaticUserConfirmation: false,
  useAdminSponsoredFamilies: false,
  useDisableSMAdsForUsers: false,
  selfHost: true,
  usersGetPremium: true,
  seats: null,
  maxCollections: null,
  maxStorageGb: null,
  key: m.akey === '' ? null : m.akey,
  hasPublicAndPrivateKeys: Boolean(o.publicKey && o.privateKey),
  status: m.status,
  type: m.atype,
  enabled: true,
  ssoBound: false,
  ssoEnabled: false,
  ssoMemberDecryptionType: null,
  identifier: null,
  permissions: storedPermissions(m),
  resetPasswordEnrolled: m.resetPasswordKey !== null,
  userId: m.userUuid,
  organizationUserId: m.uuid,
  providerId: null,
  providerName: null,
  providerType: null,
  familySponsorshipFriendlyName: null,
  familySponsorshipAvailable: false,
  productTierType: 3,
  keyConnectorEnabled: false,
  keyConnectorUrl: null,
  familySponsorshipLastSyncDate: null,
  familySponsorshipValidUntil: null,
  familySponsorshipToDelete: null,
  accessSecretsManager: m.accessSecretsManager,
  limitCollectionCreation: true,
  limitCollectionDeletion: true,
  limitItemDeletion: false,
  allowAdminAccessToAllCollectionItems: true,
  userIsClaimedByOrganization: false,
  isAdminInitiated: false,
})

/** Memberships shown in the profile: accepted, confirmed and revoked (invites are not). */
export async function profileOrganizations(db: Db, userUuid: string) {
  const rows = await db
    .select({ o: schema.organizations, m: schema.usersOrganizations })
    .from(schema.usersOrganizations)
    .innerJoin(
      schema.organizations,
      eq(schema.organizations.uuid, schema.usersOrganizations.organizationUuid),
    )
    .where(eq(schema.usersOrganizations.userUuid, userUuid))
  return rows.filter((r) => r.m.status !== Status.Invited).map((r) => profileOrgJson(r.o, r.m))
}

export const selectionJson = (id: string, a: Access) => ({
  id,
  readOnly: a.readOnly,
  hidePasswords: a.hidePasswords,
  manage: a.manage,
})

export const collectionJson = (c: typeof schema.collections.$inferSelect) => ({
  object: 'collection',
  id: c.uuid,
  organizationId: c.organizationUuid,
  name: c.name,
  externalId: c.externalId,
  defaultUserCollectionEmail: null,
  type: 0,
})

export const collectionDetailsJson = (c: typeof schema.collections.$inferSelect, a: Access) => ({
  ...collectionJson(c),
  object: 'collectionDetails',
  readOnly: a.readOnly,
  hidePasswords: a.hidePasswords,
  manage: a.manage,
})

export const groupJson = (g: typeof schema.groups.$inferSelect) => ({
  object: 'group',
  id: g.uuid,
  organizationId: g.organizationUuid,
  name: g.name,
  accessAll: g.accessAll,
  externalId: g.externalId,
})
