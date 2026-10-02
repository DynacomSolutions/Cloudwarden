import { eq, inArray } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'
import { MemberDecryptionType, parseConfigData } from '../sso/config'
import { type Access, type Member, storedPermissions } from './access'
import { Status } from './constants'
import { emailDomain, verifiedDomains } from './domains'

export type OrgRow = typeof schema.organizations.$inferSelect

/** Plan and feature flags: every organisation behaves like a self-hosted enterprise one. */
const FEATURES = {
  useGroups: true,
  // Directory Connector and the Public API (TASKS #271, #272).
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
  // Single sign-on, key connector and claimed domains (TASKS #280 to #286).
  useSso: true,
  useKeyConnector: true,
  useOrganizationDomains: true,
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
  identifier: o.identifier,
})

/** SSO facts about one membership, for the profile (TASKS #280 to #286). */
export interface ProfileSso {
  ssoEnabled: boolean
  memberDecryptionType: number | null
  keyConnectorUrl: string | null
  ssoBound: boolean
  claimed: boolean
}

const NO_SSO: ProfileSso = {
  ssoEnabled: false,
  memberDecryptionType: null,
  keyConnectorUrl: null,
  ssoBound: false,
  claimed: false,
}

/** One entry of the profile `organizations` array. */
export const profileOrgJson = (o: OrgRow, m: Member, sso: ProfileSso = NO_SSO) => ({
  object: 'profileOrganization',
  id: o.uuid,
  name: o.name,
  usePolicies: true,
  ...FEATURES,
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
  ssoBound: sso.ssoBound,
  ssoEnabled: sso.ssoEnabled,
  ssoMemberDecryptionType: sso.memberDecryptionType,
  identifier: o.identifier,
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
  keyConnectorEnabled: sso.keyConnectorUrl !== null,
  keyConnectorUrl: sso.keyConnectorUrl,
  familySponsorshipLastSyncDate: null,
  familySponsorshipValidUntil: null,
  familySponsorshipToDelete: null,
  accessSecretsManager: m.accessSecretsManager,
  limitCollectionCreation: true,
  limitCollectionDeletion: true,
  limitItemDeletion: false,
  allowAdminAccessToAllCollectionItems: true,
  userIsClaimedByOrganization: sso.claimed,
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
  const visible = rows.filter((r) => r.m.status !== Status.Invited)
  if (visible.length === 0) return []
  const orgIds = visible.map((r) => r.o.uuid)
  const [configs, links, user] = await Promise.all([
    db.select().from(schema.ssoConfigs).where(inArray(schema.ssoConfigs.organizationUuid, orgIds)),
    db
      .select({ org: schema.ssoUsers.organizationUuid })
      .from(schema.ssoUsers)
      .where(eq(schema.ssoUsers.userUuid, userUuid)),
    db
      .select({ email: schema.users.email })
      .from(schema.users)
      .where(eq(schema.users.uuid, userUuid))
      .limit(1),
  ])
  const domains = await verifiedDomains(db, orgIds)
  const userDomain = emailDomain(user[0]?.email ?? '')
  const linked = new Set(links.map((l) => l.org))
  return visible.map((r) => {
    const cfg = configs.find((x) => x.organizationUuid === r.o.uuid)
    const data = cfg ? parseConfigData(cfg) : null
    const enabled = cfg?.enabled === true
    const kc = enabled && data?.memberDecryptionType === MemberDecryptionType.KeyConnector
    return profileOrgJson(r.o, r.m, {
      ssoEnabled: enabled,
      memberDecryptionType: enabled ? (data?.memberDecryptionType ?? 0) : null,
      keyConnectorUrl: kc ? (data?.keyConnectorUrl ?? null) : null,
      ssoBound: linked.has(r.o.uuid),
      claimed: r.m.status !== Status.Revoked && (domains.get(r.o.uuid)?.has(userDomain) ?? false),
    })
  })
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
