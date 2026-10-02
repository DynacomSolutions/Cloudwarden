// What the serving side accepts from a hosting peer (TASKS #304 review). Everything a peer sends
// into the replica is rebuilt from an allowlist and bound to the organisation the local user was
// invited to, so a peer can never inject SSO, Key Connector, recovery or other organisations' ids.
import { PERMISSION_KEYS, PolicyType } from '../orgs/constants'

export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
export const isUuid = (v: unknown): v is string => typeof v === 'string' && UUID.test(v)

/** Limits per user and peer. */
export const CAPS = {
  orgs: 50,
  collectionsPerOrg: 5000,
  ciphersPerOrg: 20000,
  cipherBytes: 1024 * 1024,
  policyBytes: 16 * 1024,
  stringBytes: 20000,
}

const str = (v: unknown, max = CAPS.stringBytes): string | null =>
  typeof v === 'string' && v.length <= max ? v : null
const bool = (v: unknown) => v === true
const int = (v: unknown, min: number, max: number, dflt: number) =>
  Number.isInteger(v) && (v as number) >= min && (v as number) <= max ? (v as number) : dflt

/** Feature flags a peer may switch; anything else is forced off below. */
const ALLOWED_FLAGS = [
  'usePolicies',
  'useGroups',
  'useEvents',
  'useTotp',
  'use2fa',
  'usePasswordManager',
  'useCustomPermissions',
  'useActivateAutofillPolicy',
  'usersGetPremium',
  'hasPublicAndPrivateKeys',
  'enabled',
  'limitCollectionCreation',
  'limitCollectionDeletion',
  'limitItemDeletion',
  'allowAdminAccessToAllCollectionItems',
] as const

const FORCED_FALSE = [
  'useDirectory',
  'useApi',
  'useResetPassword',
  'useSecretsManager',
  'usePam',
  'useRiskInsights',
  'usePhishingBlocker',
  'useMyItems',
  'useInviteLinks',
  'useSso',
  'useOrganizationDomains',
  'useKeyConnector',
  'useScim',
  'useAutomaticUserConfirmation',
  'useAdminSponsoredFamilies',
  'useDisableSMAdsForUsers',
  'ssoBound',
  'ssoEnabled',
  'keyConnectorEnabled',
  'resetPasswordEnrolled',
  'userIsClaimedByOrganization',
  'userIsManagedByOrganization',
  'isAdminInitiated',
  'familySponsorshipAvailable',
  'accessSecretsManager',
] as const

const FORCED_NULL = [
  'seats',
  'maxCollections',
  'maxStorageGb',
  'ssoMemberDecryptionType',
  'identifier',
  'providerId',
  'providerName',
  'providerType',
  'familySponsorshipFriendlyName',
  'keyConnectorUrl',
  'familySponsorshipLastSyncDate',
  'familySponsorshipValidUntil',
  'familySponsorshipToDelete',
] as const

/** The profile `organizations` entry, rebuilt for one bound organisation and local user. */
export function sanitizeProfile(raw: unknown, orgUuid: string, userUuid: string) {
  const p = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>
  const perms = (p.permissions && typeof p.permissions === 'object' ? p.permissions : {}) as Record<
    string,
    unknown
  >
  const out: Record<string, unknown> = {
    object: 'profileOrganization',
    id: orgUuid,
    name: str(p.name, 1024) ?? 'Organization',
    key: str(p.key),
    status: int(p.status, -1, 2, 1),
    type: int(p.type, 0, 4, 2),
    userId: userUuid,
    organizationUserId: isUuid(p.organizationUserId) ? p.organizationUserId : null,
    permissions: Object.fromEntries(PERMISSION_KEYS.map((k) => [k, bool(perms[k])])),
    selfHost: true,
    productTierType: 3,
  }
  // Recovery, SSO and SCIM permissions mean nothing for a member of another server.
  const outPerms = out.permissions as Record<string, boolean>
  outPerms.manageResetPassword = false
  outPerms.manageSso = false
  outPerms.manageScim = false
  for (const k of ALLOWED_FLAGS) out[k] = bool(p[k])
  for (const k of FORCED_FALSE) out[k] = false
  for (const k of FORCED_NULL) out[k] = null
  return out
}

/** Client-side policies that make sense for a federated member. */
export const ALLOWED_POLICY_TYPES = new Set<number>([
  PolicyType.MasterPassword,
  PolicyType.PasswordGenerator,
  PolicyType.PersonalOwnership,
  PolicyType.DisableSend,
  PolicyType.SendOptions,
  PolicyType.MaximumVaultTimeout,
  PolicyType.DisablePersonalVaultExport,
])

export function sanitizePolicies(raw: unknown, orgUuid: string) {
  if (!Array.isArray(raw)) return []
  const out: Record<string, unknown>[] = []
  for (const r of raw.slice(0, 64)) {
    const p = (r ?? {}) as Record<string, unknown>
    if (!isUuid(p.id) || p.organizationId !== orgUuid) continue
    if (!Number.isInteger(p.type) || !ALLOWED_POLICY_TYPES.has(p.type as number)) continue
    const data =
      p.data && typeof p.data === 'object' && JSON.stringify(p.data).length <= CAPS.policyBytes
        ? p.data
        : null
    out.push({
      object: 'policy',
      id: p.id,
      organizationId: orgUuid,
      type: p.type,
      data,
      enabled: bool(p.enabled),
      canToggleState: false,
      revisionDate: str(p.revisionDate, 64),
    })
  }
  return out
}

export function sanitizeCollections(raw: unknown, orgUuid: string) {
  if (!Array.isArray(raw)) return []
  const out: Record<string, unknown>[] = []
  for (const r of raw.slice(0, CAPS.collectionsPerOrg)) {
    const c = (r ?? {}) as Record<string, unknown>
    if (!isUuid(c.id)) continue
    out.push({
      object: 'collectionDetails',
      id: c.id,
      organizationId: orgUuid,
      name: str(c.name) ?? '',
      externalId: null,
      defaultUserCollectionEmail: null,
      type: 0,
      readOnly: bool(c.readOnly),
      hidePasswords: bool(c.hidePasswords),
      manage: bool(c.manage),
    })
  }
  return out
}

/** Top-level fields of a cipher view the serving side keeps; anything else is dropped. */
const CIPHER_FIELDS = [
  'type',
  'name',
  'notes',
  'fields',
  'login',
  'card',
  'identity',
  'secureNote',
  'sshKey',
  'data',
  'favorite',
  'reprompt',
  'key',
  'revisionDate',
  'creationDate',
  'deletedDate',
  'archivedDate',
  'passwordHistory',
  'organizationUseTotp',
  'edit',
  'viewPassword',
  'permissions',
] as const

/**
 * A cipher view: its id, organisation and collections must be the bound ones, only known fields
 * are kept, and attachment links must point at the hosting peer's download route (they are then
 * rewritten to this server's relay); any other link is dropped.
 */
export function sanitizeCipher(
  raw: unknown,
  orgUuid: string,
  collectionIds: Set<string>,
  peerDomain: string,
): Record<string, unknown> | null {
  if (!raw || typeof raw !== 'object') return null
  const c = raw as Record<string, unknown>
  if (!isUuid(c.id) || c.organizationId !== orgUuid) return null
  const out: Record<string, unknown> = {
    object:
      typeof c.object === 'string' && c.object.startsWith('cipher') ? c.object : 'cipherDetails',
    id: c.id,
    organizationId: orgUuid,
    folderId: null,
    collectionIds: Array.isArray(c.collectionIds)
      ? c.collectionIds.filter((x): x is string => isUuid(x) && collectionIds.has(x))
      : [],
  }
  for (const k of CIPHER_FIELDS) if (k in c) out[k] = c[k]
  const prefix = `https://${peerDomain}/attachments/${c.id}/`
  out.attachments = Array.isArray(c.attachments)
    ? c.attachments.slice(0, 100).flatMap((a) => {
        const at = (a ?? {}) as Record<string, unknown>
        if (typeof at.id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(at.id)) return []
        const url =
          typeof at.url === 'string' && at.url.startsWith(`${prefix}${at.id}?`) ? at.url : null
        return [
          {
            object: 'attachment',
            id: at.id,
            url,
            fileName: str(at.fileName),
            key: str(at.key),
            size: str(at.size, 32),
            sizeName: str(at.sizeName, 32),
          },
        ]
      })
    : null
  return JSON.stringify(out).length <= CAPS.cipherBytes ? out : null
}
