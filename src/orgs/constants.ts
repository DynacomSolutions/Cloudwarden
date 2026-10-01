/** Member roles. Manager (3) is legacy and treated like User with assigned collections. */
export const Role = { Owner: 0, Admin: 1, User: 2, Manager: 3, Custom: 4 } as const

/** Membership status. */
export const Status = { Revoked: -1, Invited: 0, Accepted: 1, Confirmed: 2 } as const

export const PolicyType = {
  TwoFactorAuthentication: 0,
  MasterPassword: 1,
  PasswordGenerator: 2,
  SingleOrg: 3,
  RequireSso: 4,
  PersonalOwnership: 5,
  DisableSend: 6,
  SendOptions: 7,
  ResetPassword: 8,
  MaximumVaultTimeout: 9,
  DisablePersonalVaultExport: 10,
} as const

/** Event codes used on the wire by the official clients. */
export const EventType = {
  CipherCreated: 1100,
  CipherUpdated: 1101,
  CipherDeleted: 1102,
  CipherShared: 1105,
  CipherUpdatedCollections: 1106,
  CipherSoftDeleted: 1115,
  CipherRestored: 1116,
  CollectionCreated: 1300,
  CollectionUpdated: 1301,
  CollectionDeleted: 1302,
  GroupCreated: 1400,
  GroupUpdated: 1401,
  GroupDeleted: 1402,
  OrganizationUserInvited: 1500,
  OrganizationUserConfirmed: 1501,
  OrganizationUserUpdated: 1502,
  OrganizationUserRemoved: 1503,
  OrganizationUserUpdatedGroups: 1504,
  OrganizationUserRevoked: 1511,
  OrganizationUserRestored: 1512,
  OrganizationUpdated: 1600,
  PolicyUpdated: 1700,
} as const

export const PERMISSION_KEYS = [
  'accessEventLogs',
  'accessImportExport',
  'accessReports',
  'createNewCollections',
  'editAnyCollection',
  'deleteAnyCollection',
  'manageCiphers',
  'manageGroups',
  'manageSso',
  'managePolicies',
  'manageUsers',
  'manageResetPassword',
  'manageScim',
] as const

/**
 * Event codes for admin actions. They sit outside the range used by the official clients
 * (which ignore unknown codes), so they never collide with organisation event types.
 */
export const AdminEventType = {
  UserDisabled: 9001,
  UserEnabled: 9002,
  UserDeauthorized: 9003,
  UserTwoFactorRemoved: 9004,
  UserDeleted: 9005,
  InvitationCreated: 9006,
  InvitationDeleted: 9007,
  OrganizationDeleted: 9008,
} as const

/** Range of admin audit codes; user event feeds must exclude it. */
export const ADMIN_EVENT_MIN = 9001
export const ADMIN_EVENT_MAX = 9008
