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
  AutomaticUserConfirmation: 18,
} as const

/** Event codes used on the wire by the official clients. */
export const EventType = {
  UserUpdatedTempPassword: 1008,
  UserRequestedDeviceApproval: 1010,
  CipherCreated: 1100,
  CipherUpdated: 1101,
  CipherDeleted: 1102,
  CipherAttachmentDeleted: 1104,
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
  OrganizationUserResetPasswordEnroll: 1506,
  OrganizationUserResetPasswordWithdraw: 1507,
  OrganizationUserAdminResetPassword: 1508,
  OrganizationUserRevoked: 1511,
  OrganizationUserRestored: 1512,
  OrganizationUserApprovedAuthRequest: 1513,
  OrganizationUserRejectedAuthRequest: 1514,
  OrganizationUserAdminResetTwoFactor: 1519,
  OrganizationUpdated: 1600,
  PolicyUpdated: 1700,
  // Secrets Manager (TASKS #220).
  SecretRetrieved: 2100,
  SecretCreated: 2101,
  SecretEdited: 2102,
  SecretDeleted: 2103,
  SecretPermanentlyDeleted: 2104,
  SecretRestored: 2105,
  ProjectCreated: 2201,
  ProjectEdited: 2202,
  ProjectDeleted: 2203,
  ServiceAccountUserAdded: 2300,
  ServiceAccountUserRemoved: 2301,
  ServiceAccountGroupAdded: 2302,
  ServiceAccountGroupRemoved: 2303,
  ServiceAccountCreated: 2304,
  ServiceAccountDeleted: 2305,
} as const

/** `systemUser` of events raised without a member acting (TASKS #270). */
export const EventSystemUser = { Scim: 1, DomainVerification: 2, PublicApi: 3 } as const

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
  PushSettingsUpdated: 9009,
  PushSettingsRemoved: 9010,
  PushSettingsTested: 9011,
} as const

/** Range of admin audit codes; user event feeds must exclude it. */
export const ADMIN_EVENT_MIN = 9001
export const ADMIN_EVENT_MAX = 9011
