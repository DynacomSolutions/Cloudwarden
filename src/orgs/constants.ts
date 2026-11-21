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
  UserLoggedIn: 1000,
  UserChangedPassword: 1001,
  UserUpdated2fa: 1002,
  UserDisabled2fa: 1003,
  UserRecovered2fa: 1004,
  UserFailedLogIn: 1005,
  UserFailedLogIn2fa: 1006,
  UserClientExportedVault: 1007,
  UserUpdatedTempPassword: 1008,
  UserRequestedDeviceApproval: 1010,
  UserTdeOffboardingPasswordSet: 1011,
  CipherCreated: 1100,
  CipherUpdated: 1101,
  CipherDeleted: 1102,
  CipherAttachmentCreated: 1103,
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
  OrganizationUserDeleted: 1515,
  OrganizationUserLeft: 1516,
  OrganizationUserAutomaticallyConfirmed: 1517,
  OrganizationUserSelfRevoked: 1518,
  OrganizationUserAdminResetTwoFactor: 1519,
  OrganizationUserRevokedTwoFactorNonCompliance: 1520,
  OrganizationUserInviteLinkAccepted: 1524,
  OrganizationUserInviteLinkConfirmed: 1526,
  OrganizationUpdated: 1600,
  OrganizationPurgedVault: 1601,
  OrganizationVaultAccessed: 1603,
  OrganizationCollectionManagementUpdated: 1609,
  OrganizationLimitCollectionCreationEnabled: 1610,
  OrganizationLimitCollectionCreationDisabled: 1611,
  OrganizationLimitCollectionDeletionEnabled: 1612,
  OrganizationLimitCollectionDeletionDisabled: 1613,
  OrganizationLimitItemDeletionEnabled: 1614,
  OrganizationLimitItemDeletionDisabled: 1615,
  OrganizationAllowAdminAccessToAllCollectionItemsEnabled: 1616,
  OrganizationAllowAdminAccessToAllCollectionItemsDisabled: 1617,
  OrganizationAutoConfirmEnabledAdmin: 1620,
  OrganizationAutoConfirmDisabledAdmin: 1621,
  OrganizationInviteLinkCreated: 1624,
  OrganizationInviteLinkDomainsEdited: 1625,
  OrganizationInviteLinkDeleted: 1626,
  OrganizationInviteLinkRefreshed: 1628,
  OrganizationInviteLinkConfirmEnabled: 1629,
  OrganizationInviteLinkConfirmDisabled: 1630,
  PolicyUpdated: 1700,
  SendCreatedText: 2500,
  SendCreatedTextWithEmailVerification: 2501,
  SendCreatedTextWithPasswordProtection: 2502,
  SendCreatedFile: 2503,
  SendCreatedFileWithEmailVerification: 2504,
  SendCreatedFileWithPasswordProtection: 2505,
  SendEditedText: 2506,
  SendEditedFile: 2507,
  SendDeletedText: 2508,
  SendDeletedFile: 2509,
  SendAccessedText: 2510,
  SendAccessedFile: 2511,
  // Secrets Manager (TASKS #220).
  SecretRetrieved: 2100,
  SecretCreated: 2101,
  SecretEdited: 2102,
  SecretDeleted: 2103,
  SecretPermanentlyDeleted: 2104,
  SecretRestored: 2105,
  ProjectRetrieved: 2200,
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
  'manageAccessRules',
] as const

/**
 * The custom permissions the Public API reads and writes. `manageCiphers` is an older
 * Cloudwarden key that the published Public API model does not have, so it stays internal.
 */
export const PUBLIC_PERMISSION_KEYS = [
  'accessEventLogs',
  'accessImportExport',
  'accessReports',
  'createNewCollections',
  'editAnyCollection',
  'deleteAnyCollection',
  'manageGroups',
  'managePolicies',
  'manageSso',
  'manageUsers',
  'manageResetPassword',
  'manageScim',
  'manageAccessRules',
] as const

/** Highest policy type of the published Public API (FillAssist). */
export const MAX_POLICY_TYPE = 22

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
  WebPushSettingsUpdated: 9012,
  UserRoleChanged: 9013,
  SsoRateLimitUpdated: 9014,
} as const

/** Range of admin audit codes; user event feeds must exclude it. */
export const ADMIN_EVENT_MIN = 9001
export const ADMIN_EVENT_MAX = 9014
