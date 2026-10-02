// Stand-in accounts (federated members on the hosting side, TASKS #303). Kept free of imports so
// the auth layer can use it without a cycle.

/** Prefix of the stand-in account's password hash: never a PBKDF2 output, so never matches. */
export const STAND_IN_HASH_PREFIX = '!federated.'
/** `client_id` of the access tokens minted in-process for forwarded federation requests. */
export const FEDERATION_CLIENT_ID = 'cloudwarden-federation'

export const isStandInUser = (u: { passwordHash: string }) =>
  u.passwordHash.startsWith(STAND_IN_HASH_PREFIX)
