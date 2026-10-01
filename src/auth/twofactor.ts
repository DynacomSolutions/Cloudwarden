import type { Context } from 'hono'
import type { Env, User } from '../env'

/**
 * Hook for second-factor enforcement (TASKS #120 and later).
 * Called by the token endpoint after the primary credential is verified and before any
 * token is issued. Return a Response (for example the Bitwarden two-factor challenge) to
 * stop the login, or null to continue. Phase 1 has no second factors, so it continues.
 */
export type TwoFactorHook = (
  c: Context<Env>,
  user: User,
  form: Record<string, string>,
) => Promise<Response | null>

export const enforceTwoFactor: TwoFactorHook = async () => null
