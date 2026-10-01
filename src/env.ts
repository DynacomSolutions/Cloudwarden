/** Worker bindings, vars and secrets. Mirrors `cloudflare.config.ts`. */
export interface Bindings {
  // Bindings
  DB: D1Database
  ATTACHMENTS: R2Bucket
  NOTIFICATIONS: DurableObjectNamespace

  // Vars
  DOMAIN: string
  SIGNUPS_ALLOWED: string
  ADMIN_ENABLED: string

  // Secrets (documented only, set with `cf secrets`)
  JWT_SECRET?: string
  ADMIN_TOKEN_HASH?: string
}

export type Env = { Bindings: Bindings }
