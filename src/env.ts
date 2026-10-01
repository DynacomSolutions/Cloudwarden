import type { users } from './db/schema'

/** Worker bindings, vars and secrets. Mirrors `cloudflare.config.ts`. */
export interface Bindings {
  // Bindings
  DB: D1Database
  ATTACHMENTS: R2Bucket
  NOTIFICATIONS: DurableObjectNamespace
  /** Cloudflare Email Service `send_email` binding. Optional: absent means no mail is sent. */
  EMAIL?: SendEmail
  /** Workers Rate Limiting binding. When unbound, rate limiting is skipped. */
  LOGIN_LIMITER?: RateLimit

  // Vars
  DOMAIN: string
  SIGNUPS_ALLOWED: string
  /** Comma-separated domains (or full addresses) that may register when signups are closed. */
  SIGNUPS_DOMAINS_WHITELIST?: string
  ADMIN_ENABLED: string
  /** Sender address for outgoing mail, for example `Cloudwarden <noreply@example.com>`. */
  MAIL_FROM?: string

  // Secrets (documented only, set with `cf secrets`)
  /** HS256 signing secret, at least 32 characters. */
  JWT_SECRET?: string
  /** Previous signing secret, accepted for verification only while rotating. */
  JWT_SECRET_PREVIOUS?: string
  ADMIN_TOKEN_HASH?: string
  /** Comma-separated admin email addresses allowed to request a magic link. */
  ADMIN_EMAILS?: string
}

export type User = typeof users.$inferSelect

/** Access token claims placed on the request by `requireAuth`. */
export interface AccessTokenClaims {
  nbf: number
  exp: number
  iss: string
  sub: string
  email: string
  name: string
  premium: boolean
  email_verified: boolean
  sstamp: string
  device: string
  scope: string[]
  amr: string[]
  client_id?: string
}

export interface AuthContext {
  claims: AccessTokenClaims
  /** Client-chosen device identifier from the token. */
  deviceIdentifier: string
}

/** Values set on the Hono context by `requireAuth`. */
export interface Variables {
  user: User
  auth: AuthContext
}

export type Env = { Bindings: Bindings; Variables: Variables }
