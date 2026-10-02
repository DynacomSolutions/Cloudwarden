import type { users } from './db/schema'

/** Worker bindings, vars and secrets. Mirrors `cloudflare.config.ts`. */
export interface Bindings {
  // Bindings
  DB: D1Database
  ATTACHMENTS: R2Bucket
  /** Set by the D1 sessions middleware: the plain binding, which always reads the primary. */
  DB_PRIMARY?: D1Database
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
  /** Icon proxy switch; anything other than 'false' enables it (TASKS #142). */
  ICONS_ENABLED?: string
  /** `true` runs requests on D1 sessions with a bookmark header (TASKS #165). Default off. */
  D1_SESSIONS?: string
  /** Minimum log level: debug, info (default), warn or error (TASKS #164). */
  LOG_LEVEL?: string
  /** Build commit hash reported by /api/config. Optional. */
  GIT_HASH?: string
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

/** Machine account access token claims (Secrets Manager, TASKS #220). */
export interface MachineTokenClaims {
  nbf: number
  exp: number
  iss: string
  /** Machine account (service account) id. */
  sub: string
  /** Organisation the machine account belongs to; the SDK reads it to pick the key. */
  organization: string
  /** Access token id. */
  client_id: string
  scope: string[]
  type: 'ServiceAccount'
}

/** Who is calling a Secrets Manager route: a member (user token) or a machine account. */
export type SmActor =
  | { kind: 'user'; user: User }
  | {
      kind: 'machine'
      serviceAccountUuid: string
      organizationUuid: string
      accessTokenUuid: string
    }

/** Values set on the Hono context by `requireAuth`. */
export interface Variables {
  /** Set by `requireSmAuth` on Secrets Manager routes. */
  sm?: SmActor
  user: User
  auth: AuthContext
  /** Set by the token endpoint when a real second factor (not a remember token) was verified. */
  twoFactorVerified?: boolean
}

export type Env = { Bindings: Bindings; Variables: Variables }
