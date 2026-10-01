/** Worker bindings, vars and secrets. Mirrors `cloudflare.config.ts`. */
export interface Bindings {
  // Bindings
  DB: D1Database
  ATTACHMENTS: R2Bucket
  NOTIFICATIONS: DurableObjectNamespace
  /** Cloudflare Email Service `send_email` binding. Optional: absent means no mail is sent. */
  EMAIL?: SendEmail

  // Vars
  DOMAIN: string
  SIGNUPS_ALLOWED: string
  ADMIN_ENABLED: string
  /** Sender address for outgoing mail, for example `Cloudwarden <noreply@example.com>`. */
  MAIL_FROM?: string

  // Secrets (documented only, set with `cf secrets`)
  JWT_SECRET?: string
  ADMIN_TOKEN_HASH?: string
  /** Comma-separated admin email addresses allowed to request a magic link. */
  ADMIN_EMAILS?: string
}

export type Env = { Bindings: Bindings }
