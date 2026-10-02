import type { Context } from 'hono'
import type { ContentfulStatusCode } from 'hono/utils/http-status'
import type { Env } from './env'

/** Thrown by handlers; rendered by `app.onError` in the Bitwarden error shape. */
export class ApiError extends Error {
  constructor(
    readonly status: ContentfulStatusCode,
    message: string,
    readonly validationErrors: Record<string, string[]> | null = null,
  ) {
    super(message)
  }
}

export const errorBody = (
  message: string,
  validationErrors: Record<string, string[]> | null = null,
) => ({
  message,
  validationErrors,
  object: 'error',
})

/** OAuth style error used by the identity token endpoint. */
export const oauthError = (
  c: Context<Env>,
  error: string,
  description: string,
  message = description,
) =>
  c.json(
    { error, error_description: description, ErrorModel: { Message: message, Object: 'error' } },
    400,
  )

/**
 * Error of the `send_access` grant. The SDK reads `send_access_error_type` to tell a missing
 * password from a wrong one, an unknown Send, or a step of the email code flow.
 */
export const sendAccessError = (
  c: Context<Env>,
  error: 'invalid_request' | 'invalid_grant',
  type: string,
  message: string,
) =>
  c.json(
    {
      error,
      error_description: message,
      send_access_error_type: type,
      ErrorModel: { Message: message, Object: 'error' },
    },
    400,
  )
