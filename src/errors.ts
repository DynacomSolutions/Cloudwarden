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
