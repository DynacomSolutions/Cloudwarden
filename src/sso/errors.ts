/**
 * A failed SSO step. The message is safe to show to the person signing in; `cause` (provider
 * detail) is only logged by kind, never rendered.
 */
export class SsoError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'SsoError'
  }
}
