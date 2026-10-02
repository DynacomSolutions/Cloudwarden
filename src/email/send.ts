import type { Bindings } from '../env'
import { errorKind, log } from '../log'
import { createEmailTransport, type EmailMessage } from './index'

/**
 * Best-effort notice: sends when a transport is bound, never throws and never logs the message.
 * Returns true when the transport accepted it. Use `createEmailTransport` directly when the
 * caller must fail on error (codes and links the user is waiting for).
 */
export async function sendNotice(
  env: Bindings,
  to: string,
  template: Omit<EmailMessage, 'to'>,
): Promise<boolean> {
  const transport = createEmailTransport(env)
  if (!transport.configured) return false
  try {
    await transport.send({ to, ...template })
    return true
  } catch (err) {
    log('warn', 'email.send_failed', { errorKind: errorKind(err) }, env)
    return false
  }
}

/** Runs best-effort work after the response when an execution context exists. */
export function later(
  c: { executionCtx: Pick<ExecutionContext, 'waitUntil'> },
  work: Promise<unknown>,
): void {
  try {
    c.executionCtx.waitUntil(work)
  } catch {
    void work
  }
}

/** Web vault base address without a trailing slash. */
export const vaultBase = (env: Bindings) => env.DOMAIN.replace(/\/+$/, '')
