import type { Bindings } from '../env'

export interface EmailMessage {
  to: string
  subject: string
  text: string
  html: string
}

/** Sends transactional mail. Implementations throw on failure; callers must not log message content. */
export interface EmailTransport {
  /** False when no provider is bound, in which case `send` does nothing. */
  readonly configured: boolean
  send(message: EmailMessage): Promise<void>
}

/** Used when the EMAIL binding or MAIL_FROM is absent. Sends nothing and logs nothing. */
export const noopTransport: EmailTransport = {
  configured: false,
  async send() {},
}

const assertHeaderSafe = (value: string) => {
  if (/[\r\n]/.test(value)) throw new Error('Invalid email header value')
}

const b64 = (s: string) => {
  const bytes = new TextEncoder().encode(s)
  let bin = ''
  for (const byte of bytes) bin += String.fromCharCode(byte)
  return btoa(bin)
}

const wrap76 = (s: string) => s.replace(/.{1,76}/g, '$&\r\n').trimEnd()

/** Builds a minimal multipart/alternative MIME message for the legacy `EmailMessage` path. */
export function buildMime(from: string, message: EmailMessage): string {
  assertHeaderSafe(from)
  assertHeaderSafe(message.to)
  assertHeaderSafe(message.subject)
  const boundary = `cw-${crypto.randomUUID()}`
  const domain = from.split('@')[1]?.replace(/[^A-Za-z0-9.-]/g, '') || 'localhost'
  return [
    `From: ${from}`,
    `To: ${message.to}`,
    `Subject: =?UTF-8?B?${b64(message.subject)}?=`,
    `Message-ID: <${crypto.randomUUID()}@${domain}>`,
    `Date: ${new Date().toUTCString()}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    wrap76(b64(message.text)),
    `--${boundary}`,
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    wrap76(b64(message.html)),
    `--${boundary}--`,
    '',
  ].join('\r\n')
}

/**
 * Transport over the Cloudflare `send_email` binding named EMAIL. Uses the Email Service
 * builder form `send({ to, from, subject, html, text })`. A binding that only implements the
 * legacy API rejects that call with a TypeError; we then retry with a raw `EmailMessage`.
 */
export function bindingTransport(binding: SendEmail, from: string): EmailTransport {
  return {
    configured: true,
    async send(message) {
      try {
        await binding.send({
          to: message.to,
          from,
          subject: message.subject,
          html: message.html,
          text: message.text,
        })
      } catch (err) {
        if (!(err instanceof TypeError)) throw err
        const { EmailMessage } = await import('cloudflare:email')
        const sender = from.match(/<([^>]+)>/)?.[1] ?? from
        await binding.send(new EmailMessage(sender, message.to, buildMime(from, message)))
      }
    },
  }
}

export function createEmailTransport(env: Bindings): EmailTransport {
  if (env.EMAIL && typeof env.EMAIL.send === 'function' && env.MAIL_FROM) {
    return bindingTransport(env.EMAIL, env.MAIL_FROM)
  }
  return noopTransport
}

export * from './templates'
