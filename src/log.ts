import type { MiddlewareHandler } from 'hono'
import type { Env } from './env'

/**
 * Structured JSON-line logging (TASKS #164).
 *
 * Rules: log metadata only. Never request or response bodies, tokens, cookies, authorization
 * headers, query strings, emails, password hashes or vault data. Fields are allow-listed by key
 * name pattern and values are bounded, so a careless call site cannot leak a secret by accident.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

const LEVELS: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 }

/** Field names that must never reach the log, matched case-insensitively as substrings. */
const FORBIDDEN_KEY =
  /pass|token|secret|auth|cookie|email|body|hash|key|salt|stamp|cipher|name|hint|ip$/i

const MAX_VALUE_LENGTH = 200

export type LogFields = Record<string, string | number | boolean | null | undefined>

/** Drop forbidden keys, keep scalars only, truncate long strings. */
export function sanitizeFields(fields: LogFields): LogFields {
  const out: LogFields = {}
  for (const [k, v] of Object.entries(fields)) {
    if (FORBIDDEN_KEY.test(k)) continue
    if (v === undefined) continue
    if (typeof v === 'string')
      out[k] = v.length > MAX_VALUE_LENGTH ? `${v.slice(0, MAX_VALUE_LENGTH)}...` : v
    else if (typeof v === 'number' || typeof v === 'boolean' || v === null) out[k] = v
  }
  return out
}

export function formatLine(
  level: LogLevel,
  event: string,
  fields: LogFields = {},
  now = Date.now(),
): string {
  return JSON.stringify({
    ts: new Date(now).toISOString(),
    level,
    event,
    ...sanitizeFields(fields),
  })
}

function minLevel(env?: { LOG_LEVEL?: string }): number {
  const l = env?.LOG_LEVEL as LogLevel | undefined
  return l && l in LEVELS ? LEVELS[l] : LEVELS.info
}

export function log(
  level: LogLevel,
  event: string,
  fields: LogFields = {},
  env?: { LOG_LEVEL?: string },
): void {
  if (LEVELS[level] < minLevel(env)) return
  const line = formatLine(level, event, fields)
  if (level === 'error') console.error(line)
  else if (level === 'warn') console.warn(line)
  else console.log(line)
}

/** A safe summary of a thrown value: the error class only, never the message (it may echo input). */
export function errorKind(err: unknown): string {
  return err instanceof Error ? err.name : typeof err
}

const REQUEST_ID = /^[A-Za-z0-9-]{8,64}$/

/**
 * Request logging middleware. Emits one line per request after the handler runs: request id,
 * method, matched route pattern (not the raw path, which can carry ids), status and duration.
 * Sets `X-Request-Id` on the response.
 */
export const requestLogger: MiddlewareHandler<Env> = async (c, next) => {
  const start = Date.now()
  const inbound = c.req.header('cf-ray')
  const requestId = inbound && REQUEST_ID.test(inbound) ? inbound : crypto.randomUUID()
  try {
    await next()
  } finally {
    const route = c.req.routePath
    log(
      'info',
      'request',
      {
        requestId,
        method: c.req.method,
        route: route === '/*' ? 'unmatched' : route,
        status: c.res.status,
        durationMs: Date.now() - start,
      },
      c.env,
    )
    try {
      c.res.headers.set('X-Request-Id', requestId)
    } catch {
      // Immutable response headers (for example a passthrough); the log line still carries the id.
    }
  }
}
