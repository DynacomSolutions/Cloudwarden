import type { Context } from 'hono'
import type { z } from 'zod'
import type { Env } from './env'
import { ApiError } from './errors'

const lowerFirst = (k: string) => k.charAt(0).toLowerCase() + k.slice(1)

/** Lowercases the first letter of keys (clients vary between camelCase and PascalCase). */
export function normalizeKeys(value: unknown, depth = 2): unknown {
  if (Array.isArray(value)) return value.map((v) => normalizeKeys(v, depth))
  if (value && typeof value === 'object' && depth > 0) {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [lowerFirst(k), normalizeKeys(v, depth - 1)]),
    )
  }
  return value
}

/** Parses and validates a JSON body. Throws ApiError 400 with field errors. */
export async function parseBody<S extends z.ZodType>(
  c: Context<Env>,
  schema: S,
): Promise<z.infer<S>> {
  const raw = await c.req.json().catch(() => null)
  const parsed = schema.safeParse(normalizeKeys(raw))
  if (!parsed.success) {
    const errors: Record<string, string[]> = {}
    for (const issue of parsed.error.issues) {
      const key = issue.path.join('.') || 'body'
      errors[key] = [...(errors[key] ?? []), issue.message]
    }
    throw new ApiError(400, 'The request is invalid.', errors)
  }
  return parsed.data
}

export interface KdfParams {
  kdf: number
  kdfIterations: number
  kdfMemory?: number | null
  kdfParallelism?: number | null
}

/** Returns an error message if the KDF settings are outside the accepted bounds. */
export function kdfProblem(k: KdfParams): string | null {
  if (k.kdf === 0) {
    if (k.kdfIterations < 5000 || k.kdfIterations > 2_000_000) {
      return 'KDF iterations must be between 5000 and 2000000.'
    }
    return null
  }
  if (k.kdf === 1) {
    if (k.kdfIterations < 2 || k.kdfIterations > 10)
      return 'KDF iterations must be between 2 and 10.'
    if (!k.kdfMemory || k.kdfMemory < 15 || k.kdfMemory > 1024) {
      return 'KDF memory must be between 15 and 1024 MB.'
    }
    if (!k.kdfParallelism || k.kdfParallelism < 1 || k.kdfParallelism > 16) {
      return 'KDF parallelism must be between 1 and 16.'
    }
    return null
  }
  return 'Unsupported KDF type.'
}
