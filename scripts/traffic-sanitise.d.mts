export const FIXED_DATE: string
export const FIXED_EMAIL: string
export const FIXED_HOST: string
export const PLACEHOLDER: RegExp
export const WHOLE_PLACEHOLDER: RegExp
export function createSanitiser(): {
  string: (s: string, key?: string) => string
  value: (v: unknown, key?: string) => unknown
}
export function findIdentifying(data: unknown): { path: string; reason: string }[]
