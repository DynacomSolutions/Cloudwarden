import { expect, it } from 'vitest'
import {
  base32Decode,
  base32Encode,
  generateTotpKey,
  hotp,
  totpAt,
  verifyTotp,
} from '../src/auth/totp'

// RFC 4226 and RFC 6238 test secret "12345678901234567890".
const SECRET = new TextEncoder().encode('12345678901234567890')
const KEY = base32Encode(SECRET)

it('base32 round trips and tolerates spacing and case', () => {
  expect(KEY).toBe('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
  expect(base32Decode('gezd gnbv-GY3TQOJQGEZDGNBVGY3TQOJQ====')).toEqual(SECRET)
  expect(base32Decode('not*base32')).toBeNull()
  expect(base32Decode('')).toBeNull()
  expect(generateTotpKey()).toMatch(/^[A-Z2-7]{32}$/)
})

it('matches the RFC 4226 HOTP vectors', async () => {
  const expected = ['755224', '287082', '359152', '969429', '338314', '254676']
  for (const [counter, code] of expected.entries()) expect(await hotp(SECRET, counter)).toBe(code)
})

it('matches RFC 6238 time vectors (last six digits)', async () => {
  expect(await totpAt(KEY, 59_000)).toBe('287082')
  expect(await totpAt(KEY, 1111111109_000)).toBe('081804')
  expect(await totpAt(KEY, 1234567890_000)).toBe('005924')
})

it('accepts one step either side and rejects further skew', async () => {
  const now = 1_700_000_000_000
  const at = (offsetSteps: number) => totpAt(KEY, now + offsetSteps * 30_000) as Promise<string>
  const step = Math.floor(now / 30_000)
  expect(await verifyTotp(KEY, await at(0), now, 0)).toBe(step)
  expect(await verifyTotp(KEY, await at(-1), now, 0)).toBe(step - 1)
  expect(await verifyTotp(KEY, await at(1), now, 0)).toBe(step + 1)
  expect(await verifyTotp(KEY, await at(-2), now, 0)).toBeNull()
  expect(await verifyTotp(KEY, await at(2), now, 0)).toBeNull()
})

it('rejects steps at or below the last used step (replay)', async () => {
  const now = 1_700_000_000_000
  const code = (await totpAt(KEY, now)) as string
  const step = Math.floor(now / 30_000)
  expect(await verifyTotp(KEY, code, now, step)).toBeNull()
  expect(await verifyTotp(KEY, code, now, step - 1)).toBe(step)
})

it('rejects malformed codes and keys', async () => {
  expect(await verifyTotp(KEY, '12345', 0, 0)).toBeNull()
  expect(await verifyTotp(KEY, 'abcdef', 0, 0)).toBeNull()
  expect(await verifyTotp('!!', '123456', 0, 0)).toBeNull()
})
