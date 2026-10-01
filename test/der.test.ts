import { expect, it } from 'vitest'
import { derToRawEcdsa } from '../src/auth/webauthn'

const hex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => Number.parseInt(h, 16))

it('parses well formed signatures', () => {
  const ok = derToRawEcdsa(hex(`3044022011${'11'.repeat(31)}0220${'22'.repeat(32)}`))
  expect(ok).toHaveLength(64)
  const high = derToRawEcdsa(hex(`3045022100${'88'.repeat(32)}0220${'22'.repeat(32)}`))
  expect(high?.[0]).toBe(0x88)
  expect(derToRawEcdsa(hex('3006020101020102'))?.[63]).toBe(2)
})

it('rejects trailing bytes, bad lengths, negatives and non-minimal integers', () => {
  const good = `3044022011${'11'.repeat(31)}0220${'22'.repeat(32)}`
  expect(derToRawEcdsa(hex(`${good}00`))).toBeNull()
  expect(derToRawEcdsa(hex(good.replace('3044', '3043')))).toBeNull()
  expect(derToRawEcdsa(hex(good.replace('3044', '308144')))).toBeNull()
  expect(derToRawEcdsa(hex(`3045022100${'11'.repeat(32)}0220${'22'.repeat(32)}`))).toBeNull()
  expect(derToRawEcdsa(hex(`3044022088${'11'.repeat(31)}0220${'22'.repeat(32)}`))).toBeNull()
  expect(derToRawEcdsa(hex('3006020100020102'))).toBeNull()
  expect(derToRawEcdsa(hex('3006030101020102'))).toBeNull()
  expect(derToRawEcdsa(hex('30'))).toBeNull()
})
