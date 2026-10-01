import { expect, it } from 'vitest'
import { fromB64u, timingSafeEqual, toB64u, utf8 } from '../src/auth/crypto'
import { signJwt, verifyJwt } from '../src/auth/jwt'
import { hashMasterPassword, verifyMasterPassword } from '../src/auth/passwords'

const SECRET = 'a'.repeat(32)
const now = Math.floor(Date.now() / 1000)

it('round-trips base64url', () => {
  const bytes = new Uint8Array([251, 255, 0, 1, 2])
  expect(fromB64u(toB64u(bytes))).toEqual(bytes)
  expect(toB64u(bytes)).not.toMatch(/[+/=]/)
})

it('compares in constant-time style and handles length differences', () => {
  expect(timingSafeEqual(utf8('abc'), utf8('abc'))).toBe(true)
  expect(timingSafeEqual(utf8('abc'), utf8('abd'))).toBe(false)
  expect(timingSafeEqual(utf8('abc'), utf8('abcd'))).toBe(false)
  expect(timingSafeEqual(utf8(''), utf8(''))).toBe(true)
})

it('hashes and verifies master password hashes with a random salt', async () => {
  const a = await hashMasterPassword('hash')
  const b = await hashMasterPassword('hash')
  expect(a.passwordHash).not.toBe(b.passwordHash)
  expect(a.passwordIterations).toBe(100000)
  expect(await verifyMasterPassword(a, 'hash')).toBe(true)
  expect(await verifyMasterPassword(a, 'other')).toBe(false)
  expect(await verifyMasterPassword(null, 'hash')).toBe(false)
})

it('signs and verifies HS256 tokens', async () => {
  const token = await signJwt({ nbf: now, exp: now + 60, sub: 'x' }, SECRET)
  expect(await verifyJwt(token, [SECRET])).toMatchObject({ sub: 'x' })
  expect(await verifyJwt(token, ['b'.repeat(32)])).toBeNull()
})

it('rejects expired, not-yet-valid, tampered and wrong-alg tokens', async () => {
  expect(
    await verifyJwt(await signJwt({ nbf: now - 100, exp: now - 1 }, SECRET), [SECRET]),
  ).toBeNull()
  expect(
    await verifyJwt(await signJwt({ nbf: now + 100, exp: now + 200 }, SECRET), [SECRET]),
  ).toBeNull()
  const token = await signJwt({ nbf: now, exp: now + 60, sub: 'x' }, SECRET)
  const [h, , s] = token.split('.')
  const forged = toB64u(utf8(JSON.stringify({ nbf: now, exp: now + 60, sub: 'admin' })))
  expect(await verifyJwt(`${h}.${forged}.${s}`, [SECRET])).toBeNull()
  const none = toB64u(utf8(JSON.stringify({ alg: 'none', typ: 'JWT' })))
  expect(await verifyJwt(`${none}.${forged}.`, [SECRET])).toBeNull()
  expect(await verifyJwt('garbage', [SECRET])).toBeNull()
})

it('accepts the previous secret during rotation', async () => {
  const old = 'o'.repeat(32)
  const token = await signJwt({ nbf: now, exp: now + 60 }, old)
  expect(await verifyJwt(token, [SECRET])).toBeNull()
  expect(await verifyJwt(token, [SECRET, old])).not.toBeNull()
})
