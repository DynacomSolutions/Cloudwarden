import { expect, it } from 'vitest'
import { CborError, decodeCbor, decodeCborPrefix } from '../src/auth/cbor'

const hex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => Number.parseInt(h, 16))

it('decodes the RFC 8949 appendix A examples', () => {
  expect(decodeCbor(hex('00'))).toBe(0)
  expect(decodeCbor(hex('17'))).toBe(23)
  expect(decodeCbor(hex('1818'))).toBe(24)
  expect(decodeCbor(hex('1903e8'))).toBe(1000)
  expect(decodeCbor(hex('1a000f4240'))).toBe(1_000_000)
  expect(decodeCbor(hex('1b000000e8d4a51000'))).toBe(1_000_000_000_000)
  expect(decodeCbor(hex('1bffffffffffffffff'))).toBe(18446744073709551615n)
  expect(decodeCbor(hex('20'))).toBe(-1)
  expect(decodeCbor(hex('3863'))).toBe(-100)
  expect(decodeCbor(hex('3903e7'))).toBe(-1000)
  expect(decodeCbor(hex('f4'))).toBe(false)
  expect(decodeCbor(hex('f5'))).toBe(true)
  expect(decodeCbor(hex('f6'))).toBe(null)
  expect(decodeCbor(hex('f7'))).toBe(undefined)
  expect(decodeCbor(hex('f93c00'))).toBe(1)
  expect(decodeCbor(hex('f97bff'))).toBe(65504)
  expect(decodeCbor(hex('fa47c35000'))).toBe(100000)
  expect(decodeCbor(hex('fb3ff199999999999a'))).toBe(1.1)
})

it('decodes strings, arrays, maps and tags', () => {
  expect(decodeCbor(hex('6449455446'))).toBe('IETF')
  expect(decodeCbor(hex('62c3bc'))).toBe('\u00fc')
  expect(decodeCbor(hex('4401020304'))).toEqual(Uint8Array.of(1, 2, 3, 4))
  expect(decodeCbor(hex('83010203'))).toEqual([1, 2, 3])
  expect(decodeCbor(hex('8301820203820405'))).toEqual([1, [2, 3], [4, 5]])
  const map = decodeCbor(hex('a201020304')) as Map<unknown, unknown>
  expect(map.get(1)).toBe(2)
  expect(map.get(3)).toBe(4)
  const text = decodeCbor(hex('a26161016162820203')) as Map<unknown, unknown>
  expect(text.get('a')).toBe(1)
  expect(text.get('b')).toEqual([2, 3])
  expect(decodeCbor(hex('c11a514b67b0'))).toBe(1363896240)
})

it('reports consumed length for concatenated items', () => {
  const r = decodeCborPrefix(hex('a10102ff'))
  expect(r.length).toBe(3)
})

it('rejects truncated, trailing, indefinite and over-deep input', () => {
  expect(() => decodeCbor(hex('1903'))).toThrow(CborError)
  expect(() => decodeCbor(hex('0000'))).toThrow(CborError)
  expect(() => decodeCbor(hex('5f4101ff'))).toThrow(CborError)
  expect(() => decodeCbor(hex('9fff'))).toThrow(CborError)
  expect(() => decodeCbor(hex('ff'))).toThrow(CborError)
  expect(() => decodeCbor(hex('99ffff'))).toThrow(CborError)
  expect(() => decodeCbor(new Uint8Array(40).fill(0x81))).toThrow(CborError)
})
