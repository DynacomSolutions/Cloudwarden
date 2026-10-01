import { expect, it } from 'vitest'
import { decode, encode, type MsgValue } from '../src/notifications/msgpack'
import { frame, unframe, writeVarint } from '../src/notifications/signalr'

const roundTrip = (v: MsgValue) => decode(encode(v))

it('round-trips scalars across every size class', () => {
  const values: MsgValue[] = [
    null,
    true,
    false,
    0,
    127,
    128,
    255,
    256,
    65535,
    65536,
    4294967295,
    4294967296,
    -1,
    -32,
    -33,
    -128,
    -129,
    -32768,
    -32769,
    -2147483648,
    -2147483649,
    1.5,
    '',
    'a'.repeat(31),
    'a'.repeat(32),
    'a'.repeat(300),
    'a'.repeat(70000),
    'héllo ✓',
  ]
  for (const v of values) expect(roundTrip(v)).toEqual(v)
})

it('round-trips containers and binary', () => {
  const big = Array.from({ length: 20 }, (_, i) => i)
  const value: MsgValue = {
    list: big,
    nested: { a: [1, 'two', null], b: { c: true } },
    bin: Uint8Array.of(1, 2, 3),
  }
  expect(roundTrip(value)).toEqual(value)
  expect(roundTrip(Array.from({ length: 70000 }, () => 1))).toHaveLength(70000)
  const wide = Object.fromEntries(big.map((i) => [`k${i}`, i]))
  expect(roundTrip(wide)).toEqual(wide)
})

it('matches known encodings', () => {
  expect([...encode([6])]).toEqual([0x91, 0x06])
  expect([...encode('ab')]).toEqual([0xa2, 0x61, 0x62])
  expect([...encode({ a: 1 })]).toEqual([0x81, 0xa1, 0x61, 0x01])
})

it('rejects truncated input', () => {
  expect(() => decode(Uint8Array.of(0xa5, 0x61))).toThrow()
  expect(() => decode(Uint8Array.of(0xc1))).toThrow()
})

it('frames with a varint length prefix', () => {
  expect([...writeVarint(5)]).toEqual([5])
  expect([...writeVarint(300)]).toEqual([0xac, 0x02])
  const payloads = [new Uint8Array(3).fill(1), new Uint8Array(200).fill(2)]
  const joined = new Uint8Array(1 + 3 + 2 + 200)
  joined.set(frame(payloads[0] as Uint8Array))
  joined.set(frame(payloads[1] as Uint8Array), 4)
  expect(unframe(joined).map((p) => p.length)).toEqual([3, 200])
  expect(() => unframe(Uint8Array.of(5, 1))).toThrow()
})

it('rejects an overflowing varint length prefix without looping', () => {
  expect(() => unframe(Uint8Array.of(0xfb, 0xff, 0xff, 0xff, 0x0f))).toThrow()
  expect(() => unframe(Uint8Array.of(0x80, 0x80, 0x80, 0x80, 0x80, 0x01))).toThrow()
  expect(() => unframe(Uint8Array.of(0xff, 0xff, 0xff, 0xff, 0x07))).toThrow()
})

it('rejects hostile container counts and deep nesting', () => {
  expect(() => decode(Uint8Array.of(0xdd, 0xff, 0xff, 0xff, 0xff))).toThrow()
  expect(() => decode(Uint8Array.of(0xdf, 0x7f, 0xff, 0xff, 0xff))).toThrow()
  expect(() => decode(new Uint8Array(100).fill(0x91))).toThrow(/deep/)
  const ok = new Uint8Array(30).fill(0x91)
  ok[29] = 0x01
  expect(() => decode(ok)).not.toThrow()
})

it('keeps a __proto__ key as plain data', () => {
  const bytes = encode({ ['__proto__']: { polluted: true } } as MsgValue)
  const out = decode(bytes) as Record<string, unknown>
  expect(Object.keys(out)).toEqual(['__proto__'])
  expect(Object.getPrototypeOf(out)).toBe(Object.prototype)
  expect(({} as Record<string, unknown>).polluted).toBeUndefined()
})
