/** Minimal MessagePack encoder and decoder covering the types SignalR messages use. */

export type MsgValue =
  | null
  | boolean
  | number
  | string
  | Uint8Array
  | MsgValue[]
  | { [key: string]: MsgValue }

const text = new TextEncoder()
const utf8Decoder = new TextDecoder()
const MAX_DEPTH = 32

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

function header(small: number, max: number, codes: [number, number, number], n: number) {
  // `small` is the fix-type base (0 when there is none); `codes` are the 8/16/32 bit markers.
  if (small && n < max) return Uint8Array.of(small | n)
  if (n < 0x100 && codes[0]) return Uint8Array.of(codes[0], n)
  if (n < 0x10000) return Uint8Array.of(codes[1], n >> 8, n & 0xff)
  return Uint8Array.of(codes[2], (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)
}

function encodeInt(n: number): Uint8Array {
  if (n >= 0) {
    if (n < 0x80) return Uint8Array.of(n)
    if (n < 0x100) return Uint8Array.of(0xcc, n)
    if (n < 0x10000) return Uint8Array.of(0xcd, n >> 8, n & 0xff)
    if (n < 0x100000000) {
      return Uint8Array.of(0xce, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)
    }
    const b = new Uint8Array(9)
    b[0] = 0xcf
    new DataView(b.buffer).setBigUint64(1, BigInt(n))
    return b
  }
  if (n >= -32) return Uint8Array.of(n & 0xff)
  if (n >= -0x80) return Uint8Array.of(0xd0, n & 0xff)
  if (n >= -0x8000) return Uint8Array.of(0xd1, (n >> 8) & 0xff, n & 0xff)
  if (n >= -0x80000000) {
    return Uint8Array.of(0xd2, (n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff)
  }
  const b = new Uint8Array(9)
  b[0] = 0xd3
  new DataView(b.buffer).setBigInt64(1, BigInt(n))
  return b
}

export function encode(value: MsgValue): Uint8Array {
  if (value === null) return Uint8Array.of(0xc0)
  if (typeof value === 'boolean') return Uint8Array.of(value ? 0xc3 : 0xc2)
  if (typeof value === 'number') {
    if (Number.isSafeInteger(value)) return encodeInt(value)
    const b = new Uint8Array(9)
    b[0] = 0xcb
    new DataView(b.buffer).setFloat64(1, value)
    return b
  }
  if (typeof value === 'string') {
    const bytes = text.encode(value)
    return concat([header(0xa0, 32, [0xd9, 0xda, 0xdb], bytes.length), bytes])
  }
  if (value instanceof Uint8Array) {
    return concat([header(0, 0, [0xc4, 0xc5, 0xc6], value.length), value])
  }
  if (Array.isArray(value)) {
    return concat([header(0x90, 16, [0, 0xdc, 0xdd], value.length), ...value.map(encode)])
  }
  const entries = Object.entries(value).filter(([, v]) => v !== undefined)
  return concat([
    header(0x80, 16, [0, 0xde, 0xdf], entries.length),
    ...entries.flatMap(([k, v]) => [encode(k), encode(v)]),
  ])
}

export function decode(bytes: Uint8Array): MsgValue {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let pos = 0

  const need = (n: number) => {
    if (pos + n > bytes.length) throw new Error('msgpack: truncated input')
  }
  const uint = (n: 1 | 2 | 4) => {
    need(n)
    const v = n === 1 ? view.getUint8(pos) : n === 2 ? view.getUint16(pos) : view.getUint32(pos)
    pos += n
    return v
  }
  const str = (n: number) => {
    need(n)
    const s = utf8Decoder.decode(bytes.subarray(pos, pos + n))
    pos += n
    return s
  }
  // Every element takes at least one byte, so a larger count is hostile or corrupt.
  const count = (n: number) => {
    if (n > bytes.length - pos) throw new Error('msgpack: count exceeds input')
    return n
  }
  const arr = (n: number): MsgValue[] => {
    count(n)
    return Array.from({ length: n }, read)
  }
  const map = (n: number): MsgValue => {
    count(n)
    const o: { [key: string]: MsgValue } = {}
    for (let i = 0; i < n; i++) {
      const k = String(read())
      // defineProperty keeps a `__proto__` key as plain data instead of setting the prototype.
      Object.defineProperty(o, k, {
        value: read(),
        enumerable: true,
        writable: true,
        configurable: true,
      })
    }
    return o
  }
  const bin = (n: number) => {
    need(n)
    const b = bytes.slice(pos, pos + n)
    pos += n
    return b
  }

  let depth = 0
  function read(): MsgValue {
    if (++depth > MAX_DEPTH) throw new Error('msgpack: nesting too deep')
    try {
      return readValue()
    } finally {
      depth--
    }
  }

  function readValue(): MsgValue {
    const t = uint(1)
    if (t < 0x80) return t
    if (t >= 0xe0) return t - 0x100
    if (t >= 0xa0 && t < 0xc0) return str(t & 0x1f)
    if (t >= 0x90 && t < 0xa0) return arr(t & 0x0f)
    if (t >= 0x80 && t < 0x90) return map(t & 0x0f)
    switch (t) {
      case 0xc0:
        return null
      case 0xc2:
        return false
      case 0xc3:
        return true
      case 0xc4:
        return bin(uint(1))
      case 0xc5:
        return bin(uint(2))
      case 0xc6:
        return bin(uint(4))
      case 0xca: {
        need(4)
        const v = view.getFloat32(pos)
        pos += 4
        return v
      }
      case 0xcb: {
        need(8)
        const v = view.getFloat64(pos)
        pos += 8
        return v
      }
      case 0xcc:
        return uint(1)
      case 0xcd:
        return uint(2)
      case 0xce:
        return uint(4)
      case 0xcf: {
        need(8)
        const v = Number(view.getBigUint64(pos))
        pos += 8
        return v
      }
      case 0xd0:
        need(1)
        return view.getInt8(pos++)
      case 0xd1: {
        need(2)
        const v = view.getInt16(pos)
        pos += 2
        return v
      }
      case 0xd2: {
        need(4)
        const v = view.getInt32(pos)
        pos += 4
        return v
      }
      case 0xd3: {
        need(8)
        const v = Number(view.getBigInt64(pos))
        pos += 8
        return v
      }
      case 0xd9:
        return str(uint(1))
      case 0xda:
        return str(uint(2))
      case 0xdb:
        return str(uint(4))
      case 0xdc:
        return arr(uint(2))
      case 0xdd:
        return arr(uint(4))
      case 0xde:
        return map(uint(2))
      case 0xdf:
        return map(uint(4))
      default:
        throw new Error(`msgpack: unsupported type 0x${t.toString(16)}`)
    }
  }

  return read()
}
