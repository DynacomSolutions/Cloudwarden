/**
 * Minimal CBOR decoder (RFC 8949) covering what WebAuthn attestation objects and COSE keys
 * use: integers, byte and text strings, arrays, maps, tags, booleans, null and floats.
 * Indefinite lengths are not supported. Maps decode to `Map` so integer keys survive.
 */
export type CborValue =
  | number
  | bigint
  | string
  | boolean
  | null
  | undefined
  | Uint8Array
  | CborValue[]
  | Map<CborValue, CborValue>

const MAX_DEPTH = 16

export class CborError extends Error {}

class Reader {
  pos = 0
  private view: DataView
  constructor(readonly buf: Uint8Array) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  }

  need(n: number) {
    if (this.pos + n > this.buf.length) throw new CborError('Unexpected end of CBOR data')
  }
  u8(): number {
    this.need(1)
    return this.buf[this.pos++] as number
  }
  bytes(n: number): Uint8Array {
    this.need(n)
    const out = this.buf.subarray(this.pos, this.pos + n)
    this.pos += n
    return out
  }
  uint(n: number): number | bigint {
    this.need(n)
    let v: number | bigint
    if (n === 1) v = this.view.getUint8(this.pos)
    else if (n === 2) v = this.view.getUint16(this.pos)
    else if (n === 4) v = this.view.getUint32(this.pos)
    else {
      const big = this.view.getBigUint64(this.pos)
      v = big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big
    }
    this.pos += n
    return v
  }
  f16(): number {
    const h = this.uint(2) as number
    const exp = (h >> 10) & 0x1f
    const frac = h & 0x3ff
    const sign = h & 0x8000 ? -1 : 1
    if (exp === 0) return sign * 2 ** -14 * (frac / 1024)
    if (exp === 31) return frac ? Number.NaN : sign * Number.POSITIVE_INFINITY
    return sign * 2 ** (exp - 15) * (1 + frac / 1024)
  }
  f32(): number {
    this.need(4)
    const v = this.view.getFloat32(this.pos)
    this.pos += 4
    return v
  }
  f64(): number {
    this.need(8)
    const v = this.view.getFloat64(this.pos)
    this.pos += 8
    return v
  }
}

function argument(r: Reader, info: number): number {
  if (info < 24) return info
  if (info > 27) throw new CborError('Unsupported CBOR length encoding')
  const v = r.uint(1 << (info - 24))
  if (typeof v === 'bigint') throw new CborError('CBOR length too large')
  return v
}

function item(r: Reader, depth: number): CborValue {
  if (depth > MAX_DEPTH) throw new CborError('CBOR nesting too deep')
  const initial = r.u8()
  const major = initial >> 5
  const info = initial & 0x1f
  switch (major) {
    case 0:
      if (info > 27) throw new CborError('Unsupported CBOR integer encoding')
      return info < 24 ? info : r.uint(1 << (info - 24))
    case 1: {
      if (info > 27) throw new CborError('Unsupported CBOR integer encoding')
      const v = info < 24 ? info : r.uint(1 << (info - 24))
      return typeof v === 'bigint' ? -1n - v : -1 - v
    }
    case 2:
      return r.bytes(argument(r, info)).slice()
    case 3:
      return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
        r.bytes(argument(r, info)),
      )
    case 4: {
      const n = argument(r, info)
      if (n > r.buf.length - r.pos) throw new CborError('CBOR array too long')
      const out: CborValue[] = []
      for (let i = 0; i < n; i++) out.push(item(r, depth + 1))
      return out
    }
    case 5: {
      const n = argument(r, info)
      if (n > r.buf.length - r.pos) throw new CborError('CBOR map too long')
      const out = new Map<CborValue, CborValue>()
      for (let i = 0; i < n; i++) {
        const k = item(r, depth + 1)
        out.set(k, item(r, depth + 1))
      }
      return out
    }
    case 6:
      argument(r, info)
      return item(r, depth + 1)
    default:
      switch (info) {
        case 20:
          return false
        case 21:
          return true
        case 22:
          return null
        case 23:
          return undefined
        case 25:
          return r.f16()
        case 26:
          return r.f32()
        case 27:
          return r.f64()
        default:
          throw new CborError('Unsupported CBOR simple value')
      }
  }
}

/** Decodes one item and returns it with the number of bytes consumed. */
export function decodeCborPrefix(data: Uint8Array): { value: CborValue; length: number } {
  const r = new Reader(data)
  const value = item(r, 0)
  return { value, length: r.pos }
}

/** Decodes exactly one item; trailing bytes are an error. */
export function decodeCbor(data: Uint8Array): CborValue {
  const { value, length } = decodeCborPrefix(data)
  if (length !== data.length) throw new CborError('Trailing bytes after CBOR item')
  return value
}
