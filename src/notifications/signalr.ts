import { decode, encode, type MsgValue } from './msgpack'

/** SignalR hub protocol framing for the JSON and MessagePack protocols. */

export type Protocol = 'json' | 'messagepack'

/** JSON protocol records are terminated by this byte. */
export const RECORD_SEPARATOR = '\x1e'

const MSG_INVOCATION = 1
const MSG_PING = 6
export const MSG_CLOSE = 7

export const PING_JSON = `{"type":${MSG_PING}}${RECORD_SEPARATOR}`

export interface HandshakeRequest {
  protocol: string
  version: number
}

/**
 * Parses the first record of a text frame as a handshake request. Returns the request
 * and any text left after the first record, or null when it is not a valid handshake.
 */
export function parseHandshake(data: string): { request: HandshakeRequest; rest: string } | null {
  const end = data.indexOf(RECORD_SEPARATOR)
  if (end < 0) return null
  try {
    const request = JSON.parse(data.slice(0, end)) as HandshakeRequest
    if (typeof request?.protocol !== 'string') return null
    return { request, rest: data.slice(end + 1) }
  } catch {
    return null
  }
}

export const handshakeOk = `{}${RECORD_SEPARATOR}`
export const handshakeError = (message: string) =>
  `${JSON.stringify({ error: message })}${RECORD_SEPARATOR}`

export function writeVarint(n: number): Uint8Array {
  const out: number[] = []
  let v = n
  do {
    let b = v & 0x7f
    v >>>= 7
    if (v > 0) b |= 0x80
    out.push(b)
  } while (v > 0)
  return Uint8Array.from(out)
}

/** Wraps a MessagePack payload in the SignalR length prefix. */
export function frame(payload: Uint8Array): Uint8Array {
  const prefix = writeVarint(payload.length)
  const out = new Uint8Array(prefix.length + payload.length)
  out.set(prefix)
  out.set(payload, prefix.length)
  return out
}

/** Splits a binary frame buffer into its length-prefixed payloads. Throws on malformed input. */
export function unframe(data: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = []
  let pos = 0
  while (pos < data.length) {
    let len = 0
    for (let i = 0; ; i++) {
      const b = data[pos++]
      // Varints are at most 5 bytes; multiplication avoids 32-bit sign overflow.
      if (b === undefined || i >= 5) throw new Error('signalr: bad length prefix')
      len += (b & 0x7f) * 2 ** (7 * i)
      if ((b & 0x80) === 0) break
    }
    if (len < 0 || len > data.length - pos) throw new Error('signalr: truncated frame')
    out.push(data.subarray(pos, pos + len))
    pos += len
  }
  return out
}

/** Encodes a server-to-client invocation for the chosen protocol. */
export function encodeInvocation(
  protocol: Protocol,
  target: string,
  args: MsgValue[],
): string | Uint8Array {
  if (protocol === 'json') {
    return `${JSON.stringify({ type: MSG_INVOCATION, target, arguments: args })}${RECORD_SEPARATOR}`
  }
  // [type, headers, invocationId, target, arguments, streamIds]
  return frame(encode([MSG_INVOCATION, {}, null, target, args, []]))
}

export const encodePing = (protocol: Protocol): string | Uint8Array =>
  protocol === 'json' ? PING_JSON : frame(encode([MSG_PING]))

/** Message types sent by the client, ignoring anything else. */
export function clientMessageTypes(protocol: Protocol, data: string | ArrayBuffer): number[] {
  const types: number[] = []
  try {
    if (protocol === 'json' && typeof data === 'string') {
      for (const rec of data.split(RECORD_SEPARATOR)) {
        if (!rec) continue
        const t = (JSON.parse(rec) as { type?: unknown }).type
        if (typeof t === 'number') types.push(t)
      }
    } else if (protocol === 'messagepack' && typeof data !== 'string') {
      for (const payload of unframe(new Uint8Array(data))) {
        const msg = decode(payload)
        if (Array.isArray(msg) && typeof msg[0] === 'number') types.push(msg[0])
      }
    }
  } catch {
    // Malformed frames are ignored.
  }
  return types
}
