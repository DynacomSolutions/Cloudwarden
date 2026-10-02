// A minimal LDAPv3 server (RFC 4511) for the Directory Connector e2e steps (TASKS #262): simple
// bind, search with the full filter grammar (and, or, not, equality, substrings, >=, <=,
// presence) and scope, unbind. Plain TCP on 127.0.0.1, entries held in memory, nothing else.
import { createServer } from 'node:net'

// ----- BER -----

function readLength(buf, p) {
  const first = buf[p]
  if (first < 0x80) return [first, p + 1]
  const n = first & 0x7f
  let len = 0
  for (let i = 0; i < n; i++) len = len * 256 + buf[p + 1 + i]
  return [len, p + 1 + n]
}

/** Reads one TLV at `p`: { tag, value (Buffer), end }. Returns null when incomplete. */
function readTlv(buf, p) {
  if (p + 2 > buf.length) return null
  const tag = buf[p]
  if (buf[p + 1] >= 0x80 && p + 2 + (buf[p + 1] & 0x7f) > buf.length) return null
  const [len, start] = readLength(buf, p + 1)
  if (start + len > buf.length) return null
  return { tag, value: buf.subarray(start, start + len), end: start + len }
}

function children(buf) {
  const out = []
  let p = 0
  while (p < buf.length) {
    const t = readTlv(buf, p)
    out.push(t)
    p = t.end
  }
  return out
}

function encLength(n) {
  if (n < 0x80) return Buffer.from([n])
  const bytes = []
  while (n > 0) {
    bytes.unshift(n & 0xff)
    n >>= 8
  }
  return Buffer.from([0x80 | bytes.length, ...bytes])
}

const tlv = (tag, value) => Buffer.concat([Buffer.from([tag]), encLength(value.length), value])
const seq = (tag, items) => tlv(tag, Buffer.concat(items))
const str = (s, tag = 0x04) => tlv(tag, Buffer.from(s, 'utf8'))

function int(n, tag = 0x02) {
  const bytes = []
  let v = n
  do {
    bytes.unshift(v & 0xff)
    v >>= 8
  } while (v > 0)
  if (bytes[0] & 0x80) bytes.unshift(0)
  return tlv(tag, Buffer.from(bytes))
}

const readInt = (b) => b.reduce((a, x) => a * 256 + x, 0)

// ----- filters -----

const lower = (s) => String(s).toLowerCase()

function attrValues(entry, name) {
  if (lower(name) === 'dn' || lower(name) === 'distinguishedname') return [entry.dn]
  const key = Object.keys(entry.attrs).find((k) => lower(k) === lower(name))
  return key ? entry.attrs[key] : []
}

function matchFilter(entry, f) {
  const parts = () => children(f.value)
  switch (f.tag) {
    case 0xa0:
      return parts().every((x) => matchFilter(entry, x))
    case 0xa1:
      return parts().some((x) => matchFilter(entry, x))
    case 0xa2:
      return !matchFilter(entry, readTlv(f.value, 0))
    case 0xa3:
    case 0xa5:
    case 0xa6:
    case 0xa8: {
      const [a, v] = parts()
      const want = lower(v.value.toString('utf8'))
      return attrValues(entry, a.value.toString('utf8')).some((x) => {
        const have = lower(x)
        if (f.tag === 0xa5) return have >= want
        if (f.tag === 0xa6) return have <= want
        return have === want
      })
    }
    case 0xa4: {
      const [a, subs] = parts()
      const pieces = children(subs.value).map((s) => ({ tag: s.tag, v: lower(s.value) }))
      return attrValues(entry, a.value.toString('utf8')).some((x) => {
        let rest = lower(x)
        for (const s of pieces) {
          if (s.tag === 0x80) {
            if (!rest.startsWith(s.v)) return false
            rest = rest.slice(s.v.length)
          } else if (s.tag === 0x81) {
            const i = rest.indexOf(s.v)
            if (i < 0) return false
            rest = rest.slice(i + s.v.length)
          } else if (!rest.endsWith(s.v)) return false
        }
        return true
      })
    }
    case 0x87:
      return attrValues(entry, f.value.toString('utf8')).length > 0
    default:
      return false
  }
}

function inScope(dn, base, scope) {
  const d = lower(dn)
  const b = lower(base)
  if (scope === 0) return d === b
  if (!(d === b || d.endsWith(`,${b}`) || b === '')) return false
  if (scope === 1) return d !== b && d.slice(0, d.length - b.length - 1).split(',').length === 1
  return true
}

// ----- server -----

/**
 * Starts the server. `entries` are `{ dn, attrs: { name: [values] } }`; `bind` checks a DN and
 * password. Resolves to `{ port, close }`.
 */
export function startLdap({ entries, bindDn, password }) {
  const server = createServer((socket) => {
    let pending = Buffer.alloc(0)
    socket.on('error', () => {})
    socket.on('data', (chunk) => {
      pending = Buffer.concat([pending, chunk])
      for (;;) {
        const msg = readTlv(pending, 0)
        if (!msg) break
        pending = pending.subarray(msg.end)
        const [id, op] = children(msg.value)
        const messageId = readInt(id.value)
        const reply = (tag, items) => socket.write(seq(0x30, [int(messageId), seq(tag, items)]))
        const result = (tag, code, text = '') => reply(tag, [int(code, 0x0a), str(''), str(text)])
        if (op.tag === 0x60) {
          const [, name, auth] = children(op.value)
          const ok =
            lower(name.value.toString('utf8')) === lower(bindDn) &&
            auth.value.toString('utf8') === password
          result(0x61, ok ? 0 : 49, ok ? '' : 'Invalid credentials')
        } else if (op.tag === 0x42) {
          socket.end()
        } else if (op.tag === 0x63) {
          const [base, scope, , sizeLimit, , , filter] = children(op.value)
          const limit = readInt(sizeLimit.value)
          let sent = 0
          for (const e of entries) {
            if (limit && sent >= limit) break
            if (!inScope(e.dn, base.value.toString('utf8'), readInt(scope.value))) continue
            if (!matchFilter(e, filter)) continue
            const attrs = Object.entries(e.attrs).map(([k, vs]) =>
              seq(0x30, [
                str(k),
                seq(
                  0x31,
                  vs.map((v) => str(String(v))),
                ),
              ]),
            )
            reply(0x64, [str(e.dn), seq(0x30, attrs)])
            sent++
          }
          result(0x65, 0)
        } else if (op.tag === 0x77) {
          // Extended operations (StartTLS, Who am I): not supported.
          result(0x78, 2, 'Unsupported extended operation')
        } else if (op.tag !== 0x50) {
          // Anything else except abandon gets "unwillingToPerform" in the matching response.
          const responseTag =
            op.tag === 0x66 ? 0x67 : op.tag === 0x68 ? 0x69 : op.tag === 0x4a ? 0x6b : 0x65
          result(responseTag, 53, 'Unsupported operation')
        }
      }
    })
  })
  return new Promise((ok) => {
    server.listen(0, '127.0.0.1', () =>
      ok({ port: server.address().port, close: () => new Promise((r) => server.close(r)) }),
    )
  })
}
