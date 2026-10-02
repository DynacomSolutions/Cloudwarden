// SCIM 2.0 filters (RFC 7644 section 3.4.2) and attribute paths (section 3.5.2), written from the RFC.
//
//   FILTER    = attrExp / logExp / valuePath / "not" "(" FILTER ")" / "(" FILTER ")"
//   attrExp   = attrPath SP "pr" / attrPath SP compareOp SP compValue
//   valuePath = attrPath "[" valFilter "]" [ "." subAttr ]
//
// Precedence is `not`, then `and`, then `or`. Attribute names are case-insensitive. String
// comparisons are case-insensitive except for attributes that are `caseExact` in the core schemas
// (`id`, `externalId`, and the `value` of group members).

export class ScimError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly scimType?: string,
  ) {
    super(message)
  }
}

const invalidFilter = (msg: string) => new ScimError(400, msg, 'invalidFilter')

export type CompareOp = 'eq' | 'ne' | 'co' | 'sw' | 'ew' | 'gt' | 'ge' | 'lt' | 'le'
export type Value = string | number | boolean | null

export interface AttrPath {
  /** Schema URN, when the path was written fully qualified. */
  urn?: string
  attr: string
  sub?: string
}

export type Filter =
  | { kind: 'pr'; path: AttrPath }
  | { kind: 'cmp'; path: AttrPath; op: CompareOp; value: Value }
  | { kind: 'and' | 'or'; left: Filter; right: Filter }
  | { kind: 'not'; filter: Filter }
  | { kind: 'value'; path: AttrPath; filter: Filter; then?: Filter }

type Token = { t: 'word'; v: string } | { t: 'str'; v: string } | { t: '(' | ')' | '[' | ']' }

const OPS = new Set(['eq', 'ne', 'co', 'sw', 'ew', 'gt', 'ge', 'lt', 'le'])

function tokenize(input: string): Token[] {
  const out: Token[] = []
  let i = 0
  while (i < input.length) {
    const ch = input[i] as string
    if (/\s/.test(ch)) {
      i++
    } else if (ch === '(' || ch === ')' || ch === '[' || ch === ']') {
      out.push({ t: ch })
      i++
    } else if (ch === '"') {
      let j = i + 1
      let s = ''
      while (j < input.length && input[j] !== '"') {
        if (input[j] === '\\' && j + 1 < input.length) {
          const next = input[j + 1] as string
          const map: Record<string, string> = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f' }
          if (next === 'u') {
            s += String.fromCharCode(Number.parseInt(input.slice(j + 2, j + 6), 16))
            j += 6
            continue
          }
          s += map[next] ?? next
          j += 2
        } else {
          s += input[j]
          j++
        }
      }
      if (j >= input.length) throw invalidFilter('Unterminated string in filter.')
      out.push({ t: 'str', v: s })
      i = j + 1
    } else {
      let j = i
      while (j < input.length && !/[\s()[\]"]/.test(input[j] as string)) j++
      out.push({ t: 'word', v: input.slice(i, j) })
      i = j
    }
  }
  return out
}

/** Splits `urn:...:User:name.givenName` or `name.givenName` into its parts. */
export function parseAttrPath(raw: string): AttrPath {
  let rest = raw
  let urn: string | undefined
  if (/^urn:/i.test(raw)) {
    // The attribute follows the last colon of the URN.
    const idx = raw.lastIndexOf(':')
    urn = raw.slice(0, idx)
    rest = raw.slice(idx + 1)
    if (!rest) return { urn, attr: '' }
  }
  const [attr, sub, extra] = rest.split('.')
  if (!attr || extra !== undefined || !/^[A-Za-z$][\w$-]*$/.test(attr)) {
    throw invalidFilter(`Invalid attribute path "${raw}".`)
  }
  if (sub !== undefined && !/^[A-Za-z$][\w$-]*$/.test(sub)) {
    throw invalidFilter(`Invalid attribute path "${raw}".`)
  }
  return { urn, attr, sub }
}

function literal(tok: Token | undefined): Value {
  if (!tok) throw invalidFilter('Missing comparison value.')
  if (tok.t === 'str') return tok.v
  if (tok.t !== 'word') throw invalidFilter('Invalid comparison value.')
  const w = tok.v.toLowerCase()
  if (w === 'true') return true
  if (w === 'false') return false
  if (w === 'null') return null
  const n = Number(tok.v)
  if (tok.v !== '' && Number.isFinite(n)) return n
  throw invalidFilter(`Invalid comparison value "${tok.v}".`)
}

class Parser {
  private i = 0
  constructor(private readonly toks: Token[]) {}

  parse(): Filter {
    const f = this.or()
    if (this.i < this.toks.length) throw invalidFilter('Unexpected trailing filter content.')
    return f
  }

  private peekWord(): string | null {
    const t = this.toks[this.i]
    return t?.t === 'word' ? t.v.toLowerCase() : null
  }

  private or(): Filter {
    let left = this.and()
    while (this.peekWord() === 'or') {
      this.i++
      left = { kind: 'or', left, right: this.and() }
    }
    return left
  }

  private and(): Filter {
    let left = this.unary()
    while (this.peekWord() === 'and') {
      this.i++
      left = { kind: 'and', left, right: this.unary() }
    }
    return left
  }

  private expect(t: '(' | ')' | ']') {
    if (this.toks[this.i]?.t !== t) throw invalidFilter(`Expected "${t}" in filter.`)
    this.i++
  }

  private unary(): Filter {
    const tok = this.toks[this.i]
    if (!tok) throw invalidFilter('Incomplete filter.')
    if (tok.t === 'word' && tok.v.toLowerCase() === 'not' && this.toks[this.i + 1]?.t === '(') {
      this.i++
      this.expect('(')
      const f = this.or()
      this.expect(')')
      return { kind: 'not', filter: f }
    }
    if (tok.t === '(') {
      this.i++
      const f = this.or()
      this.expect(')')
      return f
    }
    if (tok.t !== 'word') throw invalidFilter('Expected an attribute name.')
    this.i++
    const path = parseAttrPath(tok.v)
    if (this.toks[this.i]?.t === '[') {
      this.i++
      const inner = this.or()
      this.expect(']')
      // Lenient extension used by some clients: `emails[type eq "work"].value eq "x"`.
      const next = this.toks[this.i]
      if (next?.t === 'word' && next.v.startsWith('.')) {
        this.i++
        const sub = next.v.slice(1)
        const then = this.attrExp({ attr: sub })
        return { kind: 'value', path, filter: inner, then }
      }
      return { kind: 'value', path, filter: inner }
    }
    return this.attrExp(path)
  }

  private attrExp(path: AttrPath): Filter {
    const op = this.peekWord()
    if (op === 'pr') {
      this.i++
      return { kind: 'pr', path }
    }
    if (!op || !OPS.has(op)) throw invalidFilter('Expected a comparison operator.')
    this.i++
    const value = literal(this.toks[this.i])
    this.i++
    return { kind: 'cmp', path, op: op as CompareOp, value }
  }
}

export function parseFilter(input: string): Filter {
  if (input.length > 4096) throw invalidFilter('Filter is too long.')
  return new Parser(tokenize(input)).parse()
}

// ----- evaluation -----

type Json = Record<string, unknown>

/** Case-insensitive property lookup. */
export function getProp(obj: unknown, name: string): unknown {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return undefined
  const lower = name.toLowerCase()
  for (const [k, v] of Object.entries(obj as Json)) if (k.toLowerCase() === lower) return v
  return undefined
}

/** The object holding a path's attribute: the resource, or its extension object for a URN path. */
export function container(resource: Json, path: AttrPath): unknown {
  if (!path.urn) return resource
  const core = Array.isArray(resource.schemas)
    ? (resource.schemas as string[]).find((s) => s.toLowerCase() === path.urn?.toLowerCase())
    : undefined
  // A core schema URN qualifies attributes of the resource itself.
  if (core && !getProp(resource, path.urn)) return resource
  return getProp(resource, path.urn)
}

const CASE_EXACT = new Set(['id', 'externalid'])

function compare(actual: unknown, op: CompareOp, expected: Value, caseExact: boolean): boolean {
  if (actual === undefined || actual === null)
    return op === 'ne' ? expected !== null : expected === null && op === 'eq'
  if (typeof actual === 'boolean' || typeof expected === 'boolean') {
    const a = typeof actual === 'string' ? actual.toLowerCase() === 'true' : Boolean(actual)
    if (op === 'eq') return a === expected
    if (op === 'ne') return a !== expected
    return false
  }
  if (typeof actual === 'number' && typeof expected === 'number') {
    switch (op) {
      case 'eq':
        return actual === expected
      case 'ne':
        return actual !== expected
      case 'gt':
        return actual > expected
      case 'ge':
        return actual >= expected
      case 'lt':
        return actual < expected
      case 'le':
        return actual <= expected
      default:
        return false
    }
  }
  if (expected === null) return op === 'ne'
  let a = String(actual)
  let e = String(expected)
  if (!caseExact) {
    a = a.toLowerCase()
    e = e.toLowerCase()
  }
  switch (op) {
    case 'eq':
      return a === e
    case 'ne':
      return a !== e
    case 'co':
      return a.includes(e)
    case 'sw':
      return a.startsWith(e)
    case 'ew':
      return a.endsWith(e)
    case 'gt':
      return a > e
    case 'ge':
      return a >= e
    case 'lt':
      return a < e
    case 'le':
      return a <= e
  }
}

/** The values a path resolves to on `obj` (multi-valued attributes are flattened). */
function values(obj: unknown, path: AttrPath): unknown[] {
  const top = getProp(obj, path.attr)
  const list = Array.isArray(top) ? top : top === undefined ? [] : [top]
  // A complex attribute compared as a whole is compared through its `value` sub-attribute.
  if (!path.sub) {
    return list.map((v) =>
      v && typeof v === 'object' && !Array.isArray(v) ? getProp(v, 'value') : v,
    )
  }
  const out: unknown[] = []
  for (const item of list) {
    const v = getProp(item, path.sub)
    if (Array.isArray(v)) out.push(...v)
    else if (v !== undefined) out.push(v)
  }
  return out
}

const present = (v: unknown) =>
  v !== null && v !== undefined && v !== '' && !(Array.isArray(v) && v.length === 0)

export function matches(resource: unknown, f: Filter, inValue = false): boolean {
  switch (f.kind) {
    case 'and':
      return matches(resource, f.left, inValue) && matches(resource, f.right, inValue)
    case 'or':
      return matches(resource, f.left, inValue) || matches(resource, f.right, inValue)
    case 'not':
      return !matches(resource, f.filter, inValue)
    case 'pr': {
      const target = inValue ? resource : container(resource as Json, f.path)
      return values(target, f.path).some(present)
    }
    case 'cmp': {
      const target = inValue ? resource : container(resource as Json, f.path)
      const name = (f.path.sub ?? f.path.attr).toLowerCase()
      const caseExact = CASE_EXACT.has(name) || (inValue && name === 'value')
      const vals = values(target, f.path)
      if (vals.length === 0) return compare(undefined, f.op, f.value, caseExact)
      return vals.some((v) => compare(v, f.op, f.value, caseExact))
    }
    case 'value': {
      const target = container(resource as Json, f.path)
      const raw = getProp(target, f.path.attr)
      const items = Array.isArray(raw) ? raw : raw === undefined ? [] : [raw]
      return items.some(
        (item) => matches(item, f.filter, true) && (!f.then || matches(item, f.then, true)),
      )
    }
  }
}
