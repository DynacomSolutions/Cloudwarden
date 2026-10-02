// SCIM 2.0 PATCH (RFC 7644 section 3.5.2) applied to a resource's JSON representation. The routes
// then read the changed attributes back out, so every operation form (with or without a path,
// value filters, sub-attributes, URN-qualified names) behaves the same for users and groups.
import {
  type AttrPath,
  container,
  type Filter,
  getProp,
  matches,
  parseAttrPath,
  parseFilter,
  ScimError,
} from './filter'

type Json = Record<string, unknown>

export interface PatchOp {
  op: string
  path?: string | null
  value?: unknown
}

interface PatchPath {
  path: AttrPath
  filter?: Filter
  /** Sub-attribute after a value filter: `emails[type eq "work"].value`. */
  sub?: string
}

const invalidPath = (msg: string) => new ScimError(400, msg, 'invalidPath')
const READ_ONLY = new Set(['id', 'meta', 'schemas'])

export function parsePatchPath(raw: string): PatchPath {
  const open = raw.indexOf('[')
  if (open < 0) {
    try {
      return { path: parseAttrPath(raw.trim()) }
    } catch {
      throw invalidPath(`Invalid path "${raw}".`)
    }
  }
  const close = raw.lastIndexOf(']')
  if (close < open) throw invalidPath(`Invalid path "${raw}".`)
  const rest = raw.slice(close + 1)
  if (rest && !/^\.[A-Za-z$][\w$-]*$/.test(rest)) throw invalidPath(`Invalid path "${raw}".`)
  let path: AttrPath
  let filter: Filter
  try {
    path = parseAttrPath(raw.slice(0, open).trim())
    filter = parseFilter(raw.slice(open + 1, close))
  } catch (e) {
    throw e instanceof ScimError ? new ScimError(400, e.message, 'invalidPath') : e
  }
  return { path, filter, sub: rest ? rest.slice(1) : undefined }
}

function keyOf(obj: Json, name: string): string {
  const lower = name.toLowerCase()
  return Object.keys(obj).find((k) => k.toLowerCase() === lower) ?? name
}

function setProp(obj: Json, name: string, value: unknown) {
  obj[keyOf(obj, name)] = value
}

function deleteProp(obj: Json, name: string) {
  delete obj[keyOf(obj, name)]
}

/** The object a path writes into, created for extension URNs that are not there yet. */
function holder(resource: Json, path: AttrPath, create: boolean): Json | undefined {
  const c = container(resource, path)
  if (c && typeof c === 'object') return c as Json
  if (!create || !path.urn) return undefined
  const ext: Json = {}
  resource[path.urn] = ext
  return ext
}

const sameItem = (a: unknown, b: unknown) => {
  const av = getProp(a, 'value')
  const bv = getProp(b, 'value')
  if (av !== undefined && bv !== undefined) return String(av) === String(bv)
  return JSON.stringify(a) === JSON.stringify(b)
}

/** Builds a new element from a simple `attr eq "x"` filter (for add or replace with no match). */
function seedFrom(filter: Filter): Json | null {
  if (filter.kind === 'cmp' && filter.op === 'eq' && !filter.path.sub) {
    return { [filter.path.attr]: filter.value }
  }
  if (filter.kind === 'and') {
    const l = seedFrom(filter.left)
    const r = seedFrom(filter.right)
    return l && r ? { ...l, ...r } : null
  }
  return null
}

function applyOne(resource: Json, op: 'add' | 'replace' | 'remove', pp: PatchPath, value: unknown) {
  const { path } = pp
  if (!path.urn && READ_ONLY.has(path.attr.toLowerCase())) return
  // `urn:...:enterprise:2.0:User` alone names the whole extension object.
  if (path.urn && !path.attr) {
    if (op === 'remove') {
      deleteProp(resource, path.urn)
      return
    }
    const ext = holder(resource, path, true) as Json
    applyObject(ext, op, value)
    return
  }
  const target = holder(resource, path, op !== 'remove')
  if (!target) {
    if (op === 'remove') return
    throw invalidPath('Unknown schema extension.')
  }

  if (pp.filter) {
    const current = getProp(target, path.attr)
    const list = Array.isArray(current) ? (current as Json[]) : []
    const hits = list.filter((item) => matches(item, pp.filter as Filter, true))
    if (op === 'remove') {
      if (pp.sub) {
        for (const item of hits) deleteProp(item, pp.sub)
      } else {
        setProp(
          target,
          path.attr,
          list.filter((item) => !hits.includes(item)),
        )
      }
      return
    }
    if (hits.length === 0) {
      const seed = seedFrom(pp.filter)
      if (!seed) throw new ScimError(400, 'No value matched the path filter.', 'noTarget')
      const item = pp.sub ? { ...seed, [pp.sub]: value } : { ...seed, ...(value as Json) }
      setProp(target, path.attr, [...list, item])
      return
    }
    for (const item of hits) {
      if (pp.sub) setProp(item, pp.sub, value)
      else if (value && typeof value === 'object' && !Array.isArray(value)) {
        if (op === 'replace') for (const k of Object.keys(item)) delete item[k]
        Object.assign(item, value)
      } else throw new ScimError(400, 'A complex value is required.', 'invalidValue')
    }
    return
  }

  if (path.sub) {
    const parentValue = getProp(target, path.attr)
    if (Array.isArray(parentValue)) {
      // `emails.value` addresses every element.
      for (const item of parentValue as Json[]) {
        if (op === 'remove') deleteProp(item, path.sub)
        else setProp(item, path.sub, value)
      }
      return
    }
    if (op === 'remove') {
      if (parentValue && typeof parentValue === 'object') deleteProp(parentValue as Json, path.sub)
      return
    }
    const parent =
      parentValue && typeof parentValue === 'object' ? (parentValue as Json) : ({} as Json)
    setProp(parent, path.sub, value)
    setProp(target, path.attr, parent)
    return
  }

  const current = getProp(target, path.attr)
  if (op === 'remove') {
    if (Array.isArray(current) && value !== undefined && value !== null) {
      // Entra ID: `{ op: Remove, path: members, value: [{ value: id }] }`.
      const drop = Array.isArray(value) ? value : [value]
      setProp(
        target,
        path.attr,
        current.filter((item) => !drop.some((d) => sameItem(item, d))),
      )
    } else {
      deleteProp(target, path.attr)
    }
    return
  }
  if (op === 'add' && (Array.isArray(current) || Array.isArray(value))) {
    const base = Array.isArray(current) ? current : current === undefined ? [] : [current]
    const extra = Array.isArray(value) ? value : [value]
    const merged = [...base]
    for (const v of extra) if (!merged.some((m) => sameItem(m, v))) merged.push(v)
    setProp(target, path.attr, merged)
    return
  }
  if (
    op === 'add' &&
    current &&
    typeof current === 'object' &&
    value &&
    typeof value === 'object' &&
    !Array.isArray(value)
  ) {
    Object.assign(current as Json, value)
    return
  }
  setProp(target, path.attr, value)
}

/** `add` or `replace` without a path: each member of the value object is applied by name. */
function applyObject(resource: Json, op: 'add' | 'replace' | 'remove', value: unknown) {
  if (op === 'remove') throw new ScimError(400, 'A path is required to remove.', 'noTarget')
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ScimError(400, 'The value must be an object when no path is given.', 'invalidValue')
  }
  for (const [k, v] of Object.entries(value as Json)) {
    if (/^urn:/i.test(k) && v && typeof v === 'object' && !Array.isArray(v)) {
      const isCore =
        Array.isArray(resource.schemas) &&
        (resource.schemas as string[]).some((s) => s.toLowerCase() === k.toLowerCase()) &&
        getProp(resource, k) === undefined &&
        /:core:/i.test(k)
      if (isCore) {
        applyObject(resource, op, v)
        continue
      }
      const ext = (getProp(resource, k) as Json | undefined) ?? {}
      setProp(resource, k, ext)
      applyObject(ext, op, v)
      continue
    }
    applyOne(resource, op, parsePatchPath(k), v)
  }
}

export const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp'

/** Applies the operations to a copy of `resource` and returns it. */
export function applyPatch(resource: Json, operations: PatchOp[]): Json {
  const out = structuredClone(resource)
  for (const raw of operations) {
    const op = String(raw.op ?? '').toLowerCase()
    if (op !== 'add' && op !== 'replace' && op !== 'remove') {
      throw new ScimError(400, `Unsupported operation "${raw.op}".`, 'invalidSyntax')
    }
    if (raw.path === undefined || raw.path === null || raw.path === '') {
      applyObject(out, op, raw.value)
    } else {
      applyOne(out, op, parsePatchPath(raw.path), raw.value)
    }
  }
  return out
}

/** Reads a SCIM boolean, accepting the `"True"`/`"False"` strings Entra ID sends. */
export function scimBool(v: unknown): boolean | undefined {
  if (typeof v === 'boolean') return v
  if (typeof v === 'string') {
    const s = v.trim().toLowerCase()
    if (s === 'true') return true
    if (s === 'false') return false
  }
  return undefined
}
