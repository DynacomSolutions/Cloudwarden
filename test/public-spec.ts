// Validates a response body against the Public API schemas of docs/api/openapi.yaml.
import { Validator } from '@cfworker/json-schema'
import { expect } from 'vitest'
import { parse } from 'yaml'
import raw from '../docs/api/openapi.yaml?raw'

type Json = any
export const spec = parse(raw) as Json
const SPEC_URI = 'https://spec.example.com/openapi'
const absolute = (node: Json): Json => {
  if (Array.isArray(node)) return node.map(absolute)
  if (node && typeof node === 'object') {
    return Object.fromEntries(
      Object.entries(node).map(([k, v]) => [
        k,
        k === '$ref' && typeof v === 'string' && v.startsWith('#/') ? SPEC_URI + v : absolute(v),
      ]),
    )
  }
  return node
}
const specDoc = { $id: SPEC_URI, components: absolute(spec.components) }
const resolve = (node: Json): Json =>
  node?.$ref?.startsWith('#/')
    ? node.$ref
        .slice(2)
        .split('/')
        .reduce((a: Json, k: string) => a[k], spec)
    : node

/** Asserts `body` matches the documented response of `METHOD /path` for `status`. */
export function conforms(op: string, status: number, body: unknown) {
  const [method, path] = op.split(' ') as [string, string]
  const operation = spec.paths[path]?.[method.toLowerCase()]
  expect(operation, `${op} is not in the spec`).toBeDefined()
  const response = resolve(operation.responses[String(status)])
  expect(response, `${op} documents no ${status}`).toBeDefined()
  const schema = response.content?.['application/json']?.schema
  if (!schema) return
  const v = new Validator(absolute(schema), '2020-12', false)
  v.addSchema(specDoc)
  const r = v.validate(body)
  expect(
    r.valid,
    `${op} ${status}: ${r.errors.map((e) => `${e.instanceLocation} ${e.error}`).join('; ')}`,
  ).toBe(true)
}
