// Shared OpenAPI helpers for the contract and traffic replay tests (docs/api/openapi.yaml).
import { Validator } from '@cfworker/json-schema'
import { parse } from 'yaml'
import raw from '../docs/api/openapi.yaml?raw'

export type Json = any
export const spec = parse(raw) as Json

// Schemas reference each other as `#/components/...`; rewrite to an absolute URI so inline schemas
// from an operation can be validated on their own.
const SPEC_URI = 'https://spec.example.com/openapi'
export const absolute = (node: Json): Json => {
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

export const resolve = (node: Json): Json => {
  if (node?.$ref?.startsWith('#/')) {
    return node.$ref
      .slice(2)
      .split('/')
      .reduce((acc: Json, key: string) => acc[key], spec)
  }
  return node
}

/** Validates `body` against a spec schema; returns error lines (empty when valid). */
export function schemaErrors(schema: Json, body: unknown): string[] {
  const validator = new Validator(absolute(schema), '2020-12', false)
  validator.addSchema(specDoc)
  const result = validator.validate(body)
  return result.valid
    ? []
    : result.errors.slice(0, 5).map((e) => `${e.instanceLocation}: ${e.error}`)
}

const templates = Object.keys(spec.paths).map((template) => ({
  template,
  re: new RegExp(
    `^${template.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{[^}]+\}/g, '[^/]+')}$`,
  ),
  literal: !template.includes('{'),
}))

/** Finds the spec operation for a concrete request; literal paths win over templated ones. */
export function findOperation(method: string, path: string) {
  const pathname = path.split('?')[0] ?? path
  const hits = templates.filter(
    (t) => t.re.test(pathname) && spec.paths[t.template][method.toLowerCase()],
  )
  const best = hits.find((t) => t.literal) ?? hits[0]
  if (!best) return undefined
  return {
    key: `${method.toUpperCase()} ${best.template}`,
    operation: spec.paths[best.template][method.toLowerCase()] as Json,
  }
}

/** Errors for a JSON response body against the documented response; `[]` when it conforms. */
export function responseErrors(operation: Json, status: number, body: unknown): string[] {
  const response = resolve(operation.responses[String(status)] ?? operation.responses.default)
  if (!response) return [`no ${status} response documented`]
  const schema = response.content?.['application/json']?.schema
  return schema ? schemaErrors(schema, body) : []
}

/** Errors for a request body (JSON or form) against the documented request body. */
export function requestErrors(operation: Json, contentType: string, body: unknown): string[] {
  const rb = resolve(operation.requestBody)
  const schema = rb?.content?.[contentType]?.schema
  return schema ? schemaErrors(schema, body) : []
}
