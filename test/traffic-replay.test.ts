// Recorded client traffic (TASKS #367, #387, #388): sanitised captures of the official Bitwarden CLI,
// web vault and Android app driving a local server (scripts/capture-traffic.mjs,
// scripts/capture-web-traffic.mjs, scripts/capture-android-traffic.mjs, docs/traffic-fixtures.md)
// are replayed against the
// Worker. Each fixture starts from a freshly registered account, rebinds tokens and ids from the
// live responses into later requests, and checks
//   - the recording itself is free of identifying data,
//   - recorded requests and responses conform to docs/api/openapi.yaml,
//   - live responses conform to the same schemas, and
//   - live responses have the same JSON shape (keys and value types) as the recording.
/// <reference types="vite/client" />
import { SELF } from 'cloudflare:test'
import { beforeAll, describe, expect, it } from 'vitest'
import {
  createSanitiser,
  FIXED_EMAIL,
  findIdentifying,
  PLACEHOLDER,
  WHOLE_PLACEHOLDER,
} from '../scripts/traffic-sanitise.mjs'
import { normalizeKeys } from '../src/validation'
import { BASE, registerUser } from './helpers'
import { findOperation, type Json, requestErrors, responseErrors } from './spec'

interface Exchange {
  method: string
  path: string
  headers: Record<string, string>
  requestBody?: Json
  requestForm?: Record<string, string>
  status: number
  responseBody?: Json
}
interface Fixture {
  client: string
  clientVersion: string
  scenario: string
  flows: string[]
  exchanges: Exchange[]
}

const fixtures = Object.entries(
  import.meta.glob('./fixtures/traffic/*.json', { eager: true, import: 'default' }),
).map(([file, data]) => ({ file: file.split('/').pop() as string, fx: data as Fixture }))

/** Describes a JSON value's shape: keys and primitive types, nulls and array lengths ignored. */
function shapeDiff(recorded: Json, live: Json, path = '$'): string[] {
  if (recorded === null || live === null || recorded === undefined || live === undefined) return []
  if (Array.isArray(recorded) || Array.isArray(live)) {
    if (!(Array.isArray(recorded) && Array.isArray(live))) return [`${path}: array mismatch`]
    return recorded.length && live.length ? shapeDiff(recorded[0], live[0], `${path}[0]`) : []
  }
  if (typeof recorded === 'object' || typeof live === 'object') {
    if (typeof recorded !== typeof live) return [`${path}: ${typeof recorded} vs ${typeof live}`]
    const keys = new Set([...Object.keys(recorded), ...Object.keys(live)])
    return [...keys].flatMap((k) =>
      !(k in recorded)
        ? [`${path}.${k}: not in recording`]
        : !(k in live)
          ? [`${path}.${k}: missing from live response`]
          : shapeDiff(recorded[k], live[k], `${path}.${k}`),
    )
  }
  return typeof recorded === typeof live ? [] : [`${path}: ${typeof recorded} vs ${typeof live}`]
}

/** Form values travel as text; integers are checked as numbers, as the spec types them. */
const typedForm = (form: Record<string, string>) =>
  Object.fromEntries(Object.entries(form).map(([k, v]) => [k, /^-?\d+$/.test(v) ? Number(v) : v]))

const label = (ex: Exchange) => `${ex.method} ${ex.path.split('?')[0]} -> ${ex.status}`

describe('traffic fixtures', () => {
  it('exist for the official CLI, web vault and Android app covering login, sync, cipher writes and Sends', () => {
    const flows = new Set(fixtures.flatMap(({ fx }) => fx.flows.map((f) => `${fx.client}:${f}`)))
    for (const client of ['cli', 'web', 'android'])
      for (const f of ['login', 'sync', 'cipher-write', 'send'])
        expect(flows).toContain(`${client}:${f}`)
    expect(flows).toContain('web:register')
    expect(flows).toContain('android:register')
  })

  it('Android fixtures carry the headers the mobile app sends', () => {
    const android = fixtures.filter(({ fx }) => fx.client === 'android')
    expect(android.length).toBeGreaterThan(0)
    for (const { file, fx } of android)
      for (const ex of fx.exchanges) {
        expect(ex.headers['bitwarden-client-name'], file).toBe('mobile')
        expect(ex.headers['bitwarden-client-version'], file).toBe(fx.clientVersion)
        expect(ex.headers['device-type'], file).toBe('0') // Android
      }
  })

  it('sanitiser replaces identifying data and is idempotent', () => {
    const dirty = {
      email: 'someone@corp.test',
      id: '8c1b2a4e-1111-4222-8333-444455556666',
      key: '2.AbCdEfGhIjKlMnOpQrStUv==|AbCdEfGhIjKlMnOpQrStUv==|AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef=',
      access_token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln',
      url: 'https://127.0.0.1:8443/x',
      revisionDate: '2026-10-06T17:26:43.106Z',
    }
    expect(findIdentifying(dirty).length).toBeGreaterThanOrEqual(6)
    const clean = createSanitiser().value(dirty)
    expect(findIdentifying(clean)).toEqual([])
    expect(createSanitiser().value(clean)).toEqual(clean)
  })

  for (const { file, fx } of fixtures) {
    describe(`${file} (${fx.client} ${fx.clientVersion})`, () => {
      it('contains no identifying data', () => {
        expect(findIdentifying(fx)).toEqual([])
      })

      it('recorded requests and responses conform to the OpenAPI spec', () => {
        const problems: string[] = []
        for (const [i, ex] of fx.exchanges.entries()) {
          const op = findOperation(ex.method, ex.path)
          if (!op) {
            problems.push(`#${i} ${label(ex)}: not in the spec`)
            continue
          }
          if (ex.requestBody !== undefined)
            // The Android app sends some PascalCase keys (`Cipher`, `MasterPasswordAuthentication`);
            // the Worker lowercases their first letter before validating, so the spec check does too.
            for (const e of requestErrors(
              op.operation,
              'application/json',
              normalizeKeys(ex.requestBody),
            ))
              problems.push(`#${i} ${op.key} request ${e}`)
          if (ex.requestForm)
            for (const e of requestErrors(
              op.operation,
              'application/x-www-form-urlencoded',
              typedForm(ex.requestForm),
            ))
              problems.push(`#${i} ${op.key} request ${e}`)
          if (ex.responseBody !== undefined)
            for (const e of responseErrors(op.operation, ex.status, ex.responseBody))
              problems.push(`#${i} ${op.key} ${ex.status} ${e}`)
        }
        expect(problems).toEqual([])
      })

      describe('replay', () => {
        const email = `replay-${file.replace(/\W/g, '-')}@example.com`
        const bindings = new Map<string, string>()
        const sub = (s: string) =>
          s.replaceAll(FIXED_EMAIL, email).replace(PLACEHOLDER, (m: string) => bindings.get(m) ?? m)
        // X-Request-Email is the address as unpadded base64url.
        const subHeader = (k: string, v: string) =>
          k === 'x-request-email'
            ? btoa(sub(atob(v.replaceAll('-', '+').replaceAll('_', '/'))))
                .replaceAll('+', '-')
                .replaceAll('/', '_')
                .replace(/=+$/, '')
            : sub(v)
        const subDeep = (v: Json): Json =>
          typeof v === 'string'
            ? sub(v)
            : Array.isArray(v)
              ? v.map(subDeep)
              : v && typeof v === 'object'
                ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, subDeep(x)]))
                : v
        // Rebinds the placeholders of a recorded response to the values of the live one.
        const bind = (recorded: Json, live: Json) => {
          if (typeof recorded === 'string' && typeof live === 'string') {
            if (!WHOLE_PLACEHOLDER.test(recorded)) return
            if (recorded.startsWith('__') || !bindings.has(recorded)) bindings.set(recorded, live)
          } else if (Array.isArray(recorded) && Array.isArray(live)) {
            for (const [i, r] of recorded.entries()) bind(r, live[i])
          } else if (recorded && live && typeof recorded === 'object' && typeof live === 'object') {
            for (const [k, r] of Object.entries(recorded)) bind(r, (live as Json)[k])
          }
        }

        beforeAll(async () => {
          // A fixture that records the registration itself replays it; the others start from an
          // account registered here with the password hash the recording logs in with.
          if (fx.exchanges.some((e) => e.path.startsWith('/identity/accounts/register/finish')))
            return
          const login = fx.exchanges.find((e) => e.requestForm?.grant_type === 'password')
          const hash = login?.requestForm?.password
          if (!hash) throw new Error('fixture has no password login')
          const res = await registerUser(email, { masterPasswordHash: hash })
          expect(res.status).toBe(200)
        })

        for (const [i, ex] of fx.exchanges.entries()) {
          it(`#${i} ${label(ex)}`, async () => {
            const headers: Record<string, string> = Object.fromEntries(
              Object.entries(ex.headers).map(([k, v]) => [k, subHeader(k, v)]),
            )
            let body: string | undefined
            if (ex.requestBody !== undefined) {
              headers['content-type'] = 'application/json'
              body = JSON.stringify(subDeep(ex.requestBody))
            } else if (ex.requestForm) {
              headers['content-type'] = 'application/x-www-form-urlencoded'
              body = new URLSearchParams(subDeep(ex.requestForm)).toString()
            }
            const res = await SELF.fetch(`${BASE}${sub(ex.path)}`, {
              method: ex.method,
              headers,
              body,
            })
            const text = await res.text()
            expect(res.status, `${label(ex)}: ${text.slice(0, 300)}`).toBe(ex.status)
            if (ex.responseBody === undefined) return
            const live = JSON.parse(text)
            const op = findOperation(ex.method, ex.path)
            expect(op, `${label(ex)} is not in the spec`).toBeDefined()
            if (op) expect(responseErrors(op.operation, res.status, live)).toEqual([])
            expect(shapeDiff(ex.responseBody, live)).toEqual([])
            bind(ex.responseBody, live)
          })
        }
      })
    })
  }
})
