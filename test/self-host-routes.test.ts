// Every row the parity matrix marks `self-host` (TASKS #231) must be served: signed-in callers get
// the self-hosted answer, anonymous callers a 401, and the route must never fall through to the
// router's "Not found" page, which clients would show as a broken feature.
import { SELF } from 'cloudflare:test'
import { describe, expect, it } from 'vitest'
import notes from '../docs/parity/notes.tsv?raw'
import { BASE } from './helpers'
import { actor } from './org-helpers'

const ID = '00000000-0000-0000-0000-000000000000'
const rows = notes
  .split('\n')
  .map((l) => l.split('\t'))
  .filter((c) => c[2] === 'self-host')
  .map(([method, path]) => [method as string, path as string] as const)

const concrete = (p: string) => p.replace(/\{[^}]*\}|\([^)]*\)/g, ID).replace(/\/\//g, '/')

describe('self-hosted answers', () => {
  it('lists the rows', () => {
    expect(rows.length).toBeGreaterThan(100)
  })

  it('serves every row to signed-in callers and refuses anonymous ones', async () => {
    const a = await actor('self-host-routes@example.com')
    const unrouted: string[] = []
    const open: string[] = []
    for (const [method, path] of rows) {
      const url = concrete(path)
      const hasBody = !['GET', 'DELETE'].includes(method)
      const res = await a.call(url, method, hasBody ? {} : undefined)
      if (res.status === 404 && (await res.text()).includes('"Not found"'))
        unrouted.push(`${method} ${path}`)
      const anon = await SELF.fetch(`${BASE}${url}`, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: hasBody ? '{}' : undefined,
      })
      if (anon.status !== 401) open.push(`${method} ${path} ${anon.status}`)
    }
    expect(unrouted).toEqual([])
    expect(open).toEqual([])
  })
})
