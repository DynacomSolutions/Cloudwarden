// Bounded reads of chunked import bodies (TASKS #417): the organisation import checks permission
// before it reads the body, and refuses an over-cap stream without a Content-Length.
import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'
import { MAX_IMPORT_BYTES } from '../src/routes/org-import'
import { BASE } from './helpers'
import { actor, addMember, createOrg, mailbox } from './org-helpers'

/** A JSON body of about `size` bytes sent as a stream, so it carries no Content-Length. */
const streamed = (token: string, orgId: string, size: number) => {
  const head = '{"users":[{"email":"s1@example.com","externalId":"s1","deleted":false}],"pad":"'
  const bytes = new TextEncoder().encode(`${head}${'x'.repeat(Math.max(0, size - head.length))}"}`)
  const stream = new ReadableStream({
    start(ctrl) {
      for (let i = 0; i < bytes.length; i += 65_536) ctrl.enqueue(bytes.slice(i, i + 65_536))
      ctrl.close()
    },
  })
  return SELF.fetch(`${BASE}/api/organizations/${orgId}/import`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: stream,
    duplex: 'half',
  } as RequestInit)
}

it('reads a chunked organisation import within the cap and refuses one over it', async () => {
  const mb = mailbox()
  const owner = await actor('bounded-owner@example.com', mb)
  const { id } = await createOrg(owner, 'Bounded Import')
  expect((await streamed(owner.token, id, 1_000_000)).status).toBe(200)
  const res = await streamed(owner.token, id, MAX_IMPORT_BYTES + 200_000)
  expect(res.status).toBe(413)
  expect(await res.json()).toMatchObject({ message: 'The import is too large.' })
})

it('checks permission before reading the body', async () => {
  const mb = mailbox()
  const owner = await actor('bounded-perm-owner@example.com', mb)
  const { id } = await createOrg(owner, 'Bounded Perm')
  const plain = await actor('bounded-perm-plain@example.com', mb)
  await addMember(owner, id, plain, {}, mb)
  const outsider = await actor('bounded-perm-out@example.com', mb)
  const big = MAX_IMPORT_BYTES + 200_000
  expect((await streamed(plain.token, id, big)).status).toBe(403)
  expect((await streamed(outsider.token, id, big)).status).toBe(404)
})
