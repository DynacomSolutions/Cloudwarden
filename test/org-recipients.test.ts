import { env } from 'cloudflare:test'
import { eq } from 'drizzle-orm'
import { expect, it } from 'vitest'
import { createDb, schema } from '../src/db'
import { loadUserAccess } from '../src/orgs/access'
import { itemAccess, linkedCollections } from '../src/orgs/ciphers'
import { activeMemberIds, cipherRecipients } from '../src/orgs/notify'
import { actor, addMember, createOrg, loginCipher } from './org-helpers'

it('cipherRecipients matches the per-member itemAccess semantics', async () => {
  const owner = await actor('rcpt-owner@example.com')
  const names = ['all', 'direct', 'group', 'groupall', 'accepted', 'none'] as const
  const u = Object.fromEntries(
    await Promise.all(names.map(async (n) => [n, await actor(`rcpt-${n}@example.com`)])),
  ) as Record<(typeof names)[number], Awaited<ReturnType<typeof actor>>>
  const { id, defaultCollectionId } = await createOrg(owner)
  const grant = [{ id: defaultCollectionId, readOnly: false }]
  const ou = {
    all: await addMember(owner, id, u.all, { accessAll: true }),
    direct: await addMember(owner, id, u.direct, { collections: grant }),
    group: await addMember(owner, id, u.group),
    groupall: await addMember(owner, id, u.groupall),
    accepted: await addMember(owner, id, u.accepted, { accessAll: true, collections: grant }),
    none: await addMember(owner, id, u.none),
  }
  const g = (body: object) => owner.json(`/api/organizations/${id}/groups`, 'POST', body)
  await g({ name: 'g', accessAll: false, collections: grant, users: [ou.group] })
  await g({ name: 'ga', accessAll: true, collections: [], users: [ou.groupall] })
  const item = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.rcpt', { organizationId: id }),
    collectionIds: [defaultCollectionId],
  })
  const db = createDb(env.DB)
  // Accepted but not Confirmed: the old code gave such a member no access at all.
  await db
    .update(schema.usersOrganizations)
    .set({ status: 1 })
    .where(eq(schema.usersOrganizations.uuid, ou.accepted))

  const cipher = { uuid: item.id as string, organizationUuid: id }
  const linked = await linkedCollections(db, cipher.uuid)
  const old: string[] = []
  for (const m of await activeMemberIds(db, id)) {
    if (itemAccess(await loadUserAccess(db, m), id, linked)) old.push(m)
  }
  const got = await cipherRecipients(db, cipher)
  expect([...got].sort()).toEqual([...old].sort())
  expect([...got].sort()).toEqual(
    [owner.uuid, u.all.uuid, u.direct.uuid, u.group.uuid, u.groupall.uuid].sort(),
  )
})
