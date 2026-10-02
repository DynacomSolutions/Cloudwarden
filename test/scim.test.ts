// SCIM 2.0 (TASKS #273): filter and PATCH conformance with RFC 7644 examples, then the request
// sequences Microsoft Entra ID and Okta send when provisioning and deprovisioning.
import { beforeAll, describe, expect, it } from 'vitest'
import { matches, parseFilter, ScimError } from '../src/scim/filter'
import { applyPatch } from '../src/scim/patch'
import { bearer, orgApiKey, raw } from './org-api-helpers'
import { type Actor, actor, addMember, createOrg, mail } from './org-helpers'

const user = {
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
  id: '2819c223-7f76-453a-919d-413861904646',
  externalId: 'Ext-1',
  userName: 'Bjensen@Example.com',
  name: { familyName: 'Jensen', givenName: 'Barbara' },
  title: 'Tour Guide',
  userType: 'Employee',
  active: true,
  emails: [
    { value: 'bjensen@example.com', type: 'work', primary: true },
    { value: 'babs@jensen.org', type: 'home' },
  ],
  meta: { lastModified: '2011-05-13T04:42:34Z' },
  'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': { employeeNumber: '701984' },
}

describe('filter (RFC 7644 section 3.4.2)', () => {
  const t = (f: string) => matches(user, parseFilter(f))
  it('evaluates the RFC examples', () => {
    expect(t('userName Eq "bjensen@example.com"')).toBe(true)
    expect(t('name.familyName co "ens"')).toBe(true)
    expect(t('userName sw "BJ"')).toBe(true)
    expect(t('title pr')).toBe(true)
    expect(t('nickName pr')).toBe(false)
    expect(t('meta.lastModified gt "2011-05-13T04:42:34Z"')).toBe(false)
    expect(t('meta.lastModified ge "2011-05-13T04:42:34Z"')).toBe(true)
    expect(t('meta.lastModified lt "2011-05-14T00:00:00Z"')).toBe(true)
    expect(t('title pr and userType eq "Employee"')).toBe(true)
    expect(t('title pr or userType eq "Intern"')).toBe(true)
    expect(
      t('userType eq "Employee" and (emails co "example.com" or emails.value co "example.org")'),
    ).toBe(true)
    expect(
      t(
        'userType ne "Employee" and not (emails co "example.com" or emails.value co "example.org")',
      ),
    ).toBe(false)
    expect(t('userType eq "Employee" and (emails.type eq "work")')).toBe(true)
    expect(t('userType eq "Employee" and emails[type eq "work" and value co "@example.com"]')).toBe(
      true,
    )
    expect(t('emails[type eq "home" and value co "@example.com"]')).toBe(false)
    expect(t('emails[type eq "work"].value eq "bjensen@example.com"')).toBe(true)
    expect(t('active eq true')).toBe(true)
    expect(t('active eq false')).toBe(false)
    expect(
      t('urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq "701984"'),
    ).toBe(true)
    expect(t('urn:ietf:params:scim:schemas:core:2.0:User:userName sw "bj"')).toBe(true)
  })
  it('compares id and externalId case-exactly, other strings without case', () => {
    expect(t('externalId eq "Ext-1"')).toBe(true)
    expect(t('externalId eq "ext-1"')).toBe(false)
    expect(t('userName eq "BJENSEN@EXAMPLE.COM"')).toBe(true)
    expect(t('userName ew ".com"')).toBe(true)
  })
  it('gives precedence to and over or and handles escapes', () => {
    expect(t('userType eq "Intern" and title pr or active eq true')).toBe(true)
    expect(t('userType eq "Intern" and (title pr or active eq true)')).toBe(false)
    expect(matches({ displayName: 'Say "hi"' }, parseFilter('displayName eq "Say \\"hi\\""'))).toBe(
      true,
    )
  })
  it('rejects malformed filters with invalidFilter', () => {
    for (const bad of [
      'userName',
      'userName eq',
      'userName zz "x"',
      '(userName eq "x"',
      'userName eq "x',
      'a eq "x" b',
    ]) {
      expect(() => parseFilter(bad), bad).toThrowError(ScimError)
      try {
        parseFilter(bad)
      } catch (e) {
        expect((e as ScimError).scimType).toBe('invalidFilter')
      }
    }
  })
})

describe('PATCH (RFC 7644 3.5.2)', () => {
  const group = {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    id: 'g1',
    displayName: 'Tour Guides',
    members: [{ value: 'a' }, { value: 'b' }],
  }
  it('adds, replaces and removes members in every documented form', () => {
    expect(
      applyPatch(group, [{ op: 'add', path: 'members', value: [{ value: 'c' }, { value: 'a' }] }])
        .members,
    ).toEqual([{ value: 'a' }, { value: 'b' }, { value: 'c' }])
    expect(applyPatch(group, [{ op: 'remove', path: 'members[value eq "a"]' }]).members).toEqual([
      { value: 'b' },
    ])
    // Entra ID form.
    expect(
      applyPatch(group, [{ op: 'Remove', path: 'members', value: [{ value: 'b' }] }]).members,
    ).toEqual([{ value: 'a' }])
    expect(applyPatch(group, [{ op: 'remove', path: 'members' }]).members).toBeUndefined()
    expect(
      applyPatch(group, [{ op: 'replace', path: 'members', value: [{ value: 'z' }] }]).members,
    ).toEqual([{ value: 'z' }])
    // Okta form: no path, value object; id is read-only and ignored.
    const okta = applyPatch(group, [
      { op: 'replace', value: { id: 'other', displayName: 'Guides' } },
    ])
    expect(okta).toMatchObject({ id: 'g1', displayName: 'Guides' })
  })
  it('patches users: sub-attributes, value paths, extensions and Entra string booleans', () => {
    let u = applyPatch(user, [{ op: 'Replace', path: 'active', value: 'False' }])
    expect(u.active).toBe('False')
    u = applyPatch(user, [{ op: 'replace', path: 'name.givenName', value: 'Babs' }])
    expect((u.name as any).givenName).toBe('Babs')
    u = applyPatch(user, [
      { op: 'replace', path: 'emails[type eq "work"].value', value: 'new@example.com' },
    ])
    expect((u.emails as any[])[0].value).toBe('new@example.com')
    expect((u.emails as any[])[1].value).toBe('babs@jensen.org')
    u = applyPatch(user, [
      { op: 'add', path: 'emails[type eq "other"].value', value: 'o@example.com' },
    ])
    expect(u.emails as any[]).toHaveLength(3)
    u = applyPatch(user, [
      {
        op: 'add',
        path: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department',
        value: 'Sales',
      },
    ])
    expect(
      (u['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'] as any).department,
    ).toBe('Sales')
    u = applyPatch(user, [{ op: 'replace', value: { active: false, 'name.familyName': 'J' } }])
    expect(u.active).toBe(false)
    expect((u.name as any).familyName).toBe('J')
    u = applyPatch(user, [{ op: 'remove', path: 'emails[type eq "home"]' }])
    expect(u.emails).toHaveLength(1)
  })
  it('reports bad operations with RFC error types', () => {
    const scimType = (f: () => unknown) => {
      try {
        f()
      } catch (e) {
        return (e as ScimError).scimType
      }
      return null
    }
    expect(scimType(() => applyPatch(user, [{ op: 'move', path: 'x' }]))).toBe('invalidSyntax')
    expect(scimType(() => applyPatch(user, [{ op: 'remove' }]))).toBe('noTarget')
    expect(scimType(() => applyPatch(user, [{ op: 'replace', path: 'emails[type eq' }]))).toBe(
      'invalidPath',
    )
    expect(
      scimType(() => applyPatch(user, [{ op: 'replace', path: 'emails[type co "x"]', value: {} }])),
    ).toBe('noTarget')
  })
})

describe('SCIM service', () => {
  let owner: Actor
  let orgId: string
  let key: string
  const s = async (path: string, method = 'GET', body?: unknown, k = key) => {
    const res = await raw(`/scim/v2/${orgId}${path}`, {
      method,
      headers: { ...bearer(k), 'Content-Type': 'application/scim+json' },
      body,
    })
    const text = await res.text()
    return {
      status: res.status,
      type: res.headers.get('Content-Type'),
      body: text ? JSON.parse(text) : null,
      res,
    }
  }

  beforeAll(async () => {
    owner = await actor('scim-owner@example.com')
    orgId = (await createOrg(owner, 'SCIM Org')).id
    key = await orgApiKey(owner, orgId, 2)
  })

  it('needs SCIM enabled and the SCIM key', async () => {
    expect((await s('/Users')).status).toBe(401)
    const cfg = await owner.json(`/api/organizations/${orgId}/scim-config`, 'PUT', {
      enabled: true,
      provider: 1,
    })
    expect(cfg).toMatchObject({
      enabled: true,
      provider: 1,
      hasApiKey: true,
      scimUrl: `https://vault.example.com/scim/v2/${orgId}`,
    })
    const wrong = await s('/Users', 'GET', undefined, 'not-the-key')
    expect(wrong.status).toBe(401)
    expect(wrong.body).toMatchObject({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '401',
    })
    // The Public API key is not the SCIM key.
    const publicKey = await orgApiKey(owner, orgId, 0)
    expect((await s('/Users', 'GET', undefined, publicKey)).status).toBe(401)
    const ok = await s('/Users')
    expect(ok.status).toBe(200)
    expect(ok.type).toContain('application/scim+json')
    // A plain member cannot read or change the SCIM settings.
    const plain = await actor('scim-plain@example.com')
    await addMember(owner, orgId, plain)
    expect((await plain.call(`/api/organizations/${orgId}/scim-config`)).status).toBe(403)
  })

  it('serves discovery documents', async () => {
    const spc = await s('/ServiceProviderConfig')
    expect(spc.body).toMatchObject({
      patch: { supported: true },
      filter: { supported: true },
      bulk: { supported: false },
    })
    const types = await s('/ResourceTypes')
    expect(types.body.Resources.map((r: any) => r.id)).toEqual(['User', 'Group'])
    expect((await s('/ResourceTypes/User')).body.endpoint).toBe('/Users')
    const schemas = await s('/Schemas')
    expect(schemas.body.totalResults).toBe(2)
    expect((await s('/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group')).body.name).toBe(
      'Group',
    )
    // The cloud path layout answers too.
    const cloud = await raw(`/v2/${orgId}/Users`, { headers: bearer(key) })
    expect(cloud.status).toBe(200)
  })

  it('provisions and deprovisions users the way Entra ID does', async () => {
    // Entra checks for the user first.
    const miss = await s(
      `/Users?filter=${encodeURIComponent('userName eq "entra.user@example.com"')}`,
    )
    expect(miss.body).toMatchObject({ totalResults: 0, Resources: [] })
    const before = mail.sent.length
    const created = await s('/Users', 'POST', {
      schemas: [
        'urn:ietf:params:scim:schemas:core:2.0:User',
        'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User',
      ],
      externalId: 'entra-object-1',
      userName: 'Entra.User@example.com',
      active: true,
      displayName: 'Entra User',
      emails: [{ primary: true, type: 'work', value: 'Entra.User@example.com' }],
      meta: { resourceType: 'User' },
      name: { formatted: 'Entra User', familyName: 'User', givenName: 'Entra' },
    })
    expect(created.status).toBe(201)
    expect(created.res.headers.get('Location')).toBe(created.body.meta.location)
    expect(created.body).toMatchObject({
      userName: 'entra.user@example.com',
      externalId: 'entra-object-1',
      active: true,
    })
    expect(mail.sent.length).toBe(before + 1)
    const id = created.body.id

    const dup = await s('/Users', 'POST', { userName: 'entra.user@example.com', externalId: 'x' })
    expect(dup.status).toBe(409)
    expect(dup.body.scimType).toBe('uniqueness')

    const found = await s(`/Users?filter=${encodeURIComponent('externalId eq "entra-object-1"')}`)
    expect(found.body.Resources.map((r: any) => r.id)).toEqual([id])

    // Disable in Entra ID: PATCH active "False" revokes the member.
    const off = await s(`/Users/${id}`, 'PATCH', {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'Replace', path: 'active', value: 'False' }],
    })
    expect(off.status).toBe(200)
    expect(off.body.active).toBe(false)
    const members = await owner.json(`/api/organizations/${orgId}/users`)
    expect(members.data.find((m: any) => m.id === id).status).toBe(-1)
    // Re-enable: restored to invited (no account yet).
    const on = await s(`/Users/${id}`, 'PATCH', {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'Replace', path: 'active', value: 'True' }],
    })
    expect(on.body.active).toBe(true)
    expect((await owner.json(`/api/organizations/${orgId}/users/${id}`)).status).toBe(0)

    // Attribute changes Entra sends that the server does not store are accepted.
    const noop = await s(`/Users/${id}`, 'PATCH', {
      Operations: [
        { op: 'Add', path: 'name.givenName', value: 'E' },
        { op: 'Replace', path: 'externalId', value: 'entra-object-1b' },
      ],
    })
    expect(noop.status).toBe(200)
    expect(noop.body.externalId).toBe('entra-object-1b')

    const events = await owner.json(`/api/organizations/${orgId}/events`)
    const scimEvents = events.data.filter((e: any) => e.systemUser === 1).map((e: any) => e.type)
    expect(scimEvents).toEqual(expect.arrayContaining([1500, 1511, 1512, 1502]))

    expect((await s(`/Users/${id}`, 'DELETE')).status).toBe(204)
    expect((await s(`/Users/${id}`)).status).toBe(404)
  })

  it('handles Okta user PUT, pagination and attribute selection', async () => {
    const ids: string[] = []
    for (const n of [1, 2, 3]) {
      const r = await s('/Users', 'POST', {
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        userName: `okta${n}@example.com`,
        name: { givenName: 'Okta', familyName: String(n) },
        emails: [{ primary: true, value: `okta${n}@example.com`, type: 'work' }],
        active: true,
      })
      ids.push(r.body.id)
    }
    const page = await s(
      `/Users?filter=${encodeURIComponent('userName sw "okta"')}&startIndex=2&count=1`,
    )
    expect(page.body).toMatchObject({ totalResults: 3, startIndex: 2, itemsPerPage: 1 })
    const slim = await s(`/Users/${ids[0]}?attributes=userName`)
    expect(Object.keys(slim.body).sort()).toEqual(['id', 'meta', 'schemas', 'userName'])
    // Okta deactivates with a PUT of the whole user.
    const put = await s(`/Users/${ids[0]}`, 'PUT', {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      id: ids[0],
      userName: 'okta1@example.com',
      active: false,
    })
    expect(put.body.active).toBe(false)
    // Owners cannot be revoked or deleted through SCIM.
    const ownerRow = (await owner.json(`/api/organizations/${orgId}/users`)).data.find(
      (m: any) => m.type === 0,
    )
    const ownerOff = await s(`/Users/${ownerRow.id}`, 'PATCH', {
      Operations: [{ op: 'replace', path: 'active', value: false }],
    })
    expect(ownerOff.status).toBe(403)
    expect((await s(`/Users/${ownerRow.id}`, 'DELETE')).status).toBe(403)
    const badFilter = await s(`/Users?filter=${encodeURIComponent('userName eq')}`)
    expect(badFilter.status).toBe(400)
    expect(badFilter.body.scimType).toBe('invalidFilter')
  })

  it('manages groups with Entra and Okta membership patches', async () => {
    const a = (await s('/Users', 'POST', { userName: 'g-a@example.com' })).body.id
    const b = (await s('/Users', 'POST', { userName: 'g-b@example.com' })).body.id
    const g = await s('/Groups', 'POST', {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      displayName: 'Sales',
      externalId: 'grp-sales',
      members: [{ value: a }],
    })
    expect(g.status).toBe(201)
    expect(g.body.members.map((m: any) => m.value)).toEqual([a])
    const gid = g.body.id
    expect(
      (await s('/Groups', 'POST', { displayName: 'Sales', externalId: 'grp-sales' })).status,
    ).toBe(409)

    // Entra: add then remove with a value array.
    let r = await s(`/Groups/${gid}`, 'PATCH', {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'Add', path: 'members', value: [{ value: b }] }],
    })
    expect(r.body.members.map((m: any) => m.value).sort()).toEqual([a, b].sort())
    const membership = await s(
      `/Groups?filter=${encodeURIComponent(`id eq "${gid}" and members[value eq "${b}"]`)}&excludedAttributes=members`,
    )
    expect(membership.body.totalResults).toBe(1)
    expect(membership.body.Resources[0].members).toBeUndefined()
    r = await s(`/Groups/${gid}`, 'PATCH', {
      Operations: [{ op: 'Remove', path: 'members', value: [{ value: a }] }],
    })
    expect(r.body.members.map((m: any) => m.value)).toEqual([b])
    // Okta: rename without a path, remove with a value filter.
    r = await s(`/Groups/${gid}`, 'PATCH', {
      Operations: [
        { op: 'replace', value: { id: gid, displayName: 'Sales EMEA' } },
        { op: 'remove', path: `members[value eq "${b}"]` },
      ],
    })
    expect(r.body).toMatchObject({ displayName: 'Sales EMEA', members: [] })
    const bad = await s(`/Groups/${gid}`, 'PATCH', {
      Operations: [
        { op: 'add', path: 'members', value: [{ value: '00000000-0000-0000-0000-000000000000' }] },
      ],
    })
    expect(bad.status).toBe(400)
    const byName = await s(`/Groups?filter=${encodeURIComponent('displayName eq "sales emea"')}`)
    expect(byName.body.totalResults).toBe(1)
    // The Admin Console sees the same group.
    const groups = await owner.json(`/api/organizations/${orgId}/groups`)
    expect(groups.data.find((x: any) => x.id === gid)).toMatchObject({
      name: 'Sales EMEA',
      externalId: 'grp-sales',
    })
    const put = await s(`/Groups/${gid}`, 'PUT', { displayName: 'Sales', members: [{ value: a }] })
    expect(put.body.members).toHaveLength(1)
    expect((await s(`/Groups/${gid}`, 'DELETE')).status).toBe(204)
    expect((await s(`/Groups/${gid}`)).status).toBe(404)
  })

  it('stops answering once disabled or the key is rotated', async () => {
    const rotated = await orgApiKey(owner, orgId, 2, true)
    expect((await s('/Users')).status).toBe(401)
    expect((await s('/Users', 'GET', undefined, rotated)).status).toBe(200)
    await owner.call(`/api/organizations/${orgId}/scim-config`, 'PUT', { enabled: false })
    expect((await s('/Users', 'GET', undefined, rotated)).status).toBe(401)
  })
})
