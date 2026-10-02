// Secret versions and Secrets Manager import and export (TASKS #224).
import { beforeAll, describe, expect, it } from 'vitest'
import { authed, form } from './helpers'
import { type Actor, actor, addMember, createOrg } from './org-helpers'

const enc = (label: string) =>
  `2.${btoa(`${label}-iv`)}|${btoa(`${label}-ct`)}|${btoa(`${label}-mac`)}`
const NIL = '00000000-0000-4000-8000-000000000000'

let owner: Actor
let member: Actor
let outsider: Actor
let orgId: string
let projectId: string

const createSecret = async (value: string, projectIds: string[] = [projectId]) =>
  owner.json(`/api/organizations/${orgId}/secrets`, 'POST', {
    key: enc('key'),
    value: enc(value),
    note: enc('note'),
    projectIds,
  })

const edit = (id: string, value: string, extra: Record<string, unknown> = {}) =>
  owner.json(`/api/secrets/${id}`, 'PUT', {
    key: enc('key'),
    value: enc(value),
    note: enc('note'),
    projectIds: [projectId],
    ...extra,
  })

beforeAll(async () => {
  owner = await actor('smv-owner@example.com')
  member = await actor('smv-member@example.com')
  outsider = await actor('smv-outsider@example.com')
  orgId = (await createOrg(owner, 'SMV Org')).id
  const memberUser = await addMember(owner, orgId, member)
  await owner.json(`/api/organizations/${orgId}/users/enable-secrets-manager`, 'PUT', {
    ids: [memberUser],
  })
  projectId = (
    await owner.json(`/api/organizations/${orgId}/projects`, 'POST', { name: enc('proj') })
  ).id
})

describe('secret versions', () => {
  it('records the replaced value on each value change only', async () => {
    const s = await createSecret('v1')
    expect((await owner.json(`/api/secrets/${s.id}/versions`)).data).toEqual([])

    await edit(s.id, 'v1', { note: enc('other note') }) // value unchanged
    expect((await owner.json(`/api/secrets/${s.id}/versions`)).data).toHaveLength(0)

    await edit(s.id, 'v2', { valueChanged: true })
    await edit(s.id, 'v3', { valueChanged: false }) // the stored value decides, not the flag
    const list = await owner.json(`/api/secrets/${s.id}/versions`)
    expect(list.object).toBe('list')
    expect(list.data.map((v: any) => v.value)).toEqual([enc('v2'), enc('v1')])
    const [latest] = list.data
    expect(latest).toMatchObject({
      object: 'secretVersion',
      secretId: s.id,
      editorServiceAccountId: null,
      editorServiceAccountName: null,
      editorOrganizationUserName: 'Test User',
    })
    expect(latest.editorOrganizationUserId).toBeTruthy()
    expect(Date.parse(latest.versionDate)).toBeGreaterThan(0)

    const one = await owner.json(`/api/secret-versions/${latest.id}`)
    expect(one).toEqual(latest)
    const many = await owner.json(
      '/api/secret-versions/get-by-ids',
      'POST',
      list.data.map((v: any) => v.id),
    )
    expect(many.data).toHaveLength(2)
  })

  it('restores a version, recording the value it replaces', async () => {
    const s = await createSecret('a')
    await edit(s.id, 'b')
    await edit(s.id, 'c')
    const [vb, va] = (await owner.json(`/api/secrets/${s.id}/versions`)).data
    expect([vb.value, va.value]).toEqual([enc('b'), enc('a')])

    const restored = await owner.json(`/api/secrets/${s.id}/versions/restore`, 'PUT', {
      versionId: va.id,
    })
    expect(restored.value).toBe(enc('a'))
    expect(restored.id).toBe(s.id)
    expect((await owner.json(`/api/secrets/${s.id}`)).value).toBe(enc('a'))
    const values = (await owner.json(`/api/secrets/${s.id}/versions`)).data.map((v: any) => v.value)
    expect(values).toEqual([enc('c'), enc('b'), enc('a')])

    const other = await createSecret('z')
    const wrong = await owner.call(`/api/secrets/${other.id}/versions/restore`, 'PUT', {
      versionId: va.id,
    })
    expect(wrong.status).toBe(404)
    expect(
      (await owner.call(`/api/secrets/${s.id}/versions/restore`, 'PUT', { versionId: NIL })).status,
    ).toBe(404)
  })

  it('deletes versions and removes them with the secret', async () => {
    const s = await createSecret('d1')
    await edit(s.id, 'd2')
    await edit(s.id, 'd3')
    const { data } = await owner.json(`/api/secrets/${s.id}/versions`)
    const del = await owner.call('/api/secret-versions/delete', 'POST', [data[0].id])
    expect(del.status).toBe(200)
    expect((await owner.json(`/api/secrets/${s.id}/versions`)).data).toHaveLength(1)
    expect((await owner.call(`/api/secret-versions/${data[0].id}`)).status).toBe(404)
    const missing = await owner.call('/api/secret-versions/delete', 'POST', [data[1].id, NIL])
    expect(missing.status).toBe(404)
    expect((await owner.json(`/api/secrets/${s.id}/versions`)).data).toHaveLength(1)

    await owner.json('/api/secrets/delete', 'POST', [s.id])
    expect((await owner.call(`/api/secret-versions/${data[1].id}`)).status).toBe(404)
  })

  it('keeps only the newest versions', async () => {
    const s = await createSecret('n0')
    for (let i = 1; i <= 53; i++) await edit(s.id, `n${i}`)
    const { data } = await owner.json(`/api/secrets/${s.id}/versions`)
    expect(data).toHaveLength(50)
    expect(data[0].value).toBe(enc('n52'))
    expect(data[49].value).toBe(enc('n3'))
  })

  it('follows secret access and names machine account editors', async () => {
    const s = await createSecret('m1')
    await edit(s.id, 'm2')
    const [v] = (await owner.json(`/api/secrets/${s.id}/versions`)).data

    // No access: indistinguishable from missing.
    expect((await member.call(`/api/secrets/${s.id}/versions`)).status).toBe(404)
    expect((await member.call(`/api/secret-versions/${v.id}`)).status).toBe(404)
    expect((await outsider.call(`/api/secret-versions/${v.id}`)).status).toBe(404)

    // Read-only access reads but cannot restore or delete.
    const user = await member.json('/api/accounts/profile')
    const members = await owner.json(`/api/organizations/${orgId}/users`)
    const memberOrgUser = members.data.find((m: any) => m.userId === user.id).id
    await owner.json(`/api/projects/${projectId}/access-policies/people`, 'PUT', {
      userAccessPolicyRequests: [{ granteeId: memberOrgUser, read: true, write: false }],
    })
    expect((await member.call(`/api/secret-versions/${v.id}`)).status).toBe(200)
    expect(
      (await member.call(`/api/secrets/${s.id}/versions/restore`, 'PUT', { versionId: v.id }))
        .status,
    ).toBe(403)
    expect((await member.call('/api/secret-versions/delete', 'POST', [v.id])).status).toBe(403)

    // A machine account with write access edits; the version names it.
    const sa = await owner.json(`/api/organizations/${orgId}/service-accounts`, 'POST', {
      name: enc('robot'),
    })
    const t = await owner.json(`/api/service-accounts/${sa.id}/access-tokens`, 'POST', {
      name: enc('tok'),
      encryptedPayload: enc('payload'),
      key: enc('k'),
      expireAt: null,
    })
    await owner.json(`/api/projects/${projectId}/access-policies/service-accounts`, 'PUT', {
      serviceAccountAccessPolicyRequests: [{ granteeId: sa.id, read: true, write: true }],
    })
    const login = await form('/identity/connect/token', {
      grant_type: 'client_credentials',
      scope: 'api.secrets',
      client_id: t.id,
      client_secret: t.clientSecret,
    })
    const token = ((await login.json()) as { access_token: string }).access_token
    const put = await authed(`/api/secrets/${s.id}`, token, 'PUT', {
      key: enc('key'),
      value: enc('m3'),
      note: enc('note'),
      projectIds: [projectId],
    })
    expect(put.status).toBe(200)
    const after = (await owner.json(`/api/secrets/${s.id}/versions`)).data[0]
    expect(after).toMatchObject({
      value: enc('m2'),
      editorServiceAccountId: sa.id,
      editorServiceAccountName: enc('robot'),
      editorOrganizationUserId: null,
      editorOrganizationUserName: null,
    })
    const viaMachine = await authed(`/api/secrets/${s.id}/versions`, token)
    expect(viaMachine.status).toBe(200)
  })
})

describe('import and export', () => {
  it('exports readable projects and secrets and re-imports them under new ids', async () => {
    const target = await actor('smv-port@example.com')
    const org2 = (await createOrg(target, 'Port Org')).id
    const p = await target.json(`/api/organizations/${org2}/projects`, 'POST', { name: enc('P') })
    const s1 = await target.json(`/api/organizations/${org2}/secrets`, 'POST', {
      key: enc('k1'),
      value: enc('v1'),
      note: enc('n1'),
      projectIds: [p.id],
    })
    const s2 = await target.json(`/api/organizations/${org2}/secrets`, 'POST', {
      key: enc('k2'),
      value: enc('v2'),
      note: '',
      projectIds: [],
    })

    const exported = await target.json(`/api/sm/${org2}/export`)
    expect(exported.object).toBe('sm-export')
    expect(exported.projects).toEqual([{ id: p.id, name: enc('P') }])
    expect(exported.secrets).toHaveLength(2)
    expect(exported.secrets.find((s: any) => s.id === s1.id)).toEqual({
      id: s1.id,
      key: enc('k1'),
      value: enc('v1'),
      note: enc('n1'),
      projectIds: [p.id],
    })

    // Import the same file into another organisation: fresh ids, links kept.
    const other = await actor('smv-port2@example.com')
    const org3 = (await createOrg(other, 'Port Org 2')).id
    const res = await other.call(`/api/sm/${org3}/import`, 'POST', exported)
    expect(res.status).toBe(200)
    const back = await other.json(`/api/sm/${org3}/export`)
    expect(back.projects).toHaveLength(1)
    expect(back.projects[0].name).toBe(enc('P'))
    expect(back.projects[0].id).not.toBe(p.id)
    expect(back.secrets).toHaveLength(2)
    const linked = back.secrets.find((s: any) => s.key === enc('k1'))
    expect(linked.projectIds).toEqual([back.projects[0].id])
    expect(back.secrets.find((s: any) => s.key === enc('k2')).projectIds).toEqual([])
    expect(back.secrets.map((s: any) => s.id)).not.toContain(s1.id)
    expect(back.secrets.map((s: any) => s.id)).not.toContain(s2.id)
    // The source organisation is untouched.
    expect((await target.json(`/api/sm/${org2}/export`)).secrets).toHaveLength(2)
    const sync = await other.json(`/api/organizations/${org3}/secrets/sync`)
    expect(sync.hasChanges).toBe(true)
    expect(sync.secrets.data).toHaveLength(2)
  })

  it('validates the file and enforces access', async () => {
    const pid = crypto.randomUUID()
    const sid = crypto.randomUUID()
    const post = (who: Actor, body: unknown, org = orgId) =>
      who.call(`/api/sm/${org}/import`, 'POST', body)
    const good = {
      projects: [{ id: pid, name: enc('IP') }],
      secrets: [{ id: sid, key: enc('k'), value: enc('v'), note: enc('n'), projectIds: [pid] }],
    }
    expect(
      (await post(owner, { ...good, secrets: [{ ...good.secrets[0], projectIds: [NIL] }] })).status,
    ).toBe(400)
    expect(
      (await post(owner, { ...good, projects: [good.projects[0], good.projects[0]] })).status,
    ).toBe(400)
    expect((await post(owner, { projects: [{ id: 'nope', name: enc('x') }] })).status).toBe(400)
    expect(
      (await post(owner, { secrets: [good.secrets[0], good.secrets[0]], projects: good.projects }))
        .status,
    ).toBe(400)
    // Nothing was written by the refused calls.
    const before = (await owner.json(`/api/sm/${orgId}/export`)).projects.length

    expect((await post(outsider, good)).status).toBe(404)
    expect((await outsider.call(`/api/sm/${orgId}/export`)).status).toBe(404)
    // A member may import projects with secrets inside them, not loose secrets.
    expect((await post(member, { secrets: [{ ...good.secrets[0], projectIds: [] }] })).status).toBe(
      403,
    )
    expect((await post(member, good)).status).toBe(200)
    expect((await owner.json(`/api/sm/${orgId}/export`)).projects.length).toBe(before + 1)
    // The member sees what it can read: the imported project (creator access) and its secret.
    const mine = await member.json(`/api/sm/${orgId}/export`)
    expect(mine.projects.map((p: any) => p.name)).toContain(enc('IP'))
    expect(mine.secrets.some((s: any) => s.key === enc('k'))).toBe(true)
  })
})
