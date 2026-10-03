// Final client parity endpoints (TASKS #330 to #333): client directory import, organisation
// deletion by emailed token, the client integrations API, and the Provider Portal answer.
import { env } from 'cloudflare:workers'
import { describe, expect, it, vi } from 'vitest'
import { openSecrets } from '../src/integrations/deliver'
import { BASE } from './helpers'
import { actor, addMember, createOrg, linkParams, mailbox } from './org-helpers'

const PWB = { masterPasswordHash: 'client-derived-hash' }
const anon = async (path: string, body: unknown, mb: ReturnType<typeof mailbox> | null = null) => {
  const { default: app } = await import('../src/index')
  return app.fetch(
    new Request(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    { ...env, ...(mb ? { EMAIL: mb.EMAIL, MAIL_FROM: mb.MAIL_FROM } : {}) },
  )
}
const secretsOf = async (uuid: string) => {
  const r = await env.DB.prepare(
    'SELECT uuid, sealed_secrets FROM org_integrations WHERE uuid = ?1',
  )
    .bind(uuid)
    .first<{ uuid: string; sealed_secrets: string }>()
  return openSecrets(env, { uuid: r?.uuid, sealedSecrets: r?.sealed_secrets } as never)
}
const orgRow = (id: string) =>
  env.DB.prepare('SELECT uuid FROM organizations WHERE uuid = ?1').bind(id).first()

describe('POST /api/organizations/{orgId}/import', () => {
  it('invites members and builds groups from either request form', async () => {
    const mb = mailbox()
    const owner = await actor('imp-owner@example.com', mb)
    const { id } = await createOrg(owner, 'Import Org')
    const res = await owner.call(`/api/organizations/${id}/import`, 'POST', {
      groups: [{ name: 'Devs', externalId: 'g1', users: ['u1'] }],
      users: [
        { email: 'dev1@example.com', externalId: 'u1', deleted: false },
        { email: 'dev2@example.com', externalId: 'u2', deleted: false },
      ],
      overwriteExisting: false,
      largeImport: false,
    })
    expect(res.status).toBe(200)
    const members = await owner.json(`/api/organizations/${id}/users?includeGroups=true`)
    expect(members.data.map((m: { email: string }) => m.email)).toEqual(
      expect.arrayContaining(['dev1@example.com', 'dev2@example.com']),
    )
    const groups = await owner.json(`/api/organizations/${id}/groups`)
    expect(groups.data.map((g: { name: string }) => g.name)).toContain('Devs')
    expect(mb.sent.some((m) => m.to === 'dev1@example.com')).toBe(true)

    // The API model form (members, memberExternalIds) with overwrite removes the absent member.
    const again = await owner.call(`/api/organizations/${id}/import`, 'POST', {
      groups: [{ name: 'Devs', externalId: 'g1', memberExternalIds: ['u1'] }],
      members: [{ email: 'dev1@example.com', externalId: 'u1', deleted: false }],
      overwriteExisting: true,
    })
    expect(again.status).toBe(200)
    const after = await owner.json(`/api/organizations/${id}/users`)
    expect(after.data.map((m: { email: string }) => m.email)).not.toContain('dev2@example.com')
  })

  it('needs manageUsers (and manageGroups for groups); outsiders get 404', async () => {
    const mb = mailbox()
    const owner = await actor('imp2-owner@example.com', mb)
    const { id } = await createOrg(owner, 'Import Perm')
    const plain = await actor('imp2-plain@example.com', mb)
    await addMember(owner, id, plain, {}, mb)
    const custom = await actor('imp2-custom@example.com', mb)
    await addMember(owner, id, custom, { type: 4, permissions: { manageUsers: true } }, mb)
    const outsider = await actor('imp2-out@example.com', mb)
    const body = { users: [{ email: 'x1@example.com', externalId: 'x1', deleted: false }] }
    expect((await plain.call(`/api/organizations/${id}/import`, 'POST', body)).status).toBe(403)
    expect((await outsider.call(`/api/organizations/${id}/import`, 'POST', body)).status).toBe(404)
    expect((await custom.call(`/api/organizations/${id}/import`, 'POST', body)).status).toBe(200)
    const withGroup = { ...body, groups: [{ name: 'G', externalId: 'g', users: [] }] }
    expect((await custom.call(`/api/organizations/${id}/import`, 'POST', withGroup)).status).toBe(
      403,
    )
    expect((await anon(`/api/organizations/${id}/import`, body)).status).toBe(401)
  })
})

describe('organisation deletion by email', () => {
  it('mails the billing address, deletes once, and rejects reuse', async () => {
    const mb = mailbox()
    const owner = await actor('del-owner@example.com', mb)
    const { id } = await createOrg(owner, 'Doomed Org')
    const link = async () => {
      const before = mb.sent.length
      expect(
        (await owner.call(`/api/organizations/${id}/delete-recover`, 'POST', PWB)).status,
      ).toBe(200)
      const m = mb.sent[before]
      expect(m?.to).toBe('billing@example.com')
      expect(m?.text).toContain('#/verify-recover-delete-org?')
      return linkParams(m)
    }
    const p = await link()
    expect(p.get('orgId')).toBe(id)
    expect(p.get('name')).toBe('Doomed Org')
    const path = `/api/organizations/${id}/delete-recover-token`
    expect((await anon(path, { token: 'a.b.c' })).status).toBe(400)
    // A token for another organisation does not delete this one.
    const other = await createOrg(owner, 'Other Org')
    expect(
      (await anon(`/api/organizations/${other.id}/delete-recover-token`, { token: p.get('token') }))
        .status,
    ).toBe(400)
    expect(await orgRow(id)).not.toBeNull()
    expect(await orgRow(other.id)).not.toBeNull()
    expect((await anon(path, { token: p.get('token') })).status).toBe(200)
    expect(await orgRow(id)).toBeNull()
    expect((await anon(path, { token: p.get('token') })).status).toBe(400)
  })

  it('is owner only, needs a mailer, and a new billing address voids old links', async () => {
    const mb = mailbox()
    const owner = await actor('del2-owner@example.com', mb)
    const { id } = await createOrg(owner, 'Guarded Org')
    const admin = await actor('del2-admin@example.com', mb)
    await addMember(owner, id, admin, { type: 1 }, mb)
    expect((await admin.call(`/api/organizations/${id}/delete-recover`, 'POST', PWB)).status).toBe(
      403,
    )
    const silent = await actor('del2-silent@example.com', mailbox())
    const silentOrg = await createOrg(silent, 'Silent Org')
    const { default: app } = await import('../src/index')
    const noMail = await app.fetch(
      new Request(`${BASE}/api/organizations/${silentOrg.id}/delete-recover`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${silent.token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(PWB),
      }),
      { ...env, EMAIL: undefined, MAIL_FROM: undefined },
    )
    expect(noMail.status).toBe(400)

    await owner.call(`/api/organizations/${id}/delete-recover`, 'POST', PWB)
    const p = linkParams(mb.sent.at(-1))
    await env.DB.prepare(
      "UPDATE organizations SET billing_email = 'new@example.com' WHERE uuid = ?1",
    )
      .bind(id)
      .run()
    expect(
      (await anon(`/api/organizations/${id}/delete-recover-token`, { token: p.get('token') }))
        .status,
    ).toBe(400)
    expect(await orgRow(id)).not.toBeNull()
  })

  it('answers 404 for providers, which a self-hosted server does not have', async () => {
    const res = await anon(
      '/api/providers/00000000-0000-0000-0000-000000000000/delete-recover-token',
      {
        token: 'x',
      },
    )
    expect(res.status).toBe(404)
  })
})

describe('client integrations API', () => {
  const secretToken = 'hec-token-never-returned'

  it('maps Hec to a Splunk row, keeps secrets write-only and delivers by event type', async () => {
    const owner = await actor('hec-owner@example.com')
    const { id } = await createOrg(owner, 'Hec Org')
    const base = `/api/organizations/${id}/integrations`
    const made = await owner.call(base, 'POST', {
      type: 5,
      configuration: JSON.stringify({
        Uri: 'https://hec.example.com:8088/services/collector/event',
        Scheme: 'Splunk',
        Token: secretToken,
        Service: 'vault',
      }),
    })
    expect(made.status).toBe(200)
    const text = await made.text()
    expect(text).not.toContain(secretToken)
    const integ = JSON.parse(text)
    expect(integ).toMatchObject({ object: 'organizationIntegration', type: 5, status: 0 })
    expect(JSON.parse(integ.configuration)).toMatchObject({ service: 'vault', scheme: 'Splunk' })

    const row = await env.DB.prepare('SELECT * FROM org_integrations WHERE uuid = ?1')
      .bind(integ.id)
      .first<{ atype: string; enabled: number; sealed_secrets: string; uuid: string }>()
    expect(row?.atype).toBe('splunk')
    expect(row?.enabled).toBe(0)
    expect(row?.sealed_secrets).not.toContain(secretToken)

    const cfgRes = await owner.call(`${base}/${integ.id}/configurations`, 'POST', {
      eventType: 1700,
      filters: '{"groups":[]}',
      template: '{"event":#EventMessage#}',
    })
    expect(cfgRes.status).toBe(200)
    const cfg = (await cfgRes.json()) as { id: string }
    expect(cfg).toMatchObject({
      object: 'organizationIntegrationConfiguration',
      eventType: 1700,
      template: '{"event":#EventMessage#}',
      configuration: null,
    })
    const live = await env.DB.prepare(
      'SELECT enabled, event_types, uuid FROM org_integrations WHERE uuid = ?1',
    )
      .bind(integ.id)
      .first<{ enabled: number; event_types: string }>()
    expect(live).toMatchObject({ enabled: 1, event_types: '[1700]' })

    const list = await owner.json(base)
    expect(list).toHaveLength(1)
    expect(JSON.stringify(list)).not.toContain(secretToken)
    expect(await owner.json(`${base}/${integ.id}/configurations`)).toHaveLength(1)

    // Same destination without a token keeps the stored one; a new one needs its own.
    const keep = await owner.call(`${base}/${integ.id}`, 'PUT', {
      type: 5,
      configuration: JSON.stringify({
        uri: 'https://hec.example.com:8088/services/collector/event',
        service: 'vault2',
      }),
    })
    expect(keep.status).toBe(200)
    expect((await secretsOf(integ.id)).token).toBe(secretToken)
    const moved = await owner.call(`${base}/${integ.id}`, 'PUT', {
      type: 5,
      configuration: JSON.stringify({ uri: 'https://other.example.com/hec' }),
    })
    expect(moved.status).toBe(400)

    expect(
      (await owner.call(`${base}/${integ.id}/configurations/${cfg.id}`, 'DELETE')).status,
    ).toBe(204)
    const off = await env.DB.prepare('SELECT enabled FROM org_integrations WHERE uuid = ?1')
      .bind(integ.id)
      .first<{ enabled: number }>()
    expect(off?.enabled).toBe(0)
    expect((await owner.call(`${base}/${integ.id}`, 'DELETE')).status).toBe(204)
    expect(await owner.json(base)).toEqual([])
  })

  it('maps Datadog and rejects other intake hosts', async () => {
    const owner = await actor('dd-owner@example.com')
    const { id } = await createOrg(owner, 'DD Org')
    const base = `/api/organizations/${id}/integrations`
    const bad = await owner.call(base, 'POST', {
      type: 6,
      configuration: JSON.stringify({ uri: 'https://evil.example.com/api/v2/logs', apiKey: 'k' }),
    })
    expect(bad.status).toBe(400)
    const ok = await owner.call(base, 'POST', {
      type: 6,
      configuration: JSON.stringify({
        uri: 'https://http-intake.logs.datadoghq.eu/api/v2/logs',
        apiKey: 'dd-key-secret',
      }),
    })
    expect(ok.status).toBe(200)
    const text = await ok.text()
    expect(text).not.toContain('dd-key-secret')
    expect(JSON.parse(JSON.parse(text).configuration).uri).toBe(
      'https://http-intake.logs.datadoghq.eu/api/v2/logs',
    )
  })

  it('keeps webhook settings on the configuration with SSRF checks and one configuration', async () => {
    const owner = await actor('wh-owner@example.com')
    const { id } = await createOrg(owner, 'WH Org')
    const base = `/api/organizations/${id}/integrations`
    const integ = await owner.json(base, 'POST', { type: 4 })
    expect(integ.type).toBe(4)
    expect(integ.configuration).toBeNull()
    const path = `${base}/${integ.id}/configurations`
    for (const uri of ['http://hook.example.com/x', 'https://127.0.0.1/x', 'https://localhost/x']) {
      expect(
        (await owner.call(path, 'POST', { configuration: JSON.stringify({ uri }) })).status,
      ).toBe(400)
    }
    const res = await owner.call(path, 'POST', {
      configuration: JSON.stringify({
        Uri: 'https://hook.example.com/in',
        Scheme: 'Bearer',
        Token: 'wh-token-secret',
      }),
      eventType: null,
    })
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).not.toContain('wh-token-secret')
    const cfg = JSON.parse(text)
    expect(JSON.parse(cfg.configuration)).toEqual({
      uri: 'https://hook.example.com/in',
      scheme: 'Bearer',
    })
    expect((await secretsOf(integ.id)).headerValue).toBe('Bearer wh-token-secret')
    expect(
      (
        await env.DB.prepare('SELECT enabled FROM org_integrations WHERE uuid = ?1')
          .bind(integ.id)
          .first<{ enabled: number }>()
      )?.enabled,
    ).toBe(1)
    expect(
      (
        await owner.call(path, 'POST', {
          configuration: JSON.stringify({ uri: 'https://hook.example.com/b' }),
        })
      ).status,
    ).toBe(400)
    // Moving the address without a token drops the stored header credential.
    const put = await owner.call(`${path}/${cfg.id}`, 'PUT', {
      configuration: JSON.stringify({ uri: 'https://hook2.example.com/in' }),
    })
    expect(put.status).toBe(200)
    expect((await secretsOf(integ.id)).headerValue).toBeUndefined()
  })

  it('answers 400 for Slack and Teams, and admin only', async () => {
    const mb = mailbox()
    const owner = await actor('st-owner@example.com', mb)
    const { id } = await createOrg(owner, 'ST Org')
    const base = `/api/organizations/${id}/integrations`
    for (const type of [3, 7, 1, 2, 99]) {
      expect((await owner.call(base, 'POST', { type, configuration: '{}' })).status).toBe(400)
    }
    const slack = await owner.call(`${base}/slack/redirect`)
    expect(slack.status).toBe(400)
    expect(((await slack.json()) as { message: string }).message).toContain('Slack')
    expect((await owner.call(`${base}/teams/redirect`)).status).toBe(400)
    expect((await owner.call(`${base}/${crypto.randomUUID()}/teams/channels`)).status).toBe(400)
    expect(
      (await owner.call('/api/organizations/integrations/slack/create?code=x&state=y')).status,
    ).toBe(400)
    expect((await anon('/api/organizations/integrations/teams/incoming', {})).status).toBe(400)
    const member = await actor('st-member@example.com', mb)
    await addMember(owner, id, member, {}, mb)
    expect((await member.call(base)).status).toBe(403)
    expect((await member.call(base, 'POST', { type: 4 })).status).toBe(403)
  })
})

describe('security review fixes', () => {
  const del = (id: string) => `/api/organizations/${id}/delete-recover`
  const q = (sql: string, ...v: unknown[]) =>
    env.DB.prepare(sql)
      .bind(...v)
      .first<Record<string, any>>()

  it('billing email changes are owner only and void mailed links', async () => {
    const mb = mailbox()
    const owner = await actor('sr-bill-owner@example.com', mb)
    const { id } = await createOrg(owner, 'Bill Org')
    const admin = await actor('sr-bill-admin@example.com', mb)
    await addMember(owner, id, admin, { type: 1 }, mb)
    const put = (a: typeof owner, billingEmail: string) =>
      a.call(`/api/organizations/${id}`, 'PUT', { name: 'Bill Org', billingEmail })
    expect((await put(admin, 'thief@example.com')).status).toBe(403)
    expect((await put(admin, 'billing@example.com')).status).toBe(200)
    await owner.call(del(id), 'POST', PWB)
    const p = linkParams(mb.sent.at(-1))
    expect((await put(owner, 'newbill@example.com')).status).toBe(200)
    expect(
      (await anon(`/api/organizations/${id}/delete-recover-token`, { token: p.get('token') }))
        .status,
    ).toBe(400)
    expect(await orgRow(id)).not.toBeNull()
  })

  it('needs the master password or a code, caps mail at 3 per hour, newest link wins', async () => {
    const mb = mailbox()
    const owner = await actor('sr-proof-owner@example.com', mb)
    const { id } = await createOrg(owner, 'Proof Org')
    expect((await owner.call(del(id), 'POST', {})).status).toBe(400)
    expect((await owner.call(del(id), 'POST', { masterPasswordHash: 'wrong' })).status).toBe(400)
    expect(mb.sent.filter((m) => m.subject.includes('organisation deletion'))).toHaveLength(0)

    // A code for accounts without a password.
    await owner.call('/api/accounts/request-otp', 'POST')
    const otp = /\b(\d{6})\b/.exec(mb.sent.at(-1)?.text ?? '')?.[1]
    expect((await owner.call(del(id), 'POST', { otp })).status).toBe(200)
    const first = linkParams(mb.sent.at(-1))
    expect((await owner.call(del(id), 'POST', PWB)).status).toBe(200)
    const second = linkParams(mb.sent.at(-1))
    expect((await owner.call(del(id), 'POST', PWB)).status).toBe(200)
    expect((await owner.call(del(id), 'POST', PWB)).status).toBe(429)

    const path = `/api/organizations/${id}/delete-recover-token`
    expect((await anon(path, { token: first.get('token') })).status).toBe(400)
    expect((await anon(path, { token: second.get('token') })).status).toBe(400)
    expect(await orgRow(id)).not.toBeNull()
  })

  it('a link dies when its requesting owner stops being an owner', async () => {
    const mb = mailbox()
    const owner = await actor('sr-own-a@example.com', mb)
    const { id } = await createOrg(owner, 'Two Owners')
    const second = await actor('sr-own-b@example.com', mb)
    await addMember(owner, id, second, { type: 0 }, mb)
    await owner.call(del(id), 'POST', PWB)
    const p = linkParams(mb.sent.at(-1))
    await env.DB.prepare(
      'UPDATE users_organizations SET atype = 2 WHERE organization_uuid = ?1 AND user_uuid = ?2',
    )
      .bind(id, owner.uuid)
      .run()
    expect(
      (await anon(`/api/organizations/${id}/delete-recover-token`, { token: p.get('token') }))
        .status,
    ).toBe(400)
    expect(await orgRow(id)).not.toBeNull()
  })

  it('erases attachment blobs and federation rows with the organisation', async () => {
    const mb = mailbox()
    const owner = await actor('sr-erase@example.com', mb)
    const { id } = await createOrg(owner, 'Erase Org')
    const cipher = crypto.randomUUID()
    const now = Date.now()
    await env.DB.prepare(
      "INSERT INTO ciphers (uuid, organization_uuid, atype, name, data, created_at, updated_at) VALUES (?1, ?2, 1, '2.n', '{}', ?3, ?3)",
    )
      .bind(cipher, id, now)
      .run()
    const key = `${cipher}/blobtest`
    await env.ATTACHMENTS.put(key, 'x')
    await env.DB.prepare(
      "INSERT INTO attachments (id, cipher_uuid, file_name, file_size, r2_key, created_at) VALUES ('blobtest', ?1, '2.n', 1, ?2, ?3)",
    )
      .bind(cipher, key, now)
      .run()
    const peer = crypto.randomUUID()
    await env.DB.prepare(
      "INSERT INTO federation_peers (uuid, instance_id, domain, public_key, fingerprint, protocol_version, status, created_at, updated_at) VALUES (?1, ?1, ?2, 'k', 'f', 1, 'active', ?3, ?3)",
    )
      .bind(peer, `${peer}.example.net`, now)
      .run()
    await env.DB.prepare(
      "INSERT INTO federation_invitations (uuid, peer_uuid, remote_member_uuid, organization_uuid, organization_name, user_uuid, status, created_at, updated_at) VALUES (?1, ?2, 'm', ?3, 'Erase Org', ?4, 'pending', ?5, ?5)",
    )
      .bind(crypto.randomUUID(), peer, id, owner.uuid, now)
      .run()

    await owner.call(del(id), 'POST', PWB)
    const p = linkParams(mb.sent.at(-1))
    expect(
      (await anon(`/api/organizations/${id}/delete-recover-token`, { token: p.get('token') }))
        .status,
    ).toBe(200)
    await vi.waitFor(async () => expect(await env.ATTACHMENTS.head(key)).toBeNull())
    expect(
      await q('SELECT 1 AS x FROM federation_invitations WHERE organization_uuid = ?1', id),
    ).toBeNull()
    expect(await q('SELECT 1 AS x FROM ciphers WHERE uuid = ?1', cipher)).toBeNull()
  })

  it('keeps integrations and deletion out of federation, and refuses stand-ins', async () => {
    const { NOT_FEDERATED } = await import('../src/federation/hosting')
    const org = '00000000-0000-0000-0000-000000000000'
    for (const path of [
      `/api/organizations/${org}/integrations`,
      `/api/organizations/${org}/integrations/x/configurations`,
      `/api/organizations/${org}/event-integrations/x/test`,
      `/api/organizations/${org}/delete-recover`,
      `/api/organizations/${org}/delete-recover-token`,
    ]) {
      expect(NOT_FEDERATED.test(path), path).toBe(true)
    }
    const standIn = await actor('sr-standin@example.com')
    const { id } = await createOrg(standIn, 'Standin Org')
    await env.DB.prepare("UPDATE users SET password_hash = '!federated.x' WHERE uuid = ?1")
      .bind(standIn.uuid)
      .run()
    for (const [path, method] of [
      [`/api/organizations/${id}/integrations`, 'GET'],
      [`/api/organizations/${id}/event-integrations`, 'GET'],
      [del(id), 'POST'],
    ] as const) {
      const res = await standIn.call(path, method, method === 'POST' ? PWB : undefined)
      expect([401, 403]).toContain(res.status)
    }
  })

  it('restricts destination ports and header characters', async () => {
    const owner = await actor('sr-port@example.com')
    const { id } = await createOrg(owner, 'Port Org')
    const base = `/api/organizations/${id}/integrations`
    const hec = (uri: string, token = 'tok') =>
      owner.call(base, 'POST', { type: 5, configuration: JSON.stringify({ uri, token }) })
    expect((await hec('https://hec.example.com:8088/services/collector/event')).status).toBe(200)
    expect((await hec('https://hec.example.com/services/collector/event')).status).toBe(200)
    expect((await hec('https://hec.example.com:6379/x')).status).toBe(400)
    expect((await hec('https://hec.example.com:8088/x', 'bad\r\ntoken')).status).toBe(400)
    expect((await hec('https://hec.example.com:8088/x', 'has space')).status).toBe(400)

    const wh = await owner.json(base, 'POST', { type: 4 })
    const path = `${base}/${wh.id}/configurations`
    const cfg = (c: Record<string, unknown>) =>
      owner.call(path, 'POST', { configuration: JSON.stringify(c) })
    expect((await cfg({ uri: 'https://hook.example.com:8088/x' })).status).toBe(400)
    expect(
      (await cfg({ uri: 'https://hook.example.com/x', scheme: 'Bad Scheme', token: 't' })).status,
    ).toBe(400)
    expect(
      (await cfg({ uri: 'https://hook.example.com/x', scheme: 'Bearer', token: 'a\nb' })).status,
    ).toBe(400)
    expect(
      (await cfg({ uri: 'https://hook.example.com/x', scheme: 'Bearer', token: 'ok' })).status,
    ).toBe(200)
  })

  it('records audit events for integration changes', async () => {
    const owner = await actor('sr-audit@example.com')
    const { id } = await createOrg(owner, 'Audit Org')
    const count = async () =>
      (
        await q(
          'SELECT count(*) AS n FROM events WHERE organization_uuid = ?1 AND event_type = 1600',
          id,
        )
      )?.n
    const before = await count()
    const base = `/api/organizations/${id}/integrations`
    const made = await owner.json(base, 'POST', { type: 4 })
    const cfg = await owner.json(`${base}/${made.id}/configurations`, 'POST', {
      configuration: JSON.stringify({ uri: 'https://hook.example.com/x' }),
    })
    expect(await count()).toBe(before + 2)
    expect((await owner.call(`${base}/${made.id}/configurations/${cfg.id}`, 'DELETE')).status).toBe(
      204,
    )
    expect(await count()).toBe(before + 3)
    expect((await owner.call(`${base}/${made.id}`, 'DELETE')).status).toBe(204)
    expect(await count()).toBe(before + 4)
  })
})

describe('directory import bounds', () => {
  it('caps invites and memberships, and spares members above the actor', async () => {
    const mb = mailbox()
    const owner = await actor('sr-imp-owner@example.com', mb)
    const { id } = await createOrg(owner, 'Bounds Org')
    const imp = (b: unknown) => owner.call(`/api/organizations/${id}/import`, 'POST', b)
    const many = Array.from({ length: 501 }, (_, i) => ({
      email: `bulk${i}@example.com`,
      externalId: `b${i}`,
    }))
    expect((await imp({ users: many })).status).toBe(400)
    const members = await owner.json(`/api/organizations/${id}/users`)
    expect(members.data).toHaveLength(1)

    const ids = Array.from({ length: 5001 }, (_, i) => `m${i}`)
    const groups = Array.from({ length: 10 }, (_, i) => ({
      name: `G${i}`,
      externalId: `g${i}`,
      users: ids,
    }))
    expect((await imp({ groups: groups.concat(groups) })).status).toBe(400)

    // An admin cannot link the owner's address to an external id (re-key) or remove an admin.
    const admin = await actor('sr-imp-admin@example.com', mb)
    await addMember(owner, id, admin, { type: 1 }, mb)
    const res = await admin.call(`/api/organizations/${id}/import`, 'POST', {
      users: [{ email: 'sr-imp-owner@example.com', externalId: 'hijack' }],
    })
    expect(res.status).toBe(200)
    const row = await env.DB.prepare(
      'SELECT external_id FROM users_organizations WHERE organization_uuid = ?1 AND user_uuid = ?2',
    )
      .bind(id, owner.uuid)
      .first<{ external_id: string | null }>()
    expect(row?.external_id).toBeNull()
  })

  it('refuses oversized bodies', async () => {
    const owner = await actor('sr-imp-big@example.com')
    const { id } = await createOrg(owner, 'Big Org')
    const pad = 'x'.repeat(5 * 1024 * 1024 + 10)
    const res = await owner.call(`/api/organizations/${id}/import`, 'POST', {
      users: [],
      pad,
    })
    expect(res.status).toBe(413)
  })
})
