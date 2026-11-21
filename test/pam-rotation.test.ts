// Access connectors, target systems, rotation configurations and the connector-facing rotation API
// (docs/privileged-access.md). Covers every route and the job state machine.
import { env } from 'cloudflare:workers'
import { beforeAll, describe, expect, it, vi } from 'vitest'

// Org flows are slow on the shared CI host (see vitest.config.ts); give each test room.
vi.setConfig({ testTimeout: 600_000 })

import { sweepRotation } from '../src/pam/rotation'
import { raw } from './org-api-helpers'
import { type Actor, actor, addMember } from './org-helpers'
import { connectorFor, orgWithLogin, sql } from './pam-helpers'

let owner: Actor
let member: Actor
let outsider: Actor
let orgId: string

const admin = (path: string, method = 'GET', body?: unknown) =>
  owner.call(`/api/organizations/${orgId}/access-connectors${path}`, method, body)

async function seal(name: string, method = 0) {
  const t = await (await admin('/rotation/target-systems', 'POST', { name, method })).json<any>()
  const put = await admin(`/rotation/target-systems/${t.id}`, 'PUT', {
    name,
    sealedData: '2.sealed',
    wrappedKey: '2.wrapped',
  })
  expect(put.status).toBe(200)
  return t.id as string
}

async function freshConfig(extra: Record<string, unknown> = {}) {
  const c = await owner.json('/api/ciphers/create', 'POST', {
    cipher: {
      type: 1,
      name: '2.db',
      key: '2.ckey',
      login: { username: '2.u', password: '2.p' },
      organizationId: orgId,
    },
    collectionIds: [],
  })
  return { cipherId: c.id as string, ...extra }
}

beforeAll(async () => {
  owner = await actor('pam-owner@example.com')
  member = await actor('pam-member@example.com')
  outsider = await actor('pam-outsider@example.com')
  const org = await orgWithLogin(owner, 'Pam Org')
  orgId = org.id
  await addMember(owner, orgId, member, { type: 2 })
}, 300_000)

describe('permissions', () => {
  it('limits administration to owners and admins', async () => {
    const paths = [
      ['GET', ''],
      ['GET', '/rotation/configs'],
      ['GET', '/rotation/target-systems'],
    ]
    for (const [method, path] of paths) {
      expect(
        (await member.call(`/api/organizations/${orgId}/access-connectors${path}`, method)).status,
      ).toBe(403)
      expect(
        (await outsider.call(`/api/organizations/${orgId}/access-connectors${path}`, method))
          .status,
      ).toBe(404)
    }
    expect((await raw(`/api/organizations/${orgId}/access-connectors`)).status).toBe(401)
  })

  it('refuses user tokens on connector routes and connector tokens on user routes', async () => {
    const dev = await connectorFor(owner, orgId, 'perm')
    expect((await owner.call('/api/access-connectors/rotation/jobs')).status).toBe(401)
    expect((await raw('/api/access-connectors/rotation/jobs')).status).toBe(401)
    const asUser = await raw(`/api/organizations/${orgId}/access-connectors`, {
      headers: { Authorization: `Bearer ${dev.tok.access_token}` },
    })
    expect(asUser.status).toBe(401)
    expect((await dev.call('/jobs')).status).toBe(200)
  })
})

describe('access connectors', () => {
  it('registers, lists, reads, disables, enables and deletes a connector', async () => {
    const reg = await (
      await admin('', 'POST', { name: 'edge-1', encryptedPayload: '2.p', key: '2.k' })
    ).json<any>()
    expect(reg).toMatchObject({
      object: 'registerAccessConnector',
      name: 'edge-1',
      status: 0,
      organizationId: orgId,
    })
    expect(reg.clientSecret).toMatch(/^[A-Za-z0-9]{40}$/)
    // Only a hash of the secret is stored.
    const stored = (
      await sql('select client_secret_hash from pam_access_connectors where uuid = ?', reg.id)
    ).results[0]
    expect(JSON.stringify(stored)).not.toContain(reg.clientSecret)

    const listed = await (await admin('')).json<any>()
    const row = listed.data.find((c: any) => c.id === reg.id)
    expect(row).toMatchObject({
      name: 'edge-1',
      status: 0,
      isConnected: false,
      assignedTargetSystemIds: [],
    })
    expect(row).not.toHaveProperty('clientSecret')

    const detail = await (await admin(`/${reg.id}`)).json<any>()
    expect(detail).toMatchObject({ id: reg.id, jobs: [] })

    expect((await admin(`/${reg.id}/disable`, 'POST')).status).toBe(200)
    expect((await (await admin(`/${reg.id}`)).json<any>()).status).toBe(1)
    expect((await admin(`/${reg.id}/enable`, 'POST')).status).toBe(200)
    expect((await (await admin(`/${reg.id}`)).json<any>()).status).toBe(0)

    expect((await admin(`/${reg.id}`, 'DELETE')).status).toBe(200)
    expect((await admin(`/${reg.id}`)).status).toBe(404)
    expect((await admin(`/${crypto.randomUUID()}`)).status).toBe(404)
    expect(
      (await admin('', 'POST', { name: '', encryptedPayload: '2.p', key: '2.k' })).status,
    ).toBe(400)
  })

  it('signs a connector in, shows it connected, and revokes access on disable and delete', async () => {
    const dev = await connectorFor(owner, orgId, 'login')
    expect(dev.login.status).toBe(200)
    expect(dev.tok).toMatchObject({
      token_type: 'Bearer',
      scope: 'api.access-connector',
      encrypted_payload: '2.orgKeyForConnector',
    })
    const row = (await (await admin('')).json<any>()).data.find((c: any) => c.id === dev.reg.id)
    expect(row.isConnected).toBe(true)

    const bad = await raw('/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'api.access-connector',
        client_id: `access-connector.${dev.reg.apiKeyId}`,
        client_secret: 'wrong',
      }).toString(),
    })
    expect(bad.status).toBe(400)
    expect(((await bad.json<any>()) as any).error).toBe('invalid_client')

    await admin(`/${dev.reg.id}/disable`, 'POST')
    expect((await dev.call('/jobs')).status).toBe(401)
    await admin(`/${dev.reg.id}/enable`, 'POST')
    expect((await dev.call('/jobs')).status).toBe(200)
    await admin(`/${dev.reg.id}`, 'DELETE')
    expect((await dev.call('/jobs')).status).toBe(401)
  })

  it('assigns and unassigns target systems', async () => {
    const reg = await (
      await admin('', 'POST', { name: 'assign', encryptedPayload: '2.p', key: '2.k' })
    ).json<any>()
    const target = await seal('db-assign')
    expect((await admin(`/${reg.id}/assignments`, 'POST', { targetSystemId: target })).status).toBe(
      200,
    )
    // Assigning twice is a no-op.
    expect((await admin(`/${reg.id}/assignments`, 'POST', { targetSystemId: target })).status).toBe(
      200,
    )
    expect((await (await admin(`/${reg.id}`)).json<any>()).assignedTargetSystemIds).toEqual([
      target,
    ])
    expect(
      (await admin(`/${reg.id}/assignments`, 'POST', { targetSystemId: crypto.randomUUID() }))
        .status,
    ).toBe(404)
    expect((await admin(`/${reg.id}/assignments/${target}`, 'DELETE')).status).toBe(200)
    expect((await admin(`/${reg.id}/assignments/${target}`, 'DELETE')).status).toBe(404)
    expect((await (await admin(`/${reg.id}`)).json<any>()).assignedTargetSystemIds).toEqual([])
  })
})

describe('target systems', () => {
  it('registers pending seal, seals, disables, enables and deletes', async () => {
    const t = await (
      await admin('/rotation/target-systems', 'POST', { name: 'pg', method: 0 })
    ).json<any>()
    expect(t).toMatchObject({ name: 'pg', method: 0, status: 2, sealedData: null })
    expect((await admin(`/rotation/target-systems/${t.id}/enable`, 'POST')).status).toBe(400)
    expect(
      (
        await admin(`/rotation/target-systems/${t.id}`, 'PUT', {
          name: 'pg2',
          sealedData: '2.s',
          wrappedKey: '2.w',
        })
      ).status,
    ).toBe(200)
    const listed = (await (await admin('/rotation/target-systems')).json<any>()).data
    expect(listed.find((x: any) => x.id === t.id)).toMatchObject({
      name: 'pg2',
      status: 0,
      sealedData: '2.s',
      wrappedKey: '2.w',
    })
    expect((await admin(`/rotation/target-systems/${t.id}/disable`, 'POST')).status).toBe(200)
    expect(
      (await (await admin('/rotation/target-systems')).json<any>()).data.find(
        (x: any) => x.id === t.id,
      ).status,
    ).toBe(1)
    expect((await admin(`/rotation/target-systems/${t.id}/enable`, 'POST')).status).toBe(200)
    expect((await admin(`/rotation/target-systems/${t.id}`, 'DELETE')).status).toBe(200)
    expect((await admin(`/rotation/target-systems/${t.id}`, 'DELETE')).status).toBe(404)
    expect((await admin('/rotation/target-systems', 'POST', { name: 'x', method: 5 })).status).toBe(
      400,
    )
  })

  it('refuses to delete a target system that a configuration uses', async () => {
    const target = await seal('in-use')
    const { cipherId: id } = await freshConfig()
    const created = await admin('/rotation/configs', 'POST', {
      cipherId: id,
      targetSystemId: target,
      sealedData: '2.a',
      wrappedKey: '2.b',
    })
    expect(created.status).toBe(200)
    expect((await admin(`/rotation/target-systems/${target}`, 'DELETE')).status).toBe(409)
  })
})

describe('rotation configurations', () => {
  it('creates, reads, updates, pauses, resumes and deletes a configuration', async () => {
    const target = await seal('cfg')
    const { cipherId: id } = await freshConfig()
    const body = {
      cipherId: id,
      targetSystemId: target,
      sealedData: '2.a',
      wrappedKey: '2.b',
      scheduleCron: '0 3 * * *',
      rotateOnAccessEnd: true,
    }
    const created = await (await admin('/rotation/configs', 'POST', body)).json<any>()
    expect(created).toMatchObject({
      cipherId: id,
      targetSystemId: target,
      targetSystemName: 'cfg',
      targetSystemMethod: 0,
      scheduleCron: '0 3 * * *',
      rotateOnAccessEnd: true,
      enabled: true,
      hasActiveJob: false,
      awaitingManualRotation: false,
      jobs: [],
    })
    expect(created.nextRotationAt).toBeTruthy()
    expect((await admin('/rotation/configs', 'POST', body)).status).toBe(409)

    const listed = await (await admin('/rotation/configs')).json<any>()
    expect(listed.data.map((c: any) => c.id)).toContain(created.id)
    expect(listed.data[0]).not.toHaveProperty('jobs')
    expect((await (await admin(`/rotation/configs/${created.id}`)).json<any>()).id).toBe(created.id)

    const updated = await (
      await admin(`/rotation/configs/${created.id}`, 'PUT', {
        sealedData: '2.c',
        wrappedKey: '2.d',
        scheduleCron: null,
      })
    ).json<any>()
    expect(updated).toMatchObject({
      sealedData: '2.c',
      wrappedKey: '2.d',
      scheduleCron: null,
      nextRotationAt: null,
      rotateOnAccessEnd: true,
    })
    expect(
      (
        await admin(`/rotation/configs/${created.id}`, 'PUT', {
          sealedData: '2.c',
          wrappedKey: '2.d',
          scheduleCron: 'bad',
        })
      ).status,
    ).toBe(400)

    expect((await admin(`/rotation/configs/${created.id}/pause`, 'POST')).status).toBe(200)
    expect((await (await admin(`/rotation/configs/${created.id}`)).json<any>()).enabled).toBe(false)
    expect((await admin(`/rotation/configs/${created.id}/rotate`, 'POST')).status).toBe(400)
    expect((await admin(`/rotation/configs/${created.id}/resume`, 'POST')).status).toBe(200)
    expect((await (await admin(`/rotation/configs/${created.id}`)).json<any>()).enabled).toBe(true)

    expect((await admin(`/rotation/configs/${created.id}`, 'DELETE')).status).toBe(200)
    expect((await admin(`/rotation/configs/${created.id}`)).status).toBe(404)
  })

  it('validates the item and the target system', async () => {
    const target = await seal('cfg-val')
    const pending = (
      await (await admin('/rotation/target-systems', 'POST', { name: 'p', method: 0 })).json<any>()
    ).id
    const { cipherId: id } = await freshConfig()
    const base = { cipherId: id, targetSystemId: target, sealedData: '2.a', wrappedKey: '2.b' }
    expect(
      (await admin('/rotation/configs', 'POST', { ...base, cipherId: crypto.randomUUID() })).status,
    ).toBe(404)
    expect(
      (await admin('/rotation/configs', 'POST', { ...base, targetSystemId: crypto.randomUUID() }))
        .status,
    ).toBe(404)
    expect(
      (await admin('/rotation/configs', 'POST', { ...base, targetSystemId: pending })).status,
    ).toBe(400)
    expect(
      (await admin('/rotation/configs', 'POST', { ...base, scheduleCron: '* *' })).status,
    ).toBe(400)
    expect((await admin('/rotation/configs', 'POST', { ...base, sealedData: '' })).status).toBe(400)
  })

  it('records a manual rotation and rejects it for automatic targets', async () => {
    const manual = await seal('manual', 1)
    const auto = await seal('auto')
    const a = (await freshConfig()).cipherId
    const b = (await freshConfig()).cipherId
    const mc = await (
      await admin('/rotation/configs', 'POST', {
        cipherId: a,
        targetSystemId: manual,
        sealedData: '2.a',
        wrappedKey: '2.b',
        scheduleCron: '0 0 1 1 *',
      })
    ).json<any>()
    const ac = await (
      await admin('/rotation/configs', 'POST', {
        cipherId: b,
        targetSystemId: auto,
        sealedData: '2.a',
        wrappedKey: '2.b',
      })
    ).json<any>()
    expect((await admin(`/rotation/configs/${ac.id}/record-manual`, 'POST')).status).toBe(400)
    // Rotating a manual target flags the obligation instead of queueing a job.
    expect((await admin(`/rotation/configs/${mc.id}/rotate`, 'POST')).status).toBe(200)
    expect(await (await admin(`/rotation/configs/${mc.id}`)).json<any>()).toMatchObject({
      awaitingManualRotation: true,
      hasActiveJob: false,
    })
    expect((await admin(`/rotation/configs/${mc.id}/record-manual`, 'POST')).status).toBe(200)
    const after = await (await admin(`/rotation/configs/${mc.id}`)).json<any>()
    expect(after.awaitingManualRotation).toBe(false)
    expect(after.lastRotationAt).toBeTruthy()
  })

  it('queues an on-demand job once and applies the cooldown', async () => {
    const target = await seal('ondemand')
    const { cipherId: id } = await freshConfig()
    const c = await (
      await admin('/rotation/configs', 'POST', {
        cipherId: id,
        targetSystemId: target,
        sealedData: '2.a',
        wrappedKey: '2.b',
      })
    ).json<any>()
    expect((await admin(`/rotation/configs/${c.id}/rotate`, 'POST')).status).toBe(200)
    const detail = await (await admin(`/rotation/configs/${c.id}`)).json<any>()
    expect(detail.hasActiveJob).toBe(true)
    expect(detail.jobs).toHaveLength(1)
    expect(detail.jobs[0]).toMatchObject({ source: 1, status: 0, attempts: [] })
    // Within the cooldown, and with a job open.
    expect((await admin(`/rotation/configs/${c.id}/rotate`, 'POST')).status).toBe(429)
    await sql('update pam_rotation_configs set last_on_demand_at = 1 where uuid = ?', c.id)
    expect((await admin(`/rotation/configs/${c.id}/rotate`, 'POST')).status).toBe(409)
  })
})

describe('connector rotation flow', () => {
  async function setup(name: string) {
    const dev = await connectorFor(owner, orgId, name)
    const target = await seal(`flow-${name}`)
    await admin(`/${dev.reg.id}/assignments`, 'POST', { targetSystemId: target })
    const { cipherId: id } = await freshConfig()
    const cfg = await (
      await admin('/rotation/configs', 'POST', {
        cipherId: id,
        targetSystemId: target,
        sealedData: '2.cfg',
        wrappedKey: '2.cfgkey',
      })
    ).json<any>()
    await admin(`/rotation/configs/${cfg.id}/rotate`, 'POST')
    const jobs = await (await dev.call('/jobs')).json<any>()
    return { dev, target, cipherId: id, cfg, jobs }
  }

  const rotated = (cipher: any, password = '2.newpw') => ({
    type: 1,
    name: cipher.name,
    key: cipher.key,
    organizationId: orgId,
    login: { ...cipher.login, password },
    lastKnownRevisionDate: cipher.revisionDate,
  })

  it('runs poll, claim, read, write and success', async () => {
    const { dev, target, cipherId: id, cfg, jobs } = await setup('happy')
    expect(jobs).toMatchObject({ object: 'list', continuationToken: null })
    expect(jobs.data).toHaveLength(1)
    expect(jobs.data[0]).toMatchObject({ source: 1, targetSystemId: target })

    const claim = await (await dev.call(`/jobs/${jobs.data[0].jobId}/claim`, 'POST')).json<any>()
    expect(claim).toMatchObject({
      jobId: jobs.data[0].jobId,
      source: 1,
      targetSystemId: target,
      targetSystemName: 'flow-happy',
      targetSystemSealedData: '2.sealed',
      targetSystemWrappedKey: '2.wrapped',
      cipherId: id,
      rotationConfigSealedData: '2.cfg',
      rotationConfigWrappedKey: '2.cfgkey',
    })
    expect(Date.parse(claim.executeBy)).toBeGreaterThan(Date.now())
    // A claimed job is no longer offered.
    expect((await (await dev.call('/jobs')).json<any>()).data).toHaveLength(0)

    // Success before any write is stale.
    const early = await dev.call(`/attempts/${claim.attemptId}/success`, 'POST', {
      sessionTermination: 0,
    })
    expect(early.status).toBe(409)

    const cipher = await (await dev.call(`/attempts/${claim.attemptId}/cipher`)).json<any>()
    expect(cipher).toMatchObject({
      object: 'cipherMini',
      id,
      organizationId: orgId,
      name: '2.db',
      key: '2.ckey',
    })
    expect(cipher.login.password).toBe('2.p')

    // A stale revision is refused, the item stays unchanged.
    const stale = await dev.call(
      `/attempts/${claim.attemptId}/cipher`,
      'PUT',
      rotated({ ...cipher, revisionDate: '2020-01-01T00:00:00.000Z' }),
    )
    expect(stale.status).toBe(409)
    // The item key must not change.
    expect(
      (
        await dev.call(`/attempts/${claim.attemptId}/cipher`, 'PUT', {
          ...rotated(cipher),
          key: '2.other',
        })
      ).status,
    ).toBe(400)
    // A non-login body is refused.
    expect(
      (
        await dev.call(`/attempts/${claim.attemptId}/cipher`, 'PUT', {
          ...rotated(cipher),
          type: 2,
        })
      ).status,
    ).toBe(400)

    const wrote = await dev.call(`/attempts/${claim.attemptId}/cipher`, 'PUT', rotated(cipher))
    expect(wrote.status).toBe(200)
    expect((await (await owner.call(`/api/ciphers/${id}`)).json<any>()).login.password).toBe(
      '2.newpw',
    )
    // A second write from the old revision is refused.
    expect(
      (await dev.call(`/attempts/${claim.attemptId}/cipher`, 'PUT', rotated(cipher, '2.third')))
        .status,
    ).toBe(409)

    const ok = await dev.call(`/attempts/${claim.attemptId}/success`, 'POST', {
      sessionTermination: 1,
    })
    expect(ok.status).toBe(200)
    // Reporting twice is stale.
    expect(
      (await dev.call(`/attempts/${claim.attemptId}/success`, 'POST', { sessionTermination: 1 }))
        .status,
    ).toBe(409)

    const detail = await (await admin(`/rotation/configs/${cfg.id}`)).json<any>()
    expect(detail.hasActiveJob).toBe(false)
    expect(detail.lastRotationAt).toBeTruthy()
    expect(detail.jobs[0]).toMatchObject({ status: 2 })
    expect(detail.jobs[0].attempts[0]).toMatchObject({
      id: claim.attemptId,
      status: 1,
      cipherUpdated: true,
      syncState: 1,
      sessionTermination: 1,
    })
    // The connector detail lists the job it worked.
    const cd = await (await admin(`/${dev.reg.id}`)).json<any>()
    expect(cd.jobs.map((j: any) => j.id)).toContain(jobs.data[0].jobId)
    // The audit trail has the rejected report.
    const audit = (
      await sql(
        'select kind from pam_audit where organization_uuid = ? and ref_uuid = ?',
        orgId,
        jobs.data[0].jobId,
      )
    ).results.map((r) => r.kind)
    expect(audit).toEqual(
      expect.arrayContaining([
        'rotation_claimed',
        'report_rejected',
        'write_rejected',
        'rotation_cipher_written',
        'rotation_succeeded',
      ]),
    )
  })

  it('records a failure with a bounded reason and frees the job slot', async () => {
    const { dev, cfg, jobs } = await setup('fail')
    const claim = await (await dev.call(`/jobs/${jobs.data[0].jobId}/claim`, 'POST')).json<any>()
    const bad = (b: unknown) => dev.call(`/attempts/${claim.attemptId}/failure`, 'POST', b)
    expect((await bad({ syncState: 9, errorCode: 'x' })).status).toBe(400)
    expect((await bad({ syncState: 0, errorCode: 'x'.repeat(65) })).status).toBe(400)
    expect((await bad({ syncState: 0, errorCode: 'e', detail: 'd'.repeat(257) })).status).toBe(400)
    expect(
      (await bad({ syncState: 2, errorCode: 'AUTH_FAILED', detail: 'login   refused\n  by host' }))
        .status,
    ).toBe(200)
    expect((await bad({ syncState: 2, errorCode: 'AUTH_FAILED' })).status).toBe(409)
    const detail = await (await admin(`/rotation/configs/${cfg.id}`)).json<any>()
    expect(detail.jobs[0]).toMatchObject({ status: 3 })
    expect(detail.jobs[0].attempts[0]).toMatchObject({
      status: 2,
      syncState: 2,
      failureReason: 'AUTH_FAILED: login refused by host',
    })
    // The slot is free again, so a new on-demand job can be queued.
    await sql('update pam_rotation_configs set last_on_demand_at = 1 where uuid = ?', cfg.id)
    expect((await admin(`/rotation/configs/${cfg.id}/rotate`, 'POST')).status).toBe(200)
  })

  it('lets exactly one of several connectors win a claim', async () => {
    const target = await seal('race')
    const devs = await Promise.all(
      ['r1', 'r2', 'r3', 'r4'].map((n) => connectorFor(owner, orgId, n)),
    )
    for (const d of devs)
      await admin(`/${d.reg.id}/assignments`, 'POST', { targetSystemId: target })
    const { cipherId: id } = await freshConfig()
    const cfg = await (
      await admin('/rotation/configs', 'POST', {
        cipherId: id,
        targetSystemId: target,
        sealedData: '2.a',
        wrappedKey: '2.b',
      })
    ).json<any>()
    await admin(`/rotation/configs/${cfg.id}/rotate`, 'POST')
    const jobId = (await (await (devs[0] as (typeof devs)[number]).call('/jobs')).json<any>())
      .data[0].jobId
    const results = await Promise.all(devs.map((d) => d.call(`/jobs/${jobId}/claim`, 'POST')))
    const statuses = results.map((r) => r.status).sort()
    expect(statuses).toEqual([200, 409, 409, 409])
    const attempts = (
      await sql('select count(*) as n from pam_rotation_attempts where job_uuid = ?', jobId)
    ).results[0]
    expect(attempts.n).toBe(1)
    // The winner cannot be displaced by a late claim, and the losers cannot touch its attempt.
    const winnerIndex = results.findIndex((r) => r.status === 200)
    const claim = await results[winnerIndex]?.json<any>()
    const loser = devs[(winnerIndex + 1) % devs.length]
    expect((await loser?.call(`/attempts/${(claim as any).attemptId}/cipher`))?.status).toBe(404)
  })

  it('refuses claims from connectors that are not assigned, and for unknown jobs', async () => {
    const { jobs } = await setup('assigned')
    const other = await connectorFor(owner, orgId, 'unassigned')
    expect((await (await other.call('/jobs')).json<any>()).data).toEqual([])
    expect((await other.call(`/jobs/${jobs.data[0].jobId}/claim`, 'POST')).status).toBe(404)
    expect((await other.call(`/jobs/${crypto.randomUUID()}/claim`, 'POST')).status).toBe(404)
  })

  it('does not offer or claim jobs of a paused configuration or disabled target', async () => {
    const { dev, cfg, target, jobs } = await setup('paused')
    await admin(`/rotation/configs/${cfg.id}/pause`, 'POST')
    expect((await (await dev.call('/jobs')).json<any>()).data).toHaveLength(0)
    expect((await dev.call(`/jobs/${jobs.data[0].jobId}/claim`, 'POST')).status).toBe(404)
    await admin(`/rotation/configs/${cfg.id}/resume`, 'POST')
    await admin(`/rotation/target-systems/${target}/disable`, 'POST')
    expect((await (await dev.call('/jobs')).json<any>()).data).toHaveLength(0)
    await admin(`/rotation/target-systems/${target}/enable`, 'POST')
    expect((await (await dev.call('/jobs')).json<any>()).data).toHaveLength(1)
  })

  it('releases a running claim when the connector is disabled', async () => {
    const { dev, cfg, jobs } = await setup('release')
    const claim = await (await dev.call(`/jobs/${jobs.data[0].jobId}/claim`, 'POST')).json<any>()
    await admin(`/${dev.reg.id}/disable`, 'POST')
    const detail = await (await admin(`/rotation/configs/${cfg.id}`)).json<any>()
    expect(detail.jobs[0]).toMatchObject({ status: 0, claimedAt: null })
    expect(detail.jobs[0].attempts[0]).toMatchObject({ id: claim.attemptId, status: 3 })
    // A deleted configuration cannot be removed while a connector holds the job.
    await admin(`/${dev.reg.id}/enable`, 'POST')
    await dev.call(`/jobs/${jobs.data[0].jobId}/claim`, 'POST')
    expect((await admin(`/rotation/configs/${cfg.id}`, 'DELETE')).status).toBe(409)
  })
})

describe('rotation sweep', () => {
  it('releases stale claims, times out old jobs and queues scheduled rotations', async () => {
    const dev = await connectorFor(owner, orgId, 'sweeper')
    const target = await seal('sweep')
    await admin(`/${dev.reg.id}/assignments`, 'POST', { targetSystemId: target })
    const { cipherId: id } = await freshConfig()
    const cfg = await (
      await admin('/rotation/configs', 'POST', {
        cipherId: id,
        targetSystemId: target,
        sealedData: '2.a',
        wrappedKey: '2.b',
        scheduleCron: '* * * * *',
      })
    ).json<any>()

    // A due schedule queues a Scheduled job and moves the schedule on.
    const now = Date.now()
    await sql(
      'update pam_rotation_configs set next_rotation_at = ? where uuid = ?',
      now - 1000,
      cfg.id,
    )
    await sweepRotation(env, now)
    let detail = await (await admin(`/rotation/configs/${cfg.id}`)).json<any>()
    expect(detail.jobs).toHaveLength(1)
    expect(detail.jobs[0]).toMatchObject({ source: 0, status: 0 })
    expect(Date.parse(detail.nextRotationAt)).toBeGreaterThan(now)
    // Running the sweep again queues nothing new.
    await sweepRotation(env, now)
    expect((await (await admin(`/rotation/configs/${cfg.id}`)).json<any>()).jobs).toHaveLength(1)

    // A claim whose lease ended while the connector is silent goes back to the queue.
    const jobId = detail.jobs[0].id
    const claim = await (await dev.call(`/jobs/${jobId}/claim`, 'POST')).json<any>()
    await sweepRotation(env, now + 60_000)
    detail = await (await admin(`/rotation/configs/${cfg.id}`)).json<any>()
    expect(detail.jobs[0].status).toBe(1)
    const later = now + 20 * 60_000
    await sweepRotation(env, later)
    detail = await (await admin(`/rotation/configs/${cfg.id}`)).json<any>()
    expect(detail.jobs[0]).toMatchObject({ status: 0 })
    expect(detail.jobs[0].attempts[0]).toMatchObject({ id: claim.attemptId, status: 3 })
    // The released attempt can no longer write or report.
    expect(
      (await dev.call(`/attempts/${claim.attemptId}/success`, 'POST', { sessionTermination: 0 }))
        .status,
    ).toBe(409)

    // A job past its lifetime times out and frees the slot.
    await sweepRotation(env, now + 7 * 3_600_000)
    detail = await (await admin(`/rotation/configs/${cfg.id}`)).json<any>()
    expect(detail.jobs.find((j: any) => j.id === jobId).status).toBe(4)
  })
})
