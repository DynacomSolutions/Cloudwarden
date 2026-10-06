import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'

interface Migration {
  name: string
  queries: string[]
}

/**
 * Rebuilds the previous shapes of the two tables the organisations migration rewrites, loads rows
 * the way an existing deployment would hold them, then replays the rewrite statements.
 */
it('carries collection grants and member emails over the organisations migration', async () => {
  const migrations = env.TEST_MIGRATIONS as unknown as Migration[]
  const mig = migrations.find((m) => m.name.includes('organizations'))
  expect(mig).toBeDefined()
  const rewrite = (mig?.queries ?? []).filter(
    (q) =>
      /users_collections|users_organizations/.test(q) &&
      !/^CREATE TABLE `(groups|policies)/.test(q),
  )
  expect(rewrite.length).toBeGreaterThan(5)

  const run = (sql: string, ...args: unknown[]) =>
    env.DB.prepare(sql)
      .bind(...args)
      .run()
  await run('PRAGMA foreign_keys=OFF')
  for (const t of ['groups_users', 'users_collections', 'users_organizations']) {
    await run(`DROP TABLE IF EXISTS ${t}`)
  }
  await run(
    'CREATE TABLE users_organizations (uuid text PRIMARY KEY NOT NULL, user_uuid text NOT NULL, organization_uuid text NOT NULL, access_all integer DEFAULT false NOT NULL, akey text NOT NULL, status integer NOT NULL, atype integer NOT NULL, reset_password_key text, external_id text, created_at integer NOT NULL, updated_at integer NOT NULL)',
  )
  await run(
    'CREATE TABLE users_collections (user_uuid text NOT NULL, collection_uuid text NOT NULL, read_only integer DEFAULT false NOT NULL, hide_passwords integer DEFAULT false NOT NULL, manage integer DEFAULT false NOT NULL, PRIMARY KEY(user_uuid, collection_uuid))',
  )
  await run(
    "INSERT INTO users (uuid, email, name, password_hash, salt, password_iterations, akey, security_stamp, created_at, updated_at) VALUES ('u1', 'old-member@example.com', 'n', 'h', 's', 1, 'k', 'st', 1, 1)",
  )
  await run(
    "INSERT INTO organizations (uuid, name, billing_email, created_at, updated_at) VALUES ('o1', 'Org', 'b@example.com', 1, 1)",
  )
  await run(
    "INSERT INTO collections (uuid, organization_uuid, name, created_at, updated_at) VALUES ('c1', 'o1', 'col', 1, 1)",
  )
  await run(
    "INSERT INTO users_organizations VALUES ('m1', 'u1', 'o1', 0, '4.k', 2, 2, NULL, NULL, 1, 1)",
  )
  await run("INSERT INTO users_collections VALUES ('u1', 'c1', 1, 1, 0)")
  // A grant to a collection of an organisation the user is not in cannot be mapped and is dropped.
  await run(
    "INSERT INTO organizations (uuid, name, billing_email, created_at, updated_at) VALUES ('o2', 'Org2', 'b@example.com', 1, 1)",
  )
  await run(
    "INSERT INTO collections (uuid, organization_uuid, name, created_at, updated_at) VALUES ('c2', 'o2', 'col', 1, 1)",
  )
  await run("INSERT INTO users_collections VALUES ('u1', 'c2', 0, 0, 1)")

  for (const q of rewrite) await env.DB.prepare(q).run()

  const member = await env.DB.prepare(
    'select email, permissions, user_uuid from users_organizations where uuid = ?',
  )
    .bind('m1')
    .first<{ email: string; permissions: string | null; user_uuid: string }>()
  expect(member).toEqual({ email: 'old-member@example.com', permissions: null, user_uuid: 'u1' })
  const grants = await env.DB.prepare('select * from users_collections').all()
  expect(grants.results).toEqual([
    {
      organization_user_uuid: 'm1',
      collection_uuid: 'c1',
      read_only: 1,
      hide_passwords: 1,
      manage: 0,
    },
  ])
})

it('marks old incoming pending requests as incoming, and nothing else', async () => {
  const migrations = env.TEST_MIGRATIONS as unknown as Migration[]
  const mig = migrations.find((m) => m.name.includes('federation_incoming_backfill'))
  expect(mig).toBeDefined()
  const run = (sql: string, ...args: unknown[]) =>
    env.DB.prepare(sql)
      .bind(...args)
      .run()
  const peer = (
    id: string,
    status: string,
    local: number,
    remote: number,
    requestedBy: string | null,
    approvedBy: string | null,
  ) =>
    run(
      "INSERT INTO federation_peers (uuid, instance_id, domain, public_key, fingerprint, protocol_version, status, local_approved, remote_approved, requested_by, approved_by, incoming, created_at, updated_at) VALUES (?1, ?1, ?2, 'k', 'f', 1, ?3, ?4, ?5, ?6, ?7, 0, 0, 0)",
      id,
      `${id}.example.net`,
      status,
      local,
      remote,
      requestedBy,
      approvedBy,
    )
  await peer('old-incoming', 'pending', 0, 1, null, null)
  await peer('user-request', 'pending', 0, 1, 'u1', null)
  await peer('admin-added', 'pending', 0, 0, null, null)
  await peer('active', 'active', 1, 1, null, null)
  await peer('approved', 'pending', 0, 1, null, 'admin')
  for (const q of mig?.queries ?? []) await env.DB.prepare(q).run()
  const rows = await env.DB.prepare(
    'select uuid, incoming from federation_peers order by uuid',
  ).all()
  expect(Object.fromEntries(rows.results.map((r) => [r.uuid, r.incoming]))).toEqual({
    active: 0,
    'admin-added': 0,
    approved: 0,
    'old-incoming': 1,
    'user-request': 0,
  })
})
