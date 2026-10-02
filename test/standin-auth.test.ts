import { env } from 'cloudflare:workers'
import { eq } from 'drizzle-orm'
import { describe, expect, it } from 'vitest'
import { authenticateAccessToken } from '../src/auth/middleware'
import { signAccessToken } from '../src/auth/session'
import { createDb, schema } from '../src/db'
import { FEDERATION_CLIENT_ID, STAND_IN_HASH_PREFIX } from '../src/federation/standin'
import { provisionSsoUser } from '../src/sso/flow'
import { actor, addMember, createOrg } from './org-helpers'

let n = 0
const unique = (p: string) => `${p}-${Date.now()}-${++n}@example.com`

async function newKey() {
  const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  const der = new Uint8Array((await crypto.subtle.exportKey('pkcs8', kp.privateKey)) as ArrayBuffer)
  return btoa(String.fromCharCode(...der))
}

/** An organisation member whose account is then turned into a stand-in. */
async function standInMember() {
  const owner = await actor(unique('owner'))
  const org = await createOrg(owner)
  const member = await actor(unique('member'))
  await addMember(owner, org.id, member, { type: 2 })
  const db = createDb(env.DB)
  await db
    .update(schema.users)
    .set({ passwordHash: `${STAND_IN_HASH_PREFIX}peer` })
    .where(eq(schema.users.uuid, member.uuid))
  const [user] = await db.select().from(schema.users).where(eq(schema.users.uuid, member.uuid))
  if (!user) throw new Error('missing user')
  return { org, member, user, db }
}

describe('stand-in accounts and SSO', () => {
  it('refuses to link or sign in a stand-in account, by email or by link request', async () => {
    const { org, member, db } = await standInMember()
    const identity = {
      externalId: `ext-${Date.now()}`,
      email: member.email,
      name: 'X',
      emailVerified: true,
    }
    await expect(provisionSsoUser(db, org.id, identity, null)).rejects.toThrow(/another server/)
    await expect(provisionSsoUser(db, org.id, identity, member.uuid)).rejects.toThrow(
      /another server/,
    )
    const links = await db
      .select()
      .from(schema.ssoUsers)
      .where(eq(schema.ssoUsers.userUuid, member.uuid))
    expect(links).toHaveLength(0)
  })
})

describe('access tokens of stand-in accounts under ES256', () => {
  it('accepts the federation token and refuses any other token for a stand-in', async () => {
    const { user } = await standInMember()
    const e = { ...env, JWT_SIGNING_KEY: await newKey() }
    const fed = await signAccessToken(e, user, 'd', ['api'], FEDERATION_CLIENT_ID)
    expect(JSON.parse(atob(fed.split('.')[0] ?? '')).alg).toBe('ES256')
    const ok = await authenticateAccessToken(e, fed)
    expect(ok?.user.uuid).toBe(user.uuid)

    const plain = await signAccessToken(e, user, 'd', ['api'])
    expect(await authenticateAccessToken(e, plain)).toBeNull()
    const other = await signAccessToken(e, user, 'd', ['api'], 'web')
    expect(await authenticateAccessToken(e, other)).toBeNull()
  })
})
