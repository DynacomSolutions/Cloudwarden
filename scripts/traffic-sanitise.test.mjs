import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import test from 'node:test'
import { createSanitiser, findIdentifying } from './traffic-sanitise.mjs'

const dir = join(import.meta.dirname, '..', 'test', 'fixtures', 'traffic')

test('replaces every kind of identifying value deterministically', () => {
  const real = {
    email: 'someone@corp.test',
    userId: '8c1b2a4e-1111-4222-8333-444455556666',
    again: '8c1b2a4e-1111-4222-8333-444455556666',
    other: '9d2c3b5f-2222-4333-9444-555566667777',
    Key: '2.AbCdEfGhIjKlMnOpQrStUv==|AbCdEfGhIjKlMnOpQrStUv==|AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef=',
    access_token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln',
    refresh_token: 'rt-1234567890',
    url: 'https://127.0.0.1:8443/x',
    revisionDate: '2026-10-06T17:26:43.106Z',
    password: 'aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA==',
  }
  assert.ok(findIdentifying(real).length >= 8)
  const a = createSanitiser().value(real)
  assert.deepEqual(a, createSanitiser().value(real), 'deterministic')
  assert.deepEqual(findIdentifying(a), [])
  assert.equal(a.userId, a.again)
  assert.notEqual(a.userId, a.other)
  assert.equal(a.email, 'user@example.com')
  assert.equal(a.url, 'https://vault.example.com/x')
  assert.ok(a.Key.startsWith('2.'))
  assert.deepEqual(createSanitiser().value(a), a, 'idempotent')
})

test('treats the registration authentication hash like the login password', () => {
  const hash = 'aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA=='
  const out = createSanitiser().value({
    masterPasswordAuthentication: { masterPasswordAuthenticationHash: hash },
    password: hash,
  })
  assert.equal(out.masterPasswordAuthentication.masterPasswordAuthenticationHash, out.password)
  assert.match(out.password, /^__[A-Z_]+__$/)
})

test('replaces the push token a mobile app registers for its device', () => {
  const token = 'fakeFcmInstanceId0000:APA91b' + '0'.repeat(58)
  const out = createSanitiser().value({ pushToken: token })
  assert.equal(out.pushToken, '__PUSHTOKEN__')
  assert.deepEqual(
    findIdentifying({ pushToken: token }).map((f) => f.reason),
    ['secret in pushToken'],
  )
})

// Obviously synthetic: header and payload are base64url of fake JSON, the signature is filler.
const fakeJwt = `${btoa('{"alg":"none"}').replace(/=+$/, '')}.${btoa('{"fake":true}').replace(/=+$/, '')}.c2lnbmF0dXJl`

test('replaces a JWT wrapped in literal quotes or embedded in a longer string', () => {
  assert.ok(fakeJwt.startsWith('eyJ'))
  const real = {
    emailVerificationToken: `"${fakeJwt}"`,
    note: `prefix ${fakeJwt} suffix`,
    list: [`"${fakeJwt}"`],
  }
  assert.ok(findIdentifying(real).length >= 3)
  const a = createSanitiser().value(real)
  assert.equal(a.emailVerificationToken, '"__ACCESS_TOKEN__"')
  assert.equal(a.note, 'prefix __ACCESS_TOKEN__ suffix')
  assert.deepEqual(a.list, ['"__ACCESS_TOKEN__"'])
  assert.deepEqual(findIdentifying(a), [])
  assert.deepEqual(createSanitiser().value(a), a, 'idempotent')
  assert.deepEqual(createSanitiser().value(real), a, 'deterministic')
})

test('treats emailVerificationToken as a secret key in any case', () => {
  const out = createSanitiser().value({ EmailVerificationToken: 'opaque-value' })
  assert.equal(out.EmailVerificationToken, '__EMAILVERIFICATIONTOKEN__')
  assert.deepEqual(
    findIdentifying({ emailVerificationToken: 'opaque-value' }).map((f) => f.reason),
    ['secret in emailVerificationToken'],
  )
})

test('findIdentifying flags a JWT anywhere in a value', () => {
  for (const v of [fakeJwt, `"${fakeJwt}"`, `Bearer ${fakeJwt}`, `x=${fakeJwt}&y=1`]) {
    assert.deepEqual(
      findIdentifying({ anything: v }).map((f) => f.reason),
      ['JWT'],
      v,
    )
  }
})

test('every recorded traffic fixture is free of identifying data', () => {
  const files = readdirSync(dir).filter((f) => f.endsWith('.json'))
  assert.ok(files.length > 0)
  for (const f of files) {
    assert.deepEqual(findIdentifying(JSON.parse(readFileSync(join(dir, f), 'utf8'))), [], f)
  }
})
