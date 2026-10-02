// Access token parsing and key derivation of the e2e Secrets Manager client (TASKS #220), checked
// against the vector published in the GPL-3.0 `bitwarden-core` crate (auth/access_token.rs).
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'
import { decType2, encType2 } from '../e2e/crypto.mjs'
import { parseAccessToken } from '../e2e/sm-client.mjs'

const VECTOR =
  '0.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ=='

test('parses an access token and derives its key like the SDK', () => {
  const t = parseAccessToken(VECTOR)
  assert.equal(t.id, 'ec2c1d46-6a4b-4751-a310-af9601317f2d')
  assert.equal(t.clientSecret, 'C2IgxjjLF7qSshsbwe8JGcbM075YXw')
  assert.equal(
    t.key.toString('base64'),
    'H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg==',
  )
})

test('rejects malformed tokens', () => {
  assert.throws(() => parseAccessToken(VECTOR.replace(/^0/, '1')), /malformed/)
  assert.throws(() => parseAccessToken(VECTOR.split(':')[0]), /no key/)
  assert.throws(() => parseAccessToken(`${VECTOR.split(':')[0]}:AAAA`), /16 bytes/)
})

test('type 2 EncStrings round-trip and fail on a bad MAC', async () => {
  const key = randomBytes(64)
  const s = await encType2(Buffer.from('hello'), key)
  assert.equal((await decType2(s, key)).toString(), 'hello')
  const [iv, ct] = s.slice(2).split('|')
  await assert.rejects(decType2(`2.${iv}|${ct}|${Buffer.alloc(32).toString('base64')}`, key), /MAC/)
})
