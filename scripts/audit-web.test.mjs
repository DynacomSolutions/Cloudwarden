import assert from 'node:assert/strict'
import { test } from 'node:test'
import { ACCEPTED, blocking } from './audit-web.mjs'

const adv = (severity, id) => ({
  severity,
  name: 'pkg',
  title: 't',
  url: `https://github.com/advisories/${id}`,
})

test('blocking reports unaccepted high and critical advisories only', () => {
  const report = {
    vulnerabilities: {
      a: { via: [adv('high', 'GHSA-new'), adv('moderate', 'GHSA-mod'), 'b'] },
      b: { via: [adv('critical', 'GHSA-crit'), adv('high', [...ACCEPTED][0])] },
    },
  }
  assert.deepEqual([...blocking(report).keys()].sort(), ['GHSA-crit', 'GHSA-new'])
  assert.equal(blocking({}).size, 0)
})
