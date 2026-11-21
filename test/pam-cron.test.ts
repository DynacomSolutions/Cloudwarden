import { expect, it } from 'vitest'
import { nextRun, parseCron } from '../src/pam/cron'

const at = (iso: string) => Date.parse(iso)

it('rejects malformed expressions', () => {
  for (const bad of [
    '',
    '* * * *',
    '61 * * * *',
    '* 24 * * *',
    '*/0 * * * *',
    'a * * * *',
    '5-1 * * * *',
  ]) {
    expect(parseCron(bad), bad).toBeNull()
  }
  expect(parseCron('*/15 0-6 1,15 * 1-5')).not.toBeNull()
})

it('finds the next matching minute strictly after the given time', () => {
  expect(nextRun('* * * * *', at('2026-11-22T10:00:30Z'))).toBe(at('2026-11-22T10:01:00Z'))
  expect(nextRun('*/15 * * * *', at('2026-11-22T10:15:00Z'))).toBe(at('2026-11-22T10:30:00Z'))
  expect(nextRun('0 3 * * *', at('2026-11-22T10:00:00Z'))).toBe(at('2026-11-23T03:00:00Z'))
  expect(nextRun('30 2 1 * *', at('2026-11-22T10:00:00Z'))).toBe(at('2026-12-01T02:30:00Z'))
  // 22 Nov 2026 is a Sunday: the next Monday is the 23rd.
  expect(nextRun('0 9 * * 1', at('2026-11-22T10:00:00Z'))).toBe(at('2026-11-23T09:00:00Z'))
  expect(nextRun('0 9 * * 7', at('2026-11-22T10:00:00Z'))).toBe(at('2026-11-29T09:00:00Z'))
  // Day of month and day of week both set: either matches.
  expect(nextRun('0 0 25 * 1', at('2026-11-22T10:00:00Z'))).toBe(at('2026-11-23T00:00:00Z'))
  // Leap day.
  expect(nextRun('0 0 29 2 *', at('2026-11-22T10:00:00Z'))).toBe(at('2028-02-29T00:00:00Z'))
})

it('returns null for an invalid expression', () => {
  expect(nextRun('nope', Date.now())).toBeNull()
})
