import { expect, it } from 'vitest'
import { assertUserBlobKey, isReservedBlobKey } from '../src/blob-keys'

it('flags keys under the backups prefix', () => {
  for (const k of [
    'backups/2026-10-01/run-1/manifest.json',
    '/backups/x',
    'BACKUPS/x',
    'a/../backups/x',
    '../backups/x',
  ]) {
    expect(isReservedBlobKey(k), k).toBe(true)
  }
  expect(isReservedBlobKey('attachments/u/a/f')).toBe(false)
  expect(() => assertUserBlobKey('backups/x')).toThrow()
  expect(assertUserBlobKey('sends/s/f')).toBe('sends/s/f')
})
