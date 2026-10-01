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

it('vault key builders refuse ids that point into backups/', async () => {
  const { attachmentKey, sendFileKey } = await import('../src/vault/blobs')
  expect(attachmentKey('c1', 'a1')).toBe('attachments/c1/a1')
  expect(sendFileKey('s1', 'f1')).toBe('sends/s1/f1')
  expect(() => attachmentKey('x/../../backups', 'y')).toThrow()
})
