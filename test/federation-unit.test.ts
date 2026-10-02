// Federation building blocks (TASKS #308): signatures, address checks, identity at rest.
import { env } from 'cloudflare:workers'
import { describe, expect, it } from 'vitest'
import { fingerprintOf, loadIdentity, normaliseFingerprint } from '../src/federation/identity'
import { parsePeerDomain } from '../src/federation/net'
import {
  contentDigest,
  parseSignature,
  signatureBase,
  signRequest,
  verifyRequest,
} from '../src/federation/signature'

describe('HTTP message signatures', () => {
  it('signs and verifies with a fixed component list', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const pub = new Uint8Array(
      (await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer,
    )
    const pubB64u = btoa(String.fromCharCode(...pub))
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replace(/=+$/, '')
    const url = 'https://peer.example.org/federation/v1/events'
    const body = new TextEncoder().encode('{"a":1}')
    const headers = new Headers()
    const keyid = '00000000-0000-0000-0000-000000000000'
    await signRequest('POST', url, headers, body, keyid, pair.privateKey)
    expect(headers.get('content-digest')).toBe(await contentDigest(body))
    const parsed = parseSignature(headers)
    expect(parsed?.params.keyid).toBe(keyid)
    if (!parsed) return
    const req = { method: 'POST', url, headers }
    expect(await verifyRequest(req, body, parsed, pubB64u)).toBeNull()
    expect(signatureBase(req, parsed.params)).toContain(
      '"@target-uri": https://peer.example.org/federation/v1/events',
    )
    expect(await verifyRequest({ ...req, url: `${url}?x=1` }, body, parsed, pubB64u)).toBe(
      'signature',
    )
    expect(await verifyRequest({ ...req, method: 'PUT' }, body, parsed, pubB64u)).toBe('signature')
    expect(await verifyRequest(req, new Uint8Array([1]), parsed, pubB64u)).toBe('digest')
    expect(await verifyRequest(req, body, parsed, pubB64u, Date.now() + 3600_000)).toBe('expired')
    // A different covered component list is not accepted at all.
    const changed = new Headers(headers)
    changed.set('signature-input', (headers.get('signature-input') ?? '').replace('"@method" ', ''))
    expect(parseSignature(changed)).toBeNull()
  })
})

describe('peer address checks', () => {
  it('accepts host names only', () => {
    expect(parsePeerDomain('Vault.Example.com')).toBe('vault.example.com')
    expect(parsePeerDomain('https://vault.example.com/')).toBe('vault.example.com')
    for (const bad of [
      '127.0.0.1',
      'localhost',
      'x.local',
      'a.internal',
      'vault.example.com:8443',
      'http://vault.example.com',
      'a b.example.com',
      '[::1]',
    ]) {
      expect(parsePeerDomain(bad)).toBeNull()
    }
  })
})

describe('instance identity', () => {
  it('creates one key pair, stores it encrypted and reloads it', async () => {
    const a = await loadIdentity(env)
    const b = await loadIdentity(env)
    expect(a.instanceId).toBe(b.instanceId)
    const row = await env.DB.prepare('SELECT private_key_enc FROM federation_identity').first<{
      private_key_enc: string
    }>()
    expect(row?.private_key_enc.startsWith('v1.')).toBe(true)
    // The wrong secret cannot open it.
    await expect(loadIdentity({ ...env, FEDERATION_KEY_SECRET: 'x'.repeat(40) })).rejects.toThrow()
    const fp = await fingerprintOf(a.publicKey)
    expect(normaliseFingerprint(fp.toLowerCase().replaceAll(':', ' '))).toBe(
      normaliseFingerprint(fp),
    )
  })
})
