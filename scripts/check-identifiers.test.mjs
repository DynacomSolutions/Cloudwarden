import assert from 'node:assert'
import { test } from 'node:test'
import { IdentifierChecker, isNoreplyAuthorIdent, parseArgs } from './check-identifiers.mjs'

const checker = new IdentifierChecker(process.cwd())

test('Email detection', async (t) => {
  await t.test('detects real email', () => {
    assert.strictEqual(checker.checkEmail('user@example.io'), true)
  })

  await t.test('allows example.com email', () => {
    assert.strictEqual(checker.checkEmail('test@example.com'), false)
  })

  await t.test('allows GitHub noreply email', () => {
    assert.strictEqual(checker.checkEmail('user@users.noreply.github.com'), false)
  })

  await t.test('detects non-example TLD', () => {
    assert.strictEqual(checker.checkEmail('admin@company.com'), true)
  })
})

test('IPv4 detection', async (t) => {
  await t.test('allows 127.0.0.1', () => {
    assert.strictEqual(checker.checkIPv4('127.0.0.1'), false)
  })

  await t.test('allows 0.0.0.0', () => {
    assert.strictEqual(checker.checkIPv4('0.0.0.0'), false)
  })

  await t.test('allows RFC 5737 doc ranges', () => {
    assert.strictEqual(checker.checkIPv4('192.0.2.1'), false)
    assert.strictEqual(checker.checkIPv4('198.51.100.1'), false)
  })

  await t.test('detects real public IP', () => {
    assert.strictEqual(checker.checkIPv4('8.8.8.8'), true)
  })

  await t.test('detects 192.168.x.x', () => {
    assert.strictEqual(checker.checkIPv4('192.168.1.1'), true)
  })
})

test('IPv6 detection', async (t) => {
  await t.test('allows ::1 loopback', () => {
    assert.strictEqual(checker.checkIPv6('::1'), false)
  })

  await t.test('allows 2001:db8:: documentation', () => {
    assert.strictEqual(checker.checkIPv6('2001:db8::1'), false)
  })

  await t.test('detects public IPv6', () => {
    assert.strictEqual(checker.checkIPv6('2001:4860:4860::8888'), true)
  })

  await t.test('allows malformed IPv6 (::)', () => {
    assert.strictEqual(checker.checkIPv6('::'), false)
  })
})

test('Domain detection', async (t) => {
  await t.test('allows example.com', () => {
    assert.strictEqual(checker.checkDomain('example.com'), false)
  })

  await t.test('allows github.com', () => {
    assert.strictEqual(checker.checkDomain('github.com'), false)
  })

  await t.test('allows subdomain of allowed', () => {
    assert.strictEqual(checker.checkDomain('sub.example.com'), false)
  })

  await t.test('detects real domain', () => {
    assert.strictEqual(checker.checkDomain('company.com'), true)
  })

  await t.test('detects corporate domain', () => {
    assert.strictEqual(checker.checkDomain('internal.mycompany.io'), true)
  })

  await t.test('allows localhost', () => {
    assert.strictEqual(checker.checkDomain('localhost'), false)
  })
})

test('Hex token detection', async (t) => {
  await t.test('allows 40-char SHA (GitHub action)', () => {
    assert.strictEqual(checker.checkHexToken('356a192b7913b04c54574d18c28d46e6395428ab'), false)
  })

  await t.test('detects 32-char hex (Cloudflare ID)', () => {
    assert.strictEqual(checker.checkHexToken('abcdef0123456789abcdef0123456789'), true)
  })

  await t.test('detects UUID', () => {
    assert.strictEqual(checker.checkHexToken('550e8400-e29b-41d4-a716-446655440000'), true)
  })

  await t.test('allows all-zeros UUID', () => {
    assert.strictEqual(checker.checkHexToken('00000000-0000-0000-0000-000000000000'), false)
  })

  await t.test('allows v4-shaped placeholder UUID', () => {
    assert.strictEqual(checker.checkHexToken('00000000-0000-4000-8000-000000000000'), false)
  })

  await t.test('detects lowercase UUID', () => {
    assert.strictEqual(checker.checkHexToken('f47ac10b-58cc-4372-a567-0e02b2c3d479'), true)
  })
})

function scan(line, filePath = 'src/file.ts') {
  const c = new IdentifierChecker(process.cwd())
  c.detectIdentifiers(line, 1, filePath)
  return c.findings
}

test('Reserved TLDs', async (t) => {
  await t.test('allows .example, .test, .invalid, .localhost', () => {
    for (const d of ['internal.example', 'svc.test', 'host.invalid', 'app.localhost']) {
      assert.strictEqual(checker.checkDomain(d), false, d)
    }
  })

  await t.test('does not flag reserved TLDs in a line', () => {
    assert.deepStrictEqual(scan('use internal.example or svc.test here'), [])
  })
})

test('Code false positives', async (t) => {
  await t.test('ignores member call like checker.run(', () => {
    assert.deepStrictEqual(scan('checker.run(options).then(() => {})'), [])
  })

  await t.test('ignores optional chaining and indexing', () => {
    assert.deepStrictEqual(scan('obj?.run and list.run[0]'), [])
  })

  await t.test('ignores this.code', () => {
    assert.deepStrictEqual(scan('return this.code'), [])
  })

  await t.test('still flags a real domain', () => {
    assert.strictEqual(scan('visit company.com now').length, 1)
  })
})

test('Path scoped UUID skip', async (t) => {
  const line = '"id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"'

  await t.test('skips UUIDs in migrations/meta json', () => {
    assert.deepStrictEqual(scan(line, 'migrations/meta/0000_snapshot.json'), [])
  })

  await t.test('flags UUIDs elsewhere', () => {
    assert.strictEqual(scan(line, 'src/config.json').length, 1)
  })

  await t.test('still flags other detectors in migrations/meta', () => {
    const detectors = scan('mail admin@company.com', 'migrations/meta/x.json').map(
      (f) => f.detector,
    )
    assert.ok(detectors.includes('email'))
  })
})

test('Findings use repo-relative paths', () => {
  const c = new IdentifierChecker(process.cwd())
  c.run({ files: [`${process.cwd()}/CONTRIBUTING.md`] })
  for (const f of c.findings) assert.ok(!f.filePath.startsWith('/'), f.filePath)
  assert.deepStrictEqual(
    new IdentifierChecker(process.cwd()).getWorktreeFiles().filter((f) => f.startsWith('/')),
    [],
  )
})

test('Author ident validation', async (t) => {
  await t.test('noreply ident with timestamp passes', () => {
    const ident =
      'Thomas McFarlane <7033707+ThomasMcFarlane@users.noreply.github.com> 1790826528 +0700'
    assert.strictEqual(isNoreplyAuthorIdent(ident), true)
  })

  await t.test('example.com ident fails', () => {
    const ident = 'User Name <user@example.com> 1790826528 +0700'
    assert.strictEqual(isNoreplyAuthorIdent(ident), false)
  })

  await t.test('malformed ident fails', () => {
    const ident = 'User Name without email'
    assert.strictEqual(isNoreplyAuthorIdent(ident), false)
  })
})

test('parseArgs', () => {
  assert.deepStrictEqual(parseArgs(['--staged', '--files', 'a', 'b']), {
    staged: true,
    checkAuthor: false,
    worktree: false,
    files: ['a', 'b'],
  })
})

test('skips only unmodified vendored upstream files', async () => {
  const { isVendoredUpstream, gitBlobId, parseUpstreamManifest } = await import(
    './check-identifiers.mjs'
  )
  const upstream = 'contact hello@upstream.example.io\n'
  const manifest = parseUpstreamManifest(
    `${gitBlobId(upstream)}  libs/common/src/a.ts\n${gitBlobId(upstream)}  apps/web/src/index.html\n`,
  )
  assert.equal(isVendoredUpstream('web/libs/common/src/a.ts', upstream, manifest), true)
  // Changed content, unknown files and always-scanned paths are scanned.
  assert.equal(isVendoredUpstream('web/libs/common/src/a.ts', `${upstream}x`, manifest), false)
  assert.equal(isVendoredUpstream('web/libs/common/src/b.ts', upstream, manifest), false)
  assert.equal(isVendoredUpstream('web/apps/web/src/index.html', upstream, manifest), false)
  assert.equal(
    isVendoredUpstream('web/apps/web/src/app/cloudwarden/x.ts', upstream, manifest),
    false,
  )
  assert.equal(isVendoredUpstream('src/web/a.ts', upstream, manifest), false)
})

test('gitBlobId matches git hash-object', async () => {
  const { gitBlobId } = await import('./check-identifiers.mjs')
  assert.equal(gitBlobId('hello\n'), 'ce013625030ba8dba906f756967f9e9ca394464a')
})
