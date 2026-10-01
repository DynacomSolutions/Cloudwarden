#!/usr/bin/env node

/**
 * Identifier detection tool to prevent committing sensitive data.
 * Modes: default (tracked files), --staged (staged changes), --check-author (verify git author)
 * Usage: node scripts/check-identifiers.mjs [--staged] [--check-author] [--worktree] [--files <path...>]
 */

import { execSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { relative, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

// Configuration
const COMMON_TLDS = new Set([
  'com',
  'net',
  'org',
  'io',
  'dev',
  'app',
  'co',
  'uk',
  'solutions',
  'studio',
  'cloud',
  'run',
  'ai',
  'xyz',
  'me',
  'sh',
  'work',
  'code',
  'online',
  'digital',
])

const DOMAIN_ALLOWLIST = new Set([
  'example.com',
  'example.org',
  'example.net',
  'localhost',
  'localhost:3000',
  'github.com',
  'githubusercontent.com',
  'bitwarden.com',
  'bitwarden.net',
  'vaultwarden',
  'cloudflare.com',
  'workers.dev',
  'npmjs.com',
  'nodejs.org',
  'conventionalcommits.org',
  'contributor-covenant.org',
  'gnu.org',
  'opensource.org',
  'keepachangelog.com',
  'semver.org',
  'biomejs.dev',
  'vitest.dev',
  'hono.dev',
  'orm.drizzle.team',
  'zod.dev',
  'securityscorecards.dev',
  'openssf.org',
  'shields.io',
  'schema.org',
  'w3.org',
  'mozilla.org',
  'ietf.org',
  'rfc-editor.org',
])

// Allowed special IPs and subnets
const ALLOWED_IPS = new Set([
  '127.0.0.1',
  '127.0.0.0',
  '0.0.0.0', // Localhost/any
  '192.0.2.0',
  '192.0.2.1',
  '198.51.100.0',
  '198.51.100.1',
  '203.0.113.0',
  '203.0.113.1', // RFC 5737
])

const ALLOWED_IPV6 = new Set(['::1', '::', '2001:db8::']) // Loopback, any, documentation

// Allowed GitHub action SHA format (40 hex chars)
const GITHUB_ACTION_SHA_PATTERN = /^[a-f0-9]{40}$/i

const EMAIL_ALLOW_DOMAINS = new Set([
  'example.com',
  'example.org',
  'example.net',
  'users.noreply.github.com',
])

// Nil UUID and a v4-shaped nil UUID (cf rejects the plain nil UUID as a D1 id)
const PLACEHOLDER_UUIDS = new Set([
  '00000000-0000-0000-0000-000000000000',
  '00000000-0000-4000-8000-000000000000',
])

// RFC 2606 / RFC 6761 reserved TLDs: never real, always safe in examples
const RESERVED_TLDS = new Set(['example', 'test', 'invalid', 'localhost'])

// drizzle-kit snapshot ids are random and non-identifying, so UUID detection is skipped there
const UUID_SKIP_PATHS = [/^migrations\/meta\/[^/]+\.json$/]

const SKIP_BASENAMES = new Set([
  'pnpm-lock.yaml',
  'package-lock.json',
  'yarn.lock',
  'bun.lockb',
  'LICENSE',
])
const SKIP_SEGMENTS = new Set(['.git', 'node_modules'])

export class IdentifierChecker {
  constructor(cwd = process.cwd()) {
    this.cwd = cwd
    this.findings = []
    this.denylisted = new Set()
    this.loadDenylist()
    this.loadAllowlist()
  }

  loadDenylist() {
    const denylistEnv = process.env.IDENTIFIER_DENYLIST || ''
    const deniedItems = denylistEnv
      .split(/[\n,]/)
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s && s.length > 0)

    if (existsSync(resolve(this.cwd, '.identifiers-deny.local'))) {
      const localDeny = readFileSync(resolve(this.cwd, '.identifiers-deny.local'), 'utf8')
        .split('\n')
        .map((s) => s.trim().toLowerCase())
        .filter((s) => s && !s.startsWith('#'))
      deniedItems.push(...localDeny)
    }

    this.denylisted = new Set(deniedItems)
  }

  loadAllowlist() {
    this.allowlistPatterns = []
    const allowlistFile = resolve(this.cwd, '.identifiers-allow')
    if (existsSync(allowlistFile)) {
      const lines = readFileSync(allowlistFile, 'utf8').split('\n')
      for (const line of lines) {
        const trimmed = line.trim()
        if (trimmed && !trimmed.startsWith('#')) {
          try {
            this.allowlistPatterns.push(new RegExp(trimmed))
          } catch {
            console.error(`Invalid regex in .identifiers-allow: ${trimmed}`)
          }
        }
      }
    }
  }

  isAllowlisted(line) {
    return this.allowlistPatterns.some((pattern) => pattern.test(line))
  }

  checkEmail(match) {
    const parts = match.split('@')
    if (parts.length !== 2) return false
    const domain = parts[1]

    if (EMAIL_ALLOW_DOMAINS.has(domain)) return false

    return true // Email detected
  }

  checkIPv4(match) {
    if (ALLOWED_IPS.has(match)) return false

    const octets = match.split('.').map(Number)
    if (octets.length !== 4 || octets.some(Number.isNaN)) return false
    if (octets.some((n) => n < 0 || n > 255)) return false

    // Localhost range
    if (octets[0] === 127) return false

    return true // IP detected
  }

  checkIPv6(match) {
    if (ALLOWED_IPV6.has(match)) return false
    if (match.startsWith('2001:db8:')) return false // Documentation prefix

    const colons = (match.match(/::/g) || []).length
    if (colons > 1) return false // Invalid
    if (colons === 0 && match.split(':').length < 3) return false // Need at least 3 groups

    return true // IPv6 detected
  }

  checkDomain(match) {
    const lower = match.toLowerCase()

    if (DOMAIN_ALLOWLIST.has(lower)) return false
    if (RESERVED_TLDS.has(lower.split('.').pop())) return false

    // Check allowlist with subdomains
    for (const allowed of DOMAIN_ALLOWLIST) {
      if (lower === allowed || lower.endsWith(`.${allowed}`)) {
        return false
      }
    }

    return true // Domain detected
  }

  checkHexToken(match) {
    // Exclude GitHub action SHAs (40 hex chars)
    if (GITHUB_ACTION_SHA_PATTERN.test(match)) return false
    // 32-char lowercase hex (Cloudflare IDs)
    if (/^[a-f0-9]{32}$/.test(match)) return true
    // UUIDs (but allow all-zeros)
    if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(match)) {
      if (PLACEHOLDER_UUIDS.has(match)) return false
      return true
    }
    return false
  }

  checkDenylist(match) {
    if (this.denylisted.size === 0) return false
    return this.denylisted.has(match.toLowerCase())
  }

  detectIdentifiers(line, lineNum, filePath) {
    if (line.includes('identifiers-allow-line')) return

    for (const m of line.matchAll(/\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g)) {
      if (this.checkEmail(m[1])) this.addFinding(filePath, lineNum, 'email', m[1])
    }

    const octet = '(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    for (const m of line.matchAll(new RegExp(`\\b(?:${octet}\\.){3}${octet}\\b`, 'g'))) {
      if (this.checkIPv4(m[0])) this.addFinding(filePath, lineNum, 'ipv4', m[0])
    }

    // IPv6 addresses (be conservative)
    for (const m of line.matchAll(/\b(?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}\b/gi)) {
      if (this.checkIPv6(m[0])) this.addFinding(filePath, lineNum, 'ipv6', m[0])
    }

    // Absolute home paths
    const homePath =
      /(?:\/home\/[a-zA-Z0-9_-]+\/|\/Users\/[a-zA-Z0-9_-]+\/|C:\\Users\\[a-zA-Z0-9_-]+\\)/g
    for (const m of line.matchAll(homePath)) {
      this.addFinding(filePath, lineNum, 'home-path', m[0])
    }

    // Domains (FQDN with a common TLD), skipping code member access and calls
    const tlds = [...COMMON_TLDS].join('|')
    const label = '[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    const domainPattern = new RegExp(`\\b(${label}(?:\\.${label})*\\.(?:${tlds}))\\b`, 'gi')
    for (const m of line.matchAll(domainPattern)) {
      if (this.isCodeReference(line, m.index, m[1])) continue
      if (this.checkDomain(m[1])) this.addFinding(filePath, lineNum, 'domain', m[1])
    }

    // 32-char hex tokens (bounded by non-hex)
    for (const m of line.matchAll(/(?:^|[^a-f0-9])([a-f0-9]{32})(?:[^a-f0-9]|$)/gi)) {
      if (this.checkHexToken(m[1])) this.addFinding(filePath, lineNum, 'token-32hex', m[1])
    }

    // UUIDs
    if (!UUID_SKIP_PATHS.some((re) => re.test(filePath))) {
      const uuid = /\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b/gi
      for (const m of line.matchAll(uuid)) {
        if (this.checkHexToken(m[1])) this.addFinding(filePath, lineNum, 'uuid', m[1])
      }
    }

    // Denylist check
    for (const denied of this.denylisted) {
      if (line.toLowerCase().includes(denied)) {
        this.addFinding(filePath, lineNum, 'denylist', '(redacted)')
      }
    }
  }

  /**
   * True when a domain-looking token is really JS member access or a call,
   * e.g. `checker.run(`, `obj?.run`, `this.code`, `a.b.run[0]`.
   */
  isCodeReference(line, index, token) {
    if (index > 0 && /[a-zA-Z0-9_.]/.test(line[index - 1])) return true
    const after = line.slice(index + token.length)
    if (/^(?:\(|\[|\?\.)/.test(after)) return true
    return /^(?:this|self|globalThis|window|process)\./.test(token)
  }

  addFinding(filePath, lineNum, detector, match) {
    if (this.isAllowlisted(match)) return
    this.findings.push({ filePath, lineNum, detector, match })
  }

  isBinaryFile(filePath) {
    const binaryExtensions = new Set([
      'png',
      'jpg',
      'jpeg',
      'gif',
      'bmp',
      'ico',
      'woff',
      'woff2',
      'ttf',
      'eot',
      'zip',
      'tar',
      'gz',
      'rar',
      '7z',
      'bin',
      'o',
      'so',
      'dylib',
      'exe',
      'dll',
    ])
    const ext = filePath.split('.').pop().toLowerCase()
    return binaryExtensions.has(ext)
  }

  shouldSkipFile(filePath) {
    const segments = filePath.split(/[\\/]/)
    const base = segments[segments.length - 1]
    if (SKIP_BASENAMES.has(base)) return true
    if (segments.some((seg) => SKIP_SEGMENTS.has(seg))) return true
    if (/\.test\.(?:mjs|ts)$/.test(base)) return true
    return this.isBinaryFile(filePath)
  }

  /** Scan text for a repo-relative path (also used for staged content). */
  scanText(content, relPath) {
    const lines = content.split('\n')
    lines.forEach((line, index) => {
      this.detectIdentifiers(line, index + 1, relPath)
    })
  }

  scanFile(relPath) {
    if (this.shouldSkipFile(relPath)) return
    try {
      this.scanText(readFileSync(resolve(this.cwd, relPath), 'utf8'), relPath)
    } catch {
      // Skip unreadable files
    }
  }

  git(command) {
    return execSync(command, { cwd: this.cwd, encoding: 'utf8' })
  }

  getTrackedFiles() {
    try {
      return this.git('git ls-files')
        .split('\n')
        .filter((f) => f.length > 0)
    } catch {
      console.error('Failed to get tracked files')
      return []
    }
  }

  getStagedFiles() {
    try {
      return this.git('git diff --cached --name-only --diff-filter=ACMR')
        .split('\n')
        .filter((f) => f.length > 0)
    } catch {
      console.error('Failed to get staged files')
      return []
    }
  }

  getStagedContent(filePath) {
    try {
      return this.git(`git show :${filePath}`)
    } catch {
      return ''
    }
  }

  /** Repo-relative paths of every non-hidden file on disk. */
  getWorktreeFiles() {
    const files = []
    const walk = (dir) => {
      try {
        for (const entry of readdirSync(dir)) {
          if (entry === 'node_modules' || entry === '.git' || entry.startsWith('.')) continue
          const path = resolve(dir, entry)
          const stat = statSync(path, { throwIfNoEntry: false })
          if (!stat) continue
          if (stat.isDirectory()) walk(path)
          else files.push(relative(this.cwd, path).split(sep).join('/'))
        }
      } catch {
        // Ignore read errors
      }
    }
    walk(this.cwd)
    return files
  }

  checkAuthor() {
    try {
      const ident = this.git('git var GIT_AUTHOR_IDENT').trim()
      if (!isNoreplyAuthorIdent(ident)) {
        this.addFinding('git config', 0, 'author-email', '(redacted)')
        return false
      }
      return true
    } catch {
      console.error('Failed to check author email')
      return false
    }
  }

  run(options = {}) {
    let files = []

    if (options.staged) {
      for (const file of this.getStagedFiles()) {
        if (!this.shouldSkipFile(file)) this.scanText(this.getStagedContent(file), file)
      }
    } else if (options.worktree) {
      files = this.getWorktreeFiles()
    } else if (options.files && options.files.length > 0) {
      files = options.files.map((f) =>
        relative(this.cwd, resolve(this.cwd, f)).split(sep).join('/'),
      )
    } else {
      files = this.getTrackedFiles()
    }

    for (const file of files) {
      this.scanFile(file)
    }

    if (options.checkAuthor) {
      this.checkAuthor()
    }

    return this.findings
  }

  report() {
    if (this.findings.length === 0) {
      console.log('No identifiers detected')
      return 0
    }

    for (const finding of this.findings) {
      console.log(`${finding.filePath}:${finding.lineNum}: [${finding.detector}] ${finding.match}`)
    }

    console.error(`\nFound ${this.findings.length} potential identifier(s)`)
    return 1
  }
}

/**
 * Extract the email from a git author ident string and check if it is a noreply email.
 * Git author ident format: `Name <email> timestamp timezone`
 * @param {string} ident - The git author ident string from `git var GIT_AUTHOR_IDENT`
 * @returns {boolean} - True if the email ends with @users.noreply.github.com
 */
export function isNoreplyAuthorIdent(ident) {
  const emailMatch = ident.match(/<([^>]+)>/)
  if (!emailMatch) return false
  const email = emailMatch[1]
  return email.endsWith('@users.noreply.github.com')
}

export function parseArgs(args) {
  const filesIndex = args.indexOf('--files')
  return {
    staged: args.includes('--staged'),
    checkAuthor: args.includes('--check-author'),
    worktree: args.includes('--worktree'),
    files: filesIndex === -1 ? [] : args.slice(filesIndex + 1),
  }
}

// Main (only when executed directly, not when imported by tests)
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const checker = new IdentifierChecker()
  checker.run(parseArgs(process.argv.slice(2)))
  process.exit(checker.report())
}
