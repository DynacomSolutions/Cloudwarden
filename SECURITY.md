# Security Policy

## Reporting Security Vulnerabilities

If you have discovered a security vulnerability in Cloudwarden, please report it responsibly.

Once public, use GitHub's private vulnerability reporting feature via the Security tab to report privately. Until then, report privately to the maintainers through the organisation.

Do not open a public issue or discussion for security vulnerabilities.

## Scope

Security vulnerabilities that affect the Cloudwarden server are in scope:

- Authentication and authorization mechanisms
- Encryption and key handling
- API security (especially regarding vault data access)
- Dependency vulnerabilities
- Server infrastructure and deployment

Bitwarden client vulnerabilities are out of scope. However, the server can serve a malicious web vault if compromised, so web vault integrity is in scope.

## Important Note on Vault Data

The Cloudwarden server is designed to never see plaintext vault data. All vault data is end-to-end encrypted by Bitwarden clients before transmission. This means a compromised server cannot directly access user vault contents, but it can serve malicious web vault code, which is why vault integrity is in scope.

## Supported Versions

This project is pre-1.0. Only the latest main branch is supported for security updates. Security patches will be released as new versions when available.

## Response Timeline

We aim to:

1. Acknowledge receipt of security reports within 2 business days
2. Provide an initial assessment within 5 business days
3. Release a patch or mitigation guidance within 30 days
4. Coordinate disclosure timing with affected parties

## Dependencies

Cloudwarden uses several key dependencies. We monitor these for vulnerabilities:

- Hono (web framework)
- Drizzle ORM (database)
- Zod (validation)
- Node.js runtime

Dependency updates are automated via Dependabot and tested in CI.
