# Contributing to Cloudwarden

Thank you for your interest in contributing! This guide will help you get started.

## Setup

1. Clone the repository and install dependencies:
   ```bash
   pnpm install
   ```

2. Install git hooks:
   ```bash
   pnpm exec lefthook install
   ```

3. Copy `.env.example` to `.env.local` if needed for local development.

## Development

- **Lint:** `pnpm lint`
- **Typecheck:** `pnpm typecheck`
- **Test:** `pnpm test`
- **Script tests:** `pnpm test:scripts`
- **Build:** `pnpm build`

Run these before pushing to ensure your changes pass CI.

## Commits and Pull Requests

### Conventional Commits

All commits must follow the [Conventional Commits](https://www.conventionalcommits.org) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Valid types:

- **feat:** A new feature
- **fix:** A bug fix
- **refactor:** Code refactoring without feature changes
- **test:** Adding or updating tests
- **docs:** Documentation changes
- **chore:** Build process, dependencies, tooling
- **ci:** CI/CD configuration

Examples:

```
feat(api): add support for custom cipher profiles
fix(db): correct query timeout handling
test: add integration tests for sync endpoint
chore(deps): update drizzle-orm to v0.30.0
```

### Atomic Commits

Each commit should represent one logical change:

- Split unrelated changes into separate commits
- Avoid mixing refactoring with feature additions
- Each commit should be independently reviewable and testable

### Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with atomic commits following Conventional Commits
3. Ensure all tests pass: `pnpm test` and `pnpm test:scripts`
4. Ensure linting passes: `pnpm lint`
5. Ensure typechecking passes: `pnpm typecheck`
6. Push your branch and open a PR against `main`
7. Describe your changes in the PR template
8. Address any CI failures or review feedback

## Code Quality

### Identifiers and Secrets

Never commit identifying information:

- Real domains (use `example.com`, `example.org`, `example.net`)
- Real email addresses or account IDs
- IP addresses (except localhost/documentation ranges)
- Credentials or API keys
- Personal or company names (except as required by GitHub)
- Absolute local paths

If you need to block specific strings from being committed locally (like your organisation name), create `.identifiers-deny.local` in the repo root:

```
# .identifiers-deny.local (git-ignored)
internal.example
internalhostname
your-name
```

This prevents accidental commits without blocking others.

### Testing

- Write tests for new features
- Update existing tests when changing behavior
- Keep test files colocated with source files (`*.test.ts`)

### Security

- Never commit secrets, even for test environments
- Use `.env.example` as a template; never commit `.env.local` or `.env`
- Be cautious with changes to authentication, encryption, or API security
- Highlight security impact in PRs

## Bitwarden Compatibility

Since Cloudwarden is a Bitwarden-compatible server:

- Maintain API compatibility with official Bitwarden clients
- Document any deviations from the official server
- Test changes against supported Bitwarden clients
- Note compatibility concerns in PRs

## Documentation

- Keep README up-to-date with setup and usage instructions
- Document breaking changes in CHANGELOG entries
- Add JSDoc comments to exported functions and types
- Update relevant docs/ files for significant changes

## Questions?

- Open a discussion in the repository
- Check existing issues and PRs for similar questions
- Refer to the Hono, Drizzle, and Bitwarden documentation for context

## Code of Conduct

This project adheres to the Contributor Covenant 2.1 Code of Conduct. By participating, you are expected to uphold this code. Report unacceptable behavior to the maintainers.
