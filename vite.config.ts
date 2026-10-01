import { cloudflare } from '@cloudflare/vite-plugin'
import { defineConfig } from 'vite'

// Dev server Host header allowlist, set at run time so no hostname is committed (docs/local-dev.md).
// `*` accepts any host (the dev container sits behind an ingress); a list names exact hosts.
const hosts = process.env.DEV_ALLOWED_HOSTS?.trim()
const allowedHosts =
  hosts === '*' ? true : hosts ? hosts.split(',').map((h) => h.trim()) : undefined

export default defineConfig({
  server: { allowedHosts },
  // Static web vault (gitignored, created by `pnpm web-vault:fetch`). Absent in CI: that is fine.
  publicDir: 'web-vault',
  plugins: [cloudflare()],
})
