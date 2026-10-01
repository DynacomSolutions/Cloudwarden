import { cloudflare } from '@cloudflare/vite-plugin'
import { defineConfig } from 'vite'

export default defineConfig({
  // Static web vault (gitignored, created by `pnpm web-vault:fetch`). Absent in CI: that is fine.
  publicDir: 'web-vault',
  plugins: [cloudflare()],
})
