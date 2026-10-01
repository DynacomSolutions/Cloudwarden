// Applies the D1 migrations to the local (simulated) database through the `cf` CLI.
// Shared by the end-to-end runner and the dev container entrypoint.
import { spawn } from 'node:child_process'
import { join } from 'node:path'

const NIL_DB = '00000000-0000-4000-8000-000000000000'

// `cf d1 migrations apply --local` prints the result as JSON but does not exit on its own, so
// stop it once the output parses and every migration reports success.
export function migrateLocal(root, env, state) {
  return new Promise((ok, fail) => {
    const child = spawn(
      join(root, 'node_modules', '.bin', 'cf'),
      [
        'd1',
        'migrations',
        'apply',
        NIL_DB,
        '--local',
        '--persist-to',
        state,
        '--dir',
        'migrations',
      ],
      { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] },
    )
    let out = ''
    const timer = setTimeout(() => {
      child.kill('SIGKILL')
      fail(new Error(`migrations timed out\n${out}`))
    }, 90000)
    child.stdout.on('data', (d) => {
      out += d
      try {
        const rows = JSON.parse(out)
        if (Array.isArray(rows)) {
          clearTimeout(timer)
          child.kill('SIGKILL')
          rows.every((r) => r.status === '✅') ? ok() : fail(new Error(out))
        }
      } catch {}
    })
    child.on('exit', (code) => {
      if (code && code !== 137) {
        clearTimeout(timer)
        fail(new Error(`cf exited ${code}\n${out}`))
      }
    })
  })
}
