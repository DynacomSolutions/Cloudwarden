# Backups

A Cron Trigger (`17 3 * * *`, daily at 03:17 UTC, set in `cloudflare.config.ts`) runs the `scheduled` handler in
`src/backup.ts` and exports D1 to the `ATTACHMENTS` R2 bucket.

## Layout

```
backups/<YYYY-MM-DD>/run-<epoch seconds>/<table>.<NNNN>.jsonl   one JSON object per row, about 5 MB per part
backups/<YYYY-MM-DD>/run-<epoch seconds>/manifest.json          tables, ordered parts, row counts, SHA-256; written last
```

- Tables are read in pages of 500 rows ordered by `rowid` and flushed to R2 as part files of about 5 MB, so memory
  use does not grow with table size. BLOB columns are written as `{"$blob":"<base64>"}`.
- Every run has its own directory. The manifest is written last (an older manifest at the same path is deleted first),
  so a run directory without `manifest.json` is incomplete; do not restore from it. A failed run deletes the parts it
  wrote.
- A failure fails the scheduled invocation (the export is awaited), so it appears in the dashboard and in
  `backup.failed` log lines.
- Backups older than 14 days are deleted after each successful export.
- Skipped tables: `d1_migrations` and the short-lived admin tables (`admin_login_tokens`, `admin_rate_limits`,
  `admin_sessions`). Admins sign in again after a restore.
- Redacted columns: `devices.refresh_token` (written as an empty string, which the token endpoint treats as revoked),
  `devices.twofactor_remember` and `devices.push_token` (null). Every device must sign in again after a restore.
  TOTP secrets and other two-factor material are kept because a restore is useless without them.
- Nothing served to users may resolve a key under `backups/`; `src/blob-keys.ts` provides the guard.

## Consistency

The export is not a point-in-time snapshot. Pages and tables are read at slightly different moments, so rows written
during a run can appear in one table and not in a related one (for example a cipher whose folder link is missing).
The restore script defers foreign key checks, but orphaned references can still fail the final commit. For a
consistent copy use D1 Time Travel (`cf cli search "d1 time travel restore"`) and treat these exports as a portable
fallback, ideally taken at the quiet hour the schedule uses.

## Security

Backups contain password hashes, encrypted vault data and two-factor secrets. Keep the bucket private (no public
access, no custom domain), and restrict who holds R2 read tokens. Vault ciphertext stays encrypted, but a stolen
backup allows offline guessing of master passwords, so treat it like the database itself.

## Restore

1. Download one backup directory, for example with `cf r2 objects get` (discover flags with
   `cf cli search "download r2 object"`), so it holds `manifest.json` and every `.jsonl` part file (flat, file names only).
2. Create a fresh D1 database and apply migrations (`cf d1 migrations apply <database-id> --dir migrations`).
3. Generate SQL, verified against the manifest checksums:

   ```sh
   node scripts/restore-backup.mjs ./backup-dir --out-dir ./restore-sql
   ```

4. Apply the parts in order:

   ```sh
   for f in ./restore-sql/part-*.sql; do pnpm exec cf d1 query <database-id> --sql "$(cat "$f")"; done
   ```

   Without `--out-dir` the script prints one SQL stream to stdout. The first statement defers foreign key checks.
5. Point the Worker at the restored database and test a login.

The script refuses a backup whose files do not match the manifest, and rejects table or column names that are not
plain identifiers.
