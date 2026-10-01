# Backups

A Cron Trigger (`17 3 * * *`, daily at 03:17 UTC, set in `cloudflare.config.ts`) runs the `scheduled` handler in
`src/backup.ts` and exports D1 to the `ATTACHMENTS` R2 bucket.

## Layout

```
backups/<YYYY-MM-DD>/<table>.jsonl   one JSON object per row
backups/<YYYY-MM-DD>/manifest.json   table list, row counts, byte sizes, SHA-256, written last
```

- Tables are read in pages of 500 rows ordered by `rowid`. BLOB columns are written as `{"$blob":"<base64>"}`.
- The manifest is written last. A date prefix without `manifest.json` is an incomplete run; do not restore from it.
- Backups older than 14 days are deleted after each successful export.
- `d1_migrations` and the short-lived admin tables (`admin_login_tokens`, `admin_rate_limits`, `admin_sessions`)
  are skipped. Admins sign in again after a restore.
- Each table is built in memory before upload. This suits personal and small-team vaults; a table beyond roughly
  50 MB needs multipart upload (not implemented).

## Security

Backups contain password hashes, encrypted vault data and device refresh tokens. Keep the bucket private (no public
access, no custom domain), and restrict who holds R2 read tokens. Vault ciphertext stays encrypted, but a stolen
backup allows offline guessing of master passwords, so treat it like the database itself.

## Restore

1. Download one backup directory, for example with `cf r2 objects get` (discover flags with
   `cf cli search "download r2 object"`), so it holds `manifest.json` and every `.jsonl` file.
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
