# Operations

## Data

Persistent state is the SQLite database at `/data/updater.db` plus WAL/SHM files while running. Secrets should be supplied using `*_FILE` variables or protected Unraid template values.

## Backup

1. Stop the application container.
2. Copy the entire appdata directory, including `updater.db`, `updater.db-wal`, and `updater.db-shm` if present.
3. Preserve the Unraid dockerMan template XML separately.
4. Restart the application and verify `/api/v1/health`.

A filesystem copy while SQLite is actively writing is not a guaranteed consistent backup. Prefer a stopped copy or SQLite's online backup API.

## Restore

1. Stop the container.
2. Move the current appdata directory aside; do not delete it.
3. Restore the complete backup with ownership writable by UID/GID 10001.
4. Start the same tagged image version used by the backup.
5. Verify health, login, latest scan, counts, and candidate details.

## Upgrade

- Use immutable semantic-version tags, not `latest`, in production.
- Back up appdata and the dockerMan template first.
- Pull the new image and recreate through native Unraid dockerMan.
- Verify health and UI. Roll back by restoring the prior image tag and data backup.

## Failure modes

- **Startup refuses execution mode:** expected; v0.1 only accepts `APP_MODE=report_only`.
- **Startup rejects password/session secret:** supply at least 12/32 characters respectively.
- **Invalid host:** add the exact LAN hostname/IP to `TRUSTED_HOSTS`; do not use `*`.
- **No candidates:** check that `LEGACY_STATE_DIR` contains readable `runs/*.json` files.
- **Import failure:** the previous successful data remains available; inspect logs and the newest scan error.
- **Approval conflict:** refresh the candidate. Its evidence revision changed, so stale intent was rejected.

## Security checks

- Container is not privileged.
- No Docker socket is mounted.
- Legacy state is read-only.
- Only `/data` is writable.
- LAN access is protected by authentication; TLS should terminate at a trusted reverse proxy when used beyond a private LAN.
- There is no execution API in v0.1.
