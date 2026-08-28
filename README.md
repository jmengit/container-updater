# Unraid Container Updater

Private, authenticated, policy-driven dashboard for Saturn's Unraid container update workflow.

## Current release boundary

**v0.1 is report-only.** It imports the existing Hermes updater report, explains candidate status, and records revision-bound approval/defer intent. It has no Docker socket, privileged mode, host mutation route, execution endpoint, or code capable of updating/restarting a container.

## Safety defaults

- `APP_MODE=report_only` is mandatory; other values fail startup.
- Only running, explicitly classified, low-risk patch/minor candidates may become approval-ready after soak.
- Stopped, medium/high/critical, major, pinned, notify-only, breaking-review, unresolved, or flavor-changing cases remain manual.
- Approval is bound to an exact candidate revision and expires after 24 hours.
- Web mutations require authentication and CSRF.
- SQLite audit events are hash chained.
- The image runs as UID/GID 10001 with no capabilities and supports a read-only root filesystem.

## Local development

```bash
uv sync
export APP_MODE=report_only
export DATABASE_URL=sqlite:////tmp/unraid-updater.db
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD='replace-with-12-plus-chars'
export SESSION_SECRET='replace-with-32-plus-random-characters'
export TRUSTED_HOSTS='localhost,127.0.0.1'
uv run uvicorn unraid_updater.main:app --host 127.0.0.1 --port 8080
```

Open <http://127.0.0.1:8080>.

To import the existing report history, mount its parent read-only and set:

```bash
export LEGACY_STATE_DIR=/legacy-state
```

The app imports the newest `runs/*.json` file at startup, on the configured `SCAN_CRON`, and when an authenticated user selects **Refresh report**.

## Verification

```bash
uv run ruff check .
uv run pytest
uv build
```

## Container

```bash
mkdir -p secrets
openssl rand -base64 24 > secrets/admin_password
openssl rand -base64 48 > secrets/session_secret
docker compose up --build
```

The included compose example uses a read-only root filesystem, drops all Linux capabilities, enables `no-new-privileges`, and mounts only `/data` writable.

## Unraid

Use `unraid/unraid-container-updater.xml`. The optional existing report-state path must be mounted **read-only**. Never add `/var/run/docker.sock` or privileged mode.

See [docs/operations.md](docs/operations.md) for backup, restore, and troubleshooting.

## Roadmap and approval boundary

The constrained host runner and live canary are tracked separately and require explicit Saturn approval plus independent architecture/security review. They are intentionally absent from this repository revision.

## License

Private/internal project. All rights reserved.
