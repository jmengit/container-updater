# Container Updater

Private, authenticated, approval-driven updater for **one container host per instance**.

> **vNext implementation handoff:** See [`docs/vnext-design-and-implementation.md`](docs/vnext-design-and-implementation.md) for the approved label-driven, headless-first redesign.

## vNext policy configuration

Per-container policy is stored in Docker/dockerMan labels: `io.jmengit.upgrade.version` (`patch|minor|major`), `io.jmengit.upgrade.policy` (`manual|auto`), and `io.jmengit.upgrade.research` (`none|notes|issues`). Optional labels are `io.jmengit.upgrade.source` and `io.jmengit.upgrade.hold-days` (`0..365`). Global holds use `HOLD_DAYS_PATCH`, `HOLD_DAYS_MINOR`, and `HOLD_DAYS_MAJOR`; manual and automatic policies use the same collision-safe hold calculation.


Each deployment selects exactly one target:

- `TARGET_TYPE=unraid`: local Docker socket inventory plus native Unraid dockerMan templates and recreation.
- `TARGET_TYPE=portainer`: one Portainer URL and one endpoint ID. Inventory is supported; remote mutation remains blocked until stack backup/revision/rollback is implemented.

A WUD instance associated with that same machine is the sole update-discovery source. Container Updater reads WUD's documented `GET /api/containers` REST endpoint and combines it with live target state. It does not run registry discovery itself and no longer imports legacy Hermes reports.

## How current vs available is determined

- **Current runtime state:** Docker socket for Unraid, or the configured Portainer endpoint API.
- **Current/available image metadata:** WUD `/api/containers`, including image tag/digest, `updateAvailable`, `updateKind`, and `result`.
- **Execution safety:** live image ID, state, and native template revision are revalidated immediately before an approved mutation.

## Safety boundary

- `APP_MODE=report_only` is the default.
- One instance cannot configure Unraid and Portainer simultaneously.
- WUD is read-only from Container Updater; it supplies discovery, not execution.
- WUD may use `wud-socket-proxy` to limit WUD's Docker API exposure instead of giving WUD the host-root-equivalent Docker socket directly. Container Updater itself does not use that proxy; local Unraid execution still requires the real socket for revision verification and approved updates.
- Unraid upgrades merge with the installed `my-container-updater.xml` and preserve all user-entered Config values—especially Admin Username/Password, WUD credentials, LLM keys, ports, and paths. Never replace the installed template wholesale. Use `scripts/merge_unraid_template.py shipped.xml installed.xml merged.xml` during deployment.
- Stopped containers are never updated or started.
- Unlabeled, digest-only, major, medium/high-risk, unresolved, or flavor-changing updates remain manual review.
- The updater excludes itself.
- Portainer updates are currently disabled; only inventory and WUD candidate discovery are supported for that target.

## Required configuration

```text
TARGET_TYPE=unraid|portainer
WUD_URL=http://wud:3000
WUD_USERNAME=optional-basic-auth-user
WUD_PASSWORD_FILE=/run/secrets/wud_password
```

For Unraid:

```text
DOCKER_SOCKET=/var/run/docker.sock
DOCKER_TEMPLATE_DIR=/boot/config/plugins/dockerMan/templates-user
```

For Portainer:

```text
PORTAINER_URL=https://portainer.example.com
PORTAINER_TOKEN_FILE=/run/secrets/portainer_token
PORTAINER_ENDPOINT_ID=3
```

## Local development

```bash
uv sync --extra test
export APP_MODE=report_only
export TARGET_TYPE=unraid
export WUD_URL=http://localhost:3000
export DATABASE_URL=sqlite:////tmp/container-updater.db
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD='replace-with-12-plus-chars'
export SESSION_SECRET='replace-with-32-plus-random-characters'
export TRUSTED_HOSTS='localhost,127.0.0.1'
uv run uvicorn unraid_updater.main:app --host 127.0.0.1 --port 8080
```

Open <http://127.0.0.1:8080>.
