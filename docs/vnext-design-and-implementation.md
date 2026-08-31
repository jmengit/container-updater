# Container Updater vNext: Label-Driven, Headless Update Controller

**Status:** Approved design handoff; implementation required  
**Audience:** A coding agent taking ownership of design migration, implementation, tests, release, and deployment  
**Repository:** `jmengit/container-updater`  
**Baseline:** `v0.7.1` / commit `9753a55`  
**Primary target:** One local Unraid host using native dockerMan semantics  
**Secondary target:** One Portainer endpoint, inventory/reporting only; mutation remains intentionally unimplemented

## 1. Purpose

Replace v0.7.1's browser/SQLite-owned policy and risk-gate model with a portable, headless-first controller whose per-container policy is stored in Docker/dockerMan labels and whose global behavior is stored in the updater container's environment variables.

The browser becomes an optional authenticated interface over the same service layer used by the scheduler and CLI. It is not required for scanning, hold evaluation, research, automatic execution, logging, auditing, or manual CLI execution.

This is a substantial model migration, not an incremental rename. Remove the current `risk` model, browser-owned risk gates, and SQLite policy overrides after a safe migration period.

## 2. Non-negotiable decisions

1. One updater instance manages exactly one target.
2. WUD is the sole update-discovery source and never authorizes or executes mutations.
3. Installed Unraid dockerMan XML is authoritative desired state for per-container labels and recreation.
4. Per-container policy is expressed by three required labels and two optional labels.
5. Global patch/minor/major hold days are environment variables; hold duration is independent of manual versus automatic execution.
6. Holds represent age after release/publication, not time since a browser or this updater first noticed an update.
7. A per-container hold override replaces all three global holds for that container.
8. Version classification is always installed version to final target version. An intervening patch must not bypass a major/minor hold.
9. Automatic major updates are allowed when explicitly configured. They are not the default and are not categorically forbidden.
10. Research may be `none`; provider failures then do not block solely because research is unavailable.
11. Poor metadata must degrade conservatively but must not leave containers permanently impossible to update.
12. SQLite may remain as an internal transaction engine, but it must not be a hidden source of user policy.
13. Every material action and decision must be inspectable in durable JSON/JSONL files without the browser or direct SQL queries.
14. All approvals, research, holds, and executions bind to an exact candidate revision/digest and are invalidated when it changes.
15. Stopped containers are never automatically started or updated.
16. Portainer mutation remains blocked until native stack/container backup, revision, verification, and rollback semantics are separately designed and implemented.

## 3. Configuration contract

### 3.1 Required per-container labels

```text
io.jmengit.upgrade.version=patch|minor|major
io.jmengit.upgrade.policy=manual|auto
io.jmengit.upgrade.research=none|notes|issues
```

#### `io.jmengit.upgrade.version`

Maximum installed-to-target transition allowed:

| Value | Patch target | Minor target | Major target |
|---|---:|---:|---:|
| `patch` | allowed | blocked | blocked |
| `minor` | allowed | allowed | blocked |
| `major` | allowed | allowed | allowed |

Unknown/unclassifiable transitions are conservatively classified as `major`. This lets an explicitly permissive `version=major` container eventually update while preventing a patch/minor policy from silently crossing an unknown boundary.

#### `io.jmengit.upgrade.policy`

- `manual`: discover, classify, age, research, log, and expose the candidate; do not permit execution until the hold passes and all gates pass. Execution requires an authenticated browser action or CLI action.
- `auto`: after the hold and all gates pass, execute without a human click. `version=major,policy=auto` is valid and must work.

#### `io.jmengit.upgrade.research`

- `none`: skip GitHub/LLM research; deterministic gates still apply.
- `notes`: inspect bounded release/document evidence.
- `issues`: perform `notes` research plus targeted issue/regression research.

### 3.2 Optional per-container labels

```text
io.jmengit.upgrade.source=https://github.com/owner/repository
io.jmengit.upgrade.hold-days=0..365
```

- `source` identifies the source repository for release-date and research resolution. Initial supported research provider is GitHub. Use a generic URL label so GitLab/Codeberg/vendor adapters can be added later.
- `hold-days` is an integer from 0 through 365. If present and valid, it replaces patch/minor/major global hold values for that container. Invalid values block execution with `invalid_hold_override`; never coerce them to zero.

### 3.3 Global updater environment variables

Required additions:

```text
HOLD_DAYS_PATCH=2
HOLD_DAYS_MINOR=7
HOLD_DAYS_MAJOR=14
EVENTS_JSONL=/data/logs/events.jsonl
AUDIT_JSONL=/data/audit/audit.jsonl
LOG_RETENTION_DAYS=90
FIRST_SEEN_FALLBACK_ENABLED=true
```

Recommended validation:

- Hold values: integers `0..365`.
- Retention: integer `1..3650`.
- Configuration validation occurs at startup and is visible in health/status output.
- Preserve existing target, WUD, research provider, authentication, and scheduler settings.
- Browser pages may display effective environment settings but must not store alternate values in SQLite.

### 3.4 Label-source precedence

For Unraid:

1. Installed dockerMan XML labels (`<ExtraParams>`) are authoritative desired policy.
2. Runtime Docker labels are observed state and should match after recreation.
3. WUD labels are discovery evidence only.
4. SQLite never overrides these values.

A mismatch is visible as `desired_runtime_label_drift`. Policy evaluation uses installed dockerMan labels, but automatic execution must be blocked until drift is repaired or the policy edit/redeploy operation completes successfully. This prevents an operator from believing the live container carries labels it does not actually have.

For Portainer report mode, use the deployment/stack specification where reliably available, otherwise runtime labels; report provenance and block mutation.

## 4. Release identity, version classification, and collision handling

### 4.1 Candidate identity

A candidate revision must include at least:

- Target identity and container identity
- Current repository, tag, image ID, and digest
- Target repository, tag, manifest digest/image digest
- Installed and target normalized versions, when available
- Installed-to-target change class
- Effective labels and their source/provenance
- Matched source repository and source release/tag, if any
- Release-line timestamp and exact-target timestamp with provenance/confidence
- Research policy and evidence revision
- dockerMan template path/hash and live container revision

Hash canonical JSON with sorted keys. Any mutation-relevant change creates a new revision, supersedes stale approval/research, and reevaluates holds.

### 4.2 Installed-to-target classification

Never classify from the immediately previous upstream release.

Example:

```text
installed: 1.9.0
upstream major: 2.0.0
newest upstream: 2.0.1
classification: 1.9.0 -> 2.0.1 = major
```

Therefore the maximum version gate and release-line hold remain `major`.

Semver parsing order:

1. Exact semantic version.
2. Normalize a leading `v`.
3. OCI `org.opencontainers.image.version`.
4. Exact source tag/release mapping.
5. Conservative `major` classification.

Preserve flavor-family protection from current code. Never jump repositories, architectures, channels, or flavors merely because a numerically newer tag exists.

### 4.3 One active target per container

Maintain one newest valid active target per container. A newer digest/tag supersedes the prior target and invalidates stale research and approval. Historical candidates remain inspectable.

Do not separately notify `2.0.0` and then `2.0.1` as actionable updates when `2.0.1` is the current newest valid target. Report the installed-to-final-target transition.

### 4.4 Two-part hold eligibility

Use both release-line and exact-target stabilization dates.

Without a container override:

```text
line_eligible_at = line_release_published_at + HOLD_DAYS_<installed_to_target_class>
exact_eligible_at = exact_target_published_at + HOLD_DAYS_<exact_target_delta_class>
eligible_at = max(line_eligible_at, exact_eligible_at)
```

Example:

```text
installed 1.9.0
2.0.0 published 17 days ago
2.0.1 published 3 days ago
major hold 14 days
patch hold 2 days
eligible_at = max(2.0.0 + 14d, 2.0.1 + 2d)
```

This prevents a patch from bypassing a major hold without restarting a full major hold for every later patch.

With `io.jmengit.upgrade.hold-days=5`:

```text
eligible_at = max(line_release_published_at + 5d, exact_target_published_at + 5d)
```

For patch-only transitions, line and exact target may be the same release.

### 4.5 Timestamp resolution

Use the later reliable timestamp associated with software and the actual target image:

1. Exact matched source release `published_at`.
2. Registry manifest/tag publication timestamp, when reliable.
3. OCI `org.opencontainers.image.created`.
4. First reliable observation of the exact immutable target digest as a conservative fallback.

For exact-target eligibility, use the later of matched source release time and image publication/creation time when both exist. This prevents an old source release with a freshly rebuilt image from immediately bypassing stabilization.

For release-line time, locate the first stable release in the crossed line (`2.0.0` for major `2.x`, `1.4.0` for minor `1.4.x`). If unavailable, use the oldest reliably identified target within that line; record reduced confidence.

Every timestamp record includes:

```json
{
  "value": "2026-08-10T15:00:00Z",
  "source": "github_release|registry|oci_created|first_seen_fallback",
  "source_url": "https://github.com/owner/repo/releases/tag/v2.0.1",
  "confidence": "exact|normalized|inferred|fallback"
}
```

Do not claim first-seen fallback is the release date. Display it as a conservative quarantine started at first reliable observation.

### 4.6 Poor metadata protection without permanent deadlock

- Exact target digest is mandatory for auto execution. If WUD does not provide it, resolve it from the registry/Docker pull result before execution and bind the execution to it.
- Mutable tags (`latest`, `stable`) are bound to digest. A changed digest resets fallback age, research, and revision.
- If no authoritative timestamp exists and fallback is enabled, quarantine the exact digest from first reliable observation for the required hold.
- If version class is unknown, treat it as major.
- If research is `notes`/`issues` but source release cannot be resolved, auto fails closed and manual is blocked until an operator explicitly acknowledges `source_release_unresolved` for that exact revision. This exception must be logged and cannot become a reusable blanket bypass.
- If research is `none`, unresolved source metadata does not block by itself, but digest, target, backup, and live preflight still must be deterministic.
- Never silently substitute candidate first-seen time while labeling it release age.

## 5. Source resolution and research

### 5.1 Source precedence

1. Explicit `io.jmengit.upgrade.source`.
2. OCI `org.opencontainers.image.source`.
3. Verified registry metadata.
4. Unresolved.

Do not guess from similar names. Canonicalize GitHub URLs to `https://github.com/owner/repo`, reject credentials/fragments/query strings, and allow only configured source hosts.

### 5.2 GitHub release mapping

Support exact and conservative normalization:

- `1.2.3` ↔ `v1.2.3`
- Exact OCI version ↔ source release/tag
- Exact target tag ↔ source release/tag

Record match method and confidence. Do not broadly fuzzy-match monorepo releases. Add provider-specific mapping only after real fixtures justify it; a future optional release-prefix label may be considered but is out of initial scope.

### 5.3 Research modes

#### `none`

Write a completed research disposition with `skipped_by_policy`. Do not call GitHub or the LLM.

#### `notes`

Bounded evidence:

- Matching release and release notes
- README
- CHANGELOG/CHANGES/HISTORY
- UPGRADING/migration documentation
- Security/deprecation notices
- Relevant merged PRs or commits between installed and target versions when identity is reliable

#### `issues`

Everything from `notes`, plus bounded targeted queries for:

- Target version/regressions
- Migration/install failures
- Data loss/database problems
- Authentication/network/compatibility regressions
- Maintainer acknowledgments, fixes, and workarounds
- Important recently closed issues when they inform current status

### 5.4 LLM trust boundary

The LLM is advisory only. It cannot approve, execute, access Docker, inspect secrets, or establish image identity. Inputs must exclude environment values, credentials, raw templates, privileged mounts, and mutation tools. Citations must exactly match collected evidence URLs. Provider failure, malformed output, or invalid citations fails required research closed.

Research outputs must include deterministic machine fields, not only prose:

```json
{
  "revision": "...",
  "mode": "issues",
  "status": "passed|concerns|failed|skipped_by_policy",
  "blocking_concerns": [],
  "non_blocking_concerns": [],
  "citations": [],
  "evidence_hash": "...",
  "model": "...",
  "created_at": "..."
}
```

Automatic execution requires `passed` for `notes`/`issues`. `concerns` routes to manual intervention; the LLM itself never decides whether an update occurs.

## 6. State machine and deterministic gates

Suggested candidate states:

```text
discovered
metadata_pending
holding
research_pending
researching
manual_ready
auto_ready
approved
executing
verifying
succeeded
manual_intervention
failed
rolled_back
superseded
resolved
```

Centralize all state transitions in a service/domain layer. Scheduler, CLI, API, and browser must call the same methods; do not duplicate gate logic in route handlers.

An execution is eligible only when all applicable conditions pass:

1. Candidate is newest active exact revision.
2. Container is running.
3. Installed-to-target class is within `upgrade.version`.
4. Labels are valid and desired/runtime drift is resolved.
5. Both hold components have elapsed.
6. Required research has completed and passed.
7. Target repository/flavor/architecture/digest are deterministic.
8. Current live image/container/template revision still matches candidate evidence.
9. No pause, active execution lease, stale approval, or unresolved prior rollback exists.
10. Backup succeeds before mutation.
11. Target image can be pulled/resolved before removing the current container.
12. Native dockerMan recreation path is available.

Policy then determines the path:

- `manual`: transition to `manual_ready`; browser or CLI approval/execute required.
- `auto`: acquire lease and execute automatically.

A manual approval is revision-bound, expiring, single-use, and cannot bypass a failed mandatory gate. Separate explicit per-revision acknowledgments may resolve poor-metadata/research concerns, but must not bypass repository/digest ambiguity, stopped-state protection, failed backup, or failed preflight.

## 7. Execution, verification, and rollback

### 7.1 Update execution

Preserve current native Unraid behavior but move it behind a reusable service:

1. Acquire per-container execution lease and operation ID.
2. Re-fetch WUD and live target evidence.
3. Recompute revision and gates.
4. Pull/resolve exact target image before service interruption.
5. Save backup containing template XML, sanitized inspect/host config, current image ID/digest, target digest, and manifest hashes.
6. Structurally change only `<Repository>` for an update.
7. Recreate through native dockerMan semantics.
8. Preserve running/stopped policy; stopped containers never enter this path.
9. Verify image/digest, running state, mounts, ports, network, restart policy, labels, native ownership, Docker health, and optional configured application health URL.
10. Commit success, write audit/events/execution record, and notify.

### 7.2 Policy label editing through browser or CLI

Docker labels are immutable on a live container. Editing policy means an explicit desired-state change and recreation.

Workflow:

1. Stage proposed labels and show exact diff.
2. Display prominent restart warning.
3. Require explicit `Save labels and redeploy` confirmation; a dropdown change alone never restarts a service.
4. Back up installed dockerMan XML and sanitized live evidence.
5. Parse XML structurally and edit only these label keys in `<ExtraParams>`:
   - `io.jmengit.upgrade.version`
   - `io.jmengit.upgrade.policy`
   - `io.jmengit.upgrade.research`
   - optional `io.jmengit.upgrade.source`
   - optional `io.jmengit.upgrade.hold-days`
6. Preserve all unrelated arguments, order where feasible, quoting, `<Config>` values, paths, secrets, and metadata.
7. Pull no new application image; recreate using the existing exact image reference/ID where dockerMan supports it.
8. Verify runtime labels and all configuration parity.
9. Roll back XML and recreate the prior container if verification fails.
10. Record operation in execution/audit JSONL.

Provide batch staging in the UI, but redeploy containers deliberately one at a time. CLI should offer `policy show`, `policy diff`, and `policy apply --confirm-container NAME`.

### 7.3 Rollback

Rollback should restore the prior template and prior image reference/digest through dockerMan, then re-run full verification. Never claim rollback succeeded from a Docker start event alone. If rollback fails, preserve evidence, enter `manual_intervention`, and emit a prominent alert.

No managed application update/rollback canary has yet completed in production. The implementer must select a low-consequence running container with the operator's approval and exercise update plus rollback before enabling broad auto mode.

## 8. Headless operation and CLI

The web server may remain in the same process initially, but all work must continue without anyone opening it. A future `WEB_ENABLED=false` option is acceptable if scheduler, health, and CLI behavior remain available.

Implement CLI subcommands using the existing `container-updater` entry point or a dedicated `container-updaterctl`:

```text
container-updater scan
container-updater status [--json]
container-updater candidates [--json]
container-updater candidate show <id|container> [--json]
container-updater approve <revision> --actor <name>
container-updater execute <revision> --confirm-container <name>
container-updater defer <revision> --reason <text>
container-updater policy show <container>
container-updater policy diff <container> ...labels...
container-updater policy apply <container> ...labels... --confirm-container <name>
container-updater logs [--container NAME] [--json]
container-updater audit verify
container-updater research run <revision>
```

The CLI and scheduler must use transactional leases so simultaneous browser/CLI/auto actions cannot execute the same update twice.

## 9. Durable state, files, and SQLite

### 9.1 Recommended persistent layout

```text
/data/
  state/
    updater.db
  logs/
    updater.log
    events.jsonl
    containers/
      <safe-container-name>.jsonl
  audit/
    audit.jsonl
  research/
    <safe-container-name>/
      <candidate-revision>.json
  executions/
    <safe-container-name>/
      <operation-id>.json
  migrations/
    v0.7.1-policy-export.json
```

Paths must be confined beneath `/data`, container names sanitized, file writes atomic, permissions restrictive, and secrets redacted.

### 9.2 Why SQLite remains

Use SQLite WAL for:

- Atomic state transitions
- Unique candidate revisions
- Per-container execution leases
- Idempotency keys
- Approval binding and expiration
- Scheduler/browser/CLI concurrency
- Notification outbox
- Recovery after process crashes

Do not use it for hidden user policy. Effective policy must be reproducible from labels and environment variables.

### 9.3 JSON/JSONL requirements

Write append-only event records for every material observation, decision, gate, and action. Include:

- `schema_version`
- UTC timestamp
- operation ID
- container
- candidate revision
- actor (`scheduler`, `auto`, authenticated user, CLI actor)
- event type
- prior/new state
- deterministic gate inputs and results
- redacted details
- previous/event hash for audit records

Per-container JSONL may duplicate the global event stream for convenient inspection. Prefer writing once plus a reliable projection; if writing twice, test crash behavior and document which file is authoritative.

Research and execution summary JSON files are immutable per revision/operation and written by temporary file plus `fsync`/atomic rename.

## 10. Browser design

The browser is optional but should expose the same effective state:

- Dashboard: no action/action needed/system attention.
- Effective labels with provenance and desired/runtime drift.
- Installed → final target classification.
- Release-line and exact-target timestamps, sources, confidence, hold requirements, eligible date, and remaining time.
- Research mode/status/citations.
- Every deterministic gate with plain-English explanation.
- Manual Update button hidden/disabled until hold and mandatory gates pass.
- Auto candidates show planned eligibility and execution disposition.
- Candidate and container event timelines with expandable JSON.
- Downloads for redacted JSON evidence/audit/execution records.
- Policy editor stages label changes and requires explicit restart/redeploy confirmation.
- Global hold settings are displayed as environment-owned and not editable into SQLite.

Remove v0.7.1's risk-gate editor and browser policy override table.

## 11. Notifications

Notifications are derived from durable outbox events, not direct route side effects. At minimum distinguish:

- Candidate discovered (optional/informational)
- Candidate now actionable/eligible
- Auto execution starting
- Update succeeded
- Update failed or rollback attempted
- Manual intervention required
- Policy label redeploy succeeded/failed

Avoid collision confusion: notifications always state installed version, final target version/digest, installed-to-target class, hold calculation, and why the candidate is or is not eligible.

Do not repeatedly notify unchanged candidates. New target revisions supersede and deduplicate prior notifications.

## 12. v0.7.1 migration plan

Current v0.7.1 state includes:

- SQLite `container_policy_overrides`
- SQLite `app_settings.risk_gates`
- Labels `io.jmengit.upgrade.policy=manual|notify|patch|minor`
- Label `io.jmengit.upgrade.risk=low|medium|high|critical`
- Browser risk-gate editor

Migration must be explicit and non-destructive:

1. Back up appdata, database, installed updater template, and all managed dockerMan templates.
2. Export existing overrides, risk gates, and discovered legacy labels to `/data/migrations/v0.7.1-policy-export.json` with redaction and hashes.
3. Generate a migration proposal for each container; do not silently redeploy the fleet.
4. Suggested mappings are proposals only:
   - old `manual` or `notify` → new `policy=manual`
   - old `patch` → `version=patch`, proposed `policy=manual`
   - old `minor` → `version=minor`, proposed `policy=manual`
   - old risk has no direct equivalent and must not silently determine auto/manual behavior
   - proposed research may default conservatively to `notes`, but must be shown for confirmation
5. Mark incomplete containers `policy_migration_required`; no automatic update is permitted.
6. UI/CLI allow review and one-at-a-time `Save labels and redeploy`.
7. After all desired policies are moved into dockerMan labels and verified at runtime, stop reading overrides/risk gates.
8. Retain old tables read-only for one release, then remove in a later migration after export/rollback documentation exists.

Do not default existing containers to `auto`, and do not infer `version=major` from risk.

## 13. Codebase implementation map

The next agent should inspect before editing, then implement roughly as follows:

- `src/unraid_updater/config.py`
  - Add/validate hold and file-output environment settings.
  - Separate web authentication requirements from headless scheduler requirements.
- `src/unraid_updater/policy_config.py`
  - Replace risk-gate logic with label parsing, validation, effective policy, and migration helpers; rename module if appropriate.
- `src/unraid_updater/domain/enums.py`, `models.py`, `policy.py`, `state_machine.py`
  - Remove risk semantics from active policy.
  - Add `UpdatePolicy`, `ResearchDepth`, hold/timestamp provenance, effective policy, and richer states.
  - Make this domain layer authoritative; remove duplicate policy logic from `wud.py` and `web.py`.
- `src/unraid_updater/wud.py`
  - Keep bounded WUD client/normalization, but emit discovery facts rather than final policy decisions.
  - Reconcile absent candidates as resolved/superseded only after successful complete scans.
- `src/unraid_updater/resolver/`
  - Implement source, version, digest, release-line, exact-target, and timestamp resolution with provider adapters.
- `src/unraid_updater/research.py`
  - Split collection from LLM assessment.
  - Implement `none|notes|issues`, exact citations, immutable JSON output, and source-release binding.
- `src/unraid_updater/docker_runtime.py`
  - Add structural label edit/diff, runtime parity verification, and policy-only redeploy/rollback.
  - Replace regex XML repository mutation with structural XML where practical.
- New service modules, e.g. `services/candidates.py`, `services/executions.py`, `services/policies.py`, `events.py`, `cli.py`
  - Central orchestration, leases, file projections, and shared browser/CLI/scheduler behavior.
- `src/unraid_updater/db.py`
  - Add schema migrations, leases/outbox/timestamp provenance as needed.
  - Remove policy override writes and risk gate reads from active paths.
  - Retain audit chaining and transactional state.
- `src/unraid_updater/scheduler.py`
  - Scan frequently enough to evaluate eligible auto candidates; scanning once daily at 06:45 is insufficient for precise holds/automatic execution.
  - Separate discovery, research, and execution jobs or implement a deterministic cycle with leases.
- `src/unraid_updater/web.py` and templates
  - Thin UI over services; new timelines/hold/source/policy pages; remove risk editor.
- `unraid/container-updater.xml`
  - Add hold/file settings and descriptions; preserve installed values via XML-aware merge.
- `docs/operations.md`, `README.md`, `SECURITY.md`
  - Document headless use, CLI, policy labels, holds, files, backup/restore, threat boundary, and migration.

## 14. Testing requirements

### 14.1 Unit tests

- Label parsing/validation and precedence.
- Hold override boundaries and invalid input.
- Installed-to-target semver classification.
- Unknown classification → major.
- Flavor/repository/architecture protection.
- Timestamp precedence/provenance.
- First-seen fallback bound to digest.
- Two-part hold collision examples.
- `manual` versus `auto` differ only in execution trigger, not hold duration.
- `research=none` makes no provider calls.
- `notes` versus `issues` evidence scopes.
- Invalid citations/provider responses fail closed.
- Canonical candidate revision changes whenever target/policy/evidence changes.
- JSONL redaction, chaining, atomic files, and safe paths.

### 14.2 Integration tests

- Successful complete WUD scan reconciles absent candidates; failed/incomplete scan does not.
- Concurrent browser/CLI/scheduler execution attempts produce one operation.
- Manual Update unavailable before hold and available after hold.
- Explicit `major+auto+none+hold-days=0` can execute a safe fixture—proving major auto is not hard-blocked.
- Stopped container remains stopped and blocked.
- Policy label edit updates only intended ExtraParams labels, preserves all `<Config>` values, recreates, verifies runtime labels, and rolls back on failure.
- Update execution preserves mounts, ports, network, environment keys/values, restart policy, labels, and native ownership.
- Research and execution JSON files survive restart and match DB state.
- CLI works with no browser session.
- Portainer mutation remains rejected.

### 14.3 Security tests

- CSRF/session/auth remain enforced for browser mutations.
- CLI requires local/container access and explicit confirmation for mutation.
- Source URL allowlist/SSRF protection.
- No secrets in JSON/JSONL/research prompts/downloads.
- Path traversal rejected.
- Symlink-safe writes beneath `/data` and backups.
- Stale revision/approval/replay rejected.
- Malicious WUD/GitHub/LLM text never becomes an instruction or mutation input.

### 14.4 Production canary

Before enabling auto broadly:

1. Deploy in report/manual mode.
2. Verify migration proposals and labels.
3. Run several scans and inspect JSONL/audit parity.
4. Choose a low-consequence running container with operator approval.
5. Exercise policy label redeploy and rollback.
6. Exercise one manual application update and rollback.
7. Enable `auto` only for one low-consequence container.
8. Observe at least one full hold/research/execution cycle.
9. Expand gradually.

## 15. Delivery discipline

- Work on a dedicated branch/worktree; one task/branch/PR.
- Do not modify production while designing or testing.
- Back up before every production-sensitive change.
- Run Ruff, full pytest, build, XML parsing, `git diff --check`, security review, and focused production code review.
- Use immutable semantic version tags and GitHub Actions for the actual container build when possible.
- Upgrade through XML-aware merge; installed values win.
- Give a prominent warning before any restart/redeploy.
- Verify the deployed image, running/health state, login, CLI, scheduler, files, labels, candidate reconciliation, and rollback artifacts.
- Do not claim success without real command/API evidence.

## 16. Suggested implementation phases

### Phase 0 — Lock design and fixtures

Create fixtures for normal semver, major→patch collision, mutable tags, no metadata, non-GitHub source, legacy labels, and policy-only XML edits. No production mutation.

### Phase 1 — Domain/config/migration foundation

Implement new labels, environment holds, typed policy/timestamp models, DB migration/export, candidate revision schema, and tests. Keep v0.7.1 execution disabled behind feature flags if needed.

### Phase 2 — Resolver and hold engine

Implement digest/source/release/timestamp resolution, conservative fallbacks, collision-safe two-part holds, and JSON outputs.

### Phase 3 — Research modes

Implement `none|notes|issues`, bounded evidence, citations, deterministic output schema, and fail-closed behavior.

### Phase 4 — Events, audit files, and CLI

Implement JSONL/JSON projections, verification command, CLI read/manual actions, and shared service layer.

### Phase 5 — Policy edit/redeploy

Implement XML structural label diff/apply, explicit restart flow, parity verification, and rollback. Migrate containers one at a time.

### Phase 6 — Automatic execution

Implement leases, auto-ready scheduler, native update execution, verification, rollback, outbox notifications, and canary controls.

### Phase 7 — Browser replacement and cleanup

Replace risk/override UI, expose timelines and policy diffs, remove active override reads, update docs, and complete release/deployment verification.

Each phase should be independently testable and releasable where practical. Do not combine the first real policy redeploy, first real application update, and first auto execution into one production step.

## 17. Definition of done

The implementation is complete only when:

- All effective per-container policy comes from dockerMan/Docker labels; no active SQLite override exists.
- Global holds come only from validated environment variables, except explicit per-container hold label override.
- Major-to-patch collision tests pass using installed-to-final-target and two-part holds.
- Manual and auto candidates use identical hold calculations.
- `research=none|notes|issues` works as specified.
- Headless scheduler and CLI work without browser interaction.
- JSON/JSONL provide complete redacted operational history.
- SQLite is limited to transactional runtime state and can be rebuilt without changing intended policy.
- Browser label changes explicitly warn, back up, redeploy natively, verify, and roll back.
- Automatic major update is possible only when explicitly labeled and all gates pass.
- Poor metadata can progress via clearly labeled conservative fallback without silently weakening digest/repository/preflight safety.
- Stale candidates, approvals, and research cannot execute.
- One approved production canary update and rollback have completed with retained evidence.
- Production is deployed through dockerMan with installed values preserved and verified healthy.

## 18. Out of scope for this implementation

- Portainer mutation.
- Arbitrary non-GitHub research adapters beyond a clean provider interface.
- Automatic fuzzy source/release mapping.
- Updating stopped containers or starting them automatically.
- Removing deterministic safeguards through labels.
- Giving the LLM mutation tools or authority.
- Replacing WUD as discovery source.
- Multi-host control from one deployment.

---

This document supersedes the v0.7.1 browser-owned risk-gate and SQLite policy-override design. Where current code conflicts with this document, migrate deliberately with export/rollback support rather than preserving the old semantics by default.
