"""Shared headless application service for discovery and safe inspection.

This module is deliberately side-effect-light: WUD discovery is injected by the
caller, policy is evaluated deterministically, and mutation remains unavailable
until an execution service supplies every required safety gate.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .db import Database
from .docker_runtime import execute_update
from .evidence import append_audit, append_jsonl, write_json
from .execution_gate import (
    ExecutionRequest,
    acquire_lease,
    check_gate,
    get_operation,
    record_operation,
    release_lease,
)
from .vnext_policy import hold_decision
from .wud import normalize


class ServiceError(RuntimeError):
    """A service operation could not be completed safely."""


class MutationUnavailable(ServiceError):
    """Mutation is intentionally unavailable without the shared executor."""


def _version_component(value: str) -> str:
    """Extract a tag/version from an image reference for semver resolution."""
    value = value.strip()
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    if ":" in value.rsplit("/", 1)[-1]:
        value = value.rsplit(":", 1)[1]
    return value


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    evidence_root: Path | None = None
    global_holds: Mapping[str, int] | None = None
    actor: str = "system"


@dataclass(frozen=True, slots=True)
class ScanSummary:
    scan_id: int
    imported: int
    resolved: int
    inventory_count: int

    def as_dict(self) -> dict[str, int]:
        return {
            "scan_id": self.scan_id,
            "imported": self.imported,
            "resolved": self.resolved,
            "inventory_count": self.inventory_count,
        }


class UpdaterService:
    """Single service boundary shared by scheduler, CLI, and web adapters."""

    def __init__(
        self,
        db: Database,
        config: ServiceConfig | None = None,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.db = db
        self.config = config or ServiceConfig()
        self._now = now or (lambda: datetime.now(UTC))
        self.db.initialize()

    def reconcile_rows(
        self,
        containers: list[dict[str, Any]],
        live: list[dict[str, Any]],
        *,
        trigger: str = "wud_api",
    ) -> dict[str, Any]:
        """Normalize and persist an authoritative WUD snapshot.

        Only rows explicitly marked ``updateAvailable`` are candidates.  Every
        row is normalized through the same WUD policy adapter; no service method
        turns a discovery result into a Docker mutation.
        """
        scan_id = self.db.start_scan(trigger)
        live_by_name = {str(row.get("container", "")): row for row in live}
        controls = self.db.container_controls()
        overrides = self.db.policy_overrides()
        gates = self.db.get_setting("risk_gates", {})
        seen: set[str] = set()
        imported = 0
        try:
            for raw in containers:
                if raw.get("updateAvailable") is not True:
                    continue
                name = str(raw.get("name") or raw.get("displayName") or "")
                item = normalize(
                    raw,
                    live_by_name,
                    bool(controls.get(name, {}).get("paused")),
                    overrides.get(name),
                    gates,
                )
                candidate_id = self.db.upsert_candidate(item, scan_id)
                saved = self.db.get_candidate(candidate_id)
                if saved:
                    revision = str(saved["revision_hash"])
                    seen.add(revision)
                    self.db.supersede_older_candidates(name, revision)
                imported += 1
            resolved = self.db.resolve_missing_candidates(seen)
            summary = ScanSummary(scan_id, imported, resolved, len(containers)).as_dict()
            self.db.finish_scan(scan_id, "success", summary)
            self._audit("scan.completed", "scan", str(scan_id), summary)
            self._write_projection("scans", f"{scan_id}.json", summary)
            return summary
        except Exception as exc:
            self.db.finish_scan(scan_id, "failed", {"imported": imported}, str(exc))
            self._audit("scan.failed", "scan", str(scan_id), {"imported": imported, "error": str(exc)})
            raise

    def evaluate_candidate(
        self,
        candidate_id: int,
        *,
        line_release_at: datetime | str | None = None,
        target_release_at: datetime | str | None = None,
        change_class: str | None = None,
        timestamp_confidence: str = "authoritative",
    ) -> dict[str, Any]:
        candidate = self.db.get_candidate(candidate_id)
        if not candidate:
            raise ServiceError(f"candidate {candidate_id} not found")
        policy = str(candidate.get("policy") or "")
        target = str(candidate.get("target") or candidate.get("candidate") or "")
        installed = str(candidate.get("current_version") or candidate.get("current") or "")
        # The database stores the normalized target image for WUD candidates;
        # hold classification consumes the tag/version component, not the
        # registry/repository prefix.
        installed = _version_component(installed)
        target_version = _version_component(target)
        holds = self.config.global_holds or {"patch": 2, "minor": 7, "major": 14}
        decision = hold_decision(
            installed=installed,
            target=target_version,
            line_release_at=line_release_at,
            target_release_at=target_release_at,
            global_holds=holds,
            override_days=(int(candidate["soak_days"]) if candidate.get("soak_days") else None),
            timestamp_confidence=timestamp_confidence,
        )
        result = {
            "candidate_id": candidate_id,
            "revision": candidate["revision_hash"],
            "policy": policy,
            "target": target,
            "change": decision.change_class,
            "hold": {
                "change_class": decision.change_class,
                "eligible_at": decision.eligible_at.isoformat() if decision.eligible_at else None,
                "line_eligible_at": decision.line_eligible_at.isoformat() if decision.line_eligible_at else None,
                "exact_eligible_at": decision.exact_eligible_at.isoformat() if decision.exact_eligible_at else None,
                "reason": decision.reason,
                "timestamp_confidence": decision.timestamp_confidence,
            },
        }
        self._write_projection("candidates", f"{candidate_id}.json", result)
        self._audit("candidate.evaluated", "candidate", str(candidate_id), result)
        return result

    def status(self) -> dict[str, Any]:
        return {"scan": self.db.latest_scan(), "counts": self.db.counts()}

    def candidates(self, status: str | None = None) -> list[dict[str, Any]]:
        return self.db.list_candidates(status)

    def candidate(self, candidate_id: int) -> dict[str, Any] | None:
        return self.db.get_candidate(candidate_id)

    def logs(self) -> list[dict[str, Any]]:
        return self.db.audit_rows()

    def audit(self) -> list[dict[str, Any]]:
        return self.db.audit_rows()

    def read_model(self) -> dict[str, Any]:
        """Return the complete authenticated read model used by adapters."""
        return {
            "status": self.status(),
            "candidates": self.candidates(),
            "logs": self.logs(),
            "audit": self.audit(),
        }

    def approve(
        self,
        candidate_id: int,
        revision: str,
        actor: str,
        reason: str = "",
    ) -> None:
        """Record an explicit revision-bound approval through the service."""
        self.decide(candidate_id, revision, "approved", actor, reason)

    def execute(
        self,
        candidate_id: int | None = None,
        *,
        revision: str | None = None,
        live_revision: str | None = None,
        actor: str = "system",
        socket_path: str | None = None,
        template_dir: Path | None = None,
        backup_root: Path | None = None,
        self_name: str = "container-updater",
        lease_seconds: int = 900,
        operation_key: str | None = None,
    ) -> dict[str, Any]:
        """Execute one revision-bound update through the shared safety boundary."""
        if candidate_id is None or revision is None or live_revision is None:
            raise MutationUnavailable("execution requires an explicit revision-bound request")
        if socket_path is None or template_dir is None or backup_root is None:
            raise MutationUnavailable("execution runtime is not configured")
        candidate_id = int(candidate_id)
        candidate = self.db.get_candidate(candidate_id)
        if not candidate:
            raise ServiceError("candidate not found")
        if str(candidate["revision_hash"]) != str(revision):
            raise ServiceError("candidate revision changed")
        approval = self.db.active_approval(candidate_id, revision)
        if approval is None:
            raise ServiceError("a current approval is required")
        if str(candidate.get("status")) != "approval_ready":
            raise ServiceError("candidate is not approval-ready")
        controls = self.db.container_controls().get(str(candidate["container_name"]), {})
        paused = bool(controls.get("paused"))
        target = str(candidate.get("target") or candidate.get("candidate") or "")
        if not target:
            raise ServiceError("candidate has no resolved target image")
        request = ExecutionRequest(
            container_name=str(candidate["container_name"]),
            candidate_revision=revision,
            live_revision=live_revision,
            approval_id=int(approval["id"]),
            approval_revision=str(approval["candidate_revision"]),
            target=target,
            running=str(candidate.get("state")) == "running",
            hold_active=str(candidate.get("status")) in {"holding", "research_pending"},
            paused=paused,
            self_update=str(candidate["container_name"]) == self_name,
        )
        gate = check_gate(request)
        if not gate.allowed:
            raise ServiceError("execution denied: " + ",".join(gate.reasons))
        key = operation_key or f"candidate:{candidate_id}:{revision}:{live_revision}"
        operation_id = hashlib.sha256(key.encode("utf-8")).hexdigest()
        existing = get_operation(self.db.path, operation_id)
        if existing is not None:
            if existing.get("status") == "succeeded":
                return dict(existing.get("result") or {})
            if existing.get("status") == "running":
                raise ServiceError("operation is already in progress")
        if not acquire_lease(
            self.db.path, operation_id, str(candidate["container_name"]), actor, lease_seconds
        ):
            raise ServiceError("another execution is already in progress")
        execution_id: int | None = None
        try:
            execution_id = self.db.start_execution(
                candidate_id, int(approval["id"]), revision, live_revision, actor
            )
            result = execute_update(
                name=str(candidate["container_name"]),
                target_image=target,
                expected_live_revision=live_revision,
                socket_path=socket_path,
                template_dir=template_dir,
                backup_root=backup_root,
                self_name=self_name,
            )
            self.db.finish_execution(execution_id, "succeeded", result)
            record_operation(self.db.path, operation_id, "succeeded", result)
            self._audit("execution.succeeded", "candidate", str(candidate_id), {
                "execution_id": execution_id, "revision": revision, "operation_key": key,
            })
            return result
        except Exception as exc:
            if execution_id is not None:
                self.db.finish_execution(execution_id, "failed", {}, str(exc))
            record_operation(self.db.path, operation_id, "failed", {"error": str(exc)})
            self._audit("execution.failed", "candidate", str(candidate_id), {
                "revision": revision, "operation_key": key, "error": str(exc),
            })
            raise
        finally:
            release_lease(self.db.path, operation_id, actor)

    def decide(self, candidate_id: int, revision: str, decision: str, actor: str, reason: str = "") -> None:
        """Record an authenticated, revision-bound decision through the service."""
        if decision not in {"approved", "deferred", "rejected"}:
            raise ServiceError("unsupported decision")
        candidate = self.db.get_candidate(candidate_id)
        if not candidate or str(candidate["revision_hash"]) != str(revision):
            raise ServiceError("stale or unknown candidate revision")
        self.db.record_decision(candidate_id, revision, decision, actor, reason)
        self._audit("candidate.decision", "candidate", str(candidate_id), {
            "revision": revision, "decision": decision, "actor": actor, "reason": reason,
        })

    def _audit(self, event_type: str, entity_type: str, entity_id: str, details: Mapping[str, Any]) -> None:
        self.db.audit(self.config.actor, event_type, entity_type, entity_id, dict(details))
        root = self.config.evidence_root
        if root is not None:
            append_audit(root, "audit.jsonl", {"actor": self.config.actor, "event_type": event_type, "entity_type": entity_type, "entity_id": entity_id, "details": dict(details)})

    def _write_projection(self, collection: str, name: str, value: Mapping[str, Any]) -> None:
        root = self.config.evidence_root
        if root is None:
            return
        write_json(root, Path(collection) / name, dict(value))
        append_jsonl(root, "events.jsonl", {"type": f"{collection}.updated", "name": name, "revision": hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()})


Service = UpdaterService

__all__ = ["MutationUnavailable", "ScanSummary", "Service", "ServiceConfig", "ServiceError", "UpdaterService"]
