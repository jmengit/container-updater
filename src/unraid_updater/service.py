"""Shared headless application service for discovery and safe inspection.

This module is deliberately side-effect-light: WUD discovery is injected by the
caller, policy is evaluated deterministically, and mutation remains unavailable
until an execution service supplies every required safety gate.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping

from .db import Database
from .evidence import append_audit, append_jsonl, write_json
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

    def logs(self) -> list[dict[str, Any]]:
        return self.db.audit_rows()

    def audit(self) -> list[dict[str, Any]]:
        return self.db.audit_rows()

    def approve(self, *_args: Any, **_kwargs: Any) -> None:
        raise MutationUnavailable("approval requires the shared authenticated service")

    def execute(self, *_args: Any, **_kwargs: Any) -> None:
        raise MutationUnavailable("execution is fail-closed until all service gates are configured")

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
