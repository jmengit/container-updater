"""Typed domain records shared by scanning, policy, and approvals.

The records deliberately contain evidence snapshots.  An approval is only valid for
one exact candidate revision, rather than for a container name in the abstract.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .enums import ApprovalDecision, CandidateStatus, ChangeType, Policy, Risk


@dataclass(frozen=True, slots=True)
class Host:
    name: str
    host_fingerprint: str = ""
    runner_schema: str = "1"
    enabled: bool = True
    id: int | None = None
    created_at: datetime | None = None
    last_seen_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class Container:
    host_id: int
    name: str
    template_identity: str = ""
    display_name: str = ""
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    last_state: str = "unknown"
    archived_at: datetime | None = None
    id: int | None = None


@dataclass(frozen=True, slots=True)
class PolicySpec:
    policy: Policy | str | None = None
    risk: Risk | str | None = None
    soak_major_days: int = 30
    soak_minor_days: int = 14
    soak_patch_days: int = 7
    soak_digest_days: int = 7
    breaking_review: bool = True
    issue_review: str = "none"
    source_revision: str = ""

    @property
    def explicit(self) -> bool:
        return self.policy is not None and self.risk is not None

    def soak_days(self, change: ChangeType | str) -> int:
        return {
            ChangeType.MAJOR.value: self.soak_major_days,
            ChangeType.MINOR.value: self.soak_minor_days,
            ChangeType.PATCH.value: self.soak_patch_days,
            ChangeType.DIGEST.value: self.soak_digest_days,
        }.get(str(change), self.soak_patch_days)


@dataclass(frozen=True, slots=True)
class Deployment:
    scan_id: int
    container_id: int
    state: str
    repository: str
    image_id: str = ""
    digest: str = ""
    version: str | None = None
    flavor: str = ""
    template_hash: str = ""
    health: str = ""
    evidence: Mapping[str, Any] = field(default_factory=dict)
    id: int | None = None


@dataclass(frozen=True, slots=True)
class Candidate:
    container_id: int
    current_version: str | None
    current_image: str
    current_image_id: str = ""
    current_digest: str = ""
    target_tag: str | None = None
    target_digest: str = ""
    target_version: str | None = None
    flavor: str = ""
    change_type: ChangeType | str = ChangeType.NONE
    status: CandidateStatus | str = CandidateStatus.DISCOVERED
    reason_codes: tuple[str, ...] = ()
    first_seen_at: datetime | None = None
    soak_until: datetime | None = None
    revision_hash: str = ""
    superseded_by_id: int | None = None
    first_scan_id: int | None = None
    last_scan_id: int | None = None
    id: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @property
    def target(self) -> str | None:
        return self.target_tag or self.target_digest or self.target_version


@dataclass(frozen=True, slots=True)
class Approval:
    candidate_id: int
    candidate_revision_hash: str
    decision: ApprovalDecision | str
    actor: str
    note: str = ""
    created_at: datetime | None = None
    expires_at: datetime | None = None
    consumed_at: datetime | None = None
    id: int | None = None

    @property
    def is_terminal(self) -> bool:
        return self.decision in {
            ApprovalDecision.REVOKED,
            ApprovalDecision.DEFERRED,
            "expired",
        }


@dataclass(frozen=True, slots=True)
class Classification:
    status: CandidateStatus
    reason_codes: tuple[str, ...] = ()
    explanations: tuple[str, ...] = ()
    soak_days: int = 0
    age_days: int = 0


@dataclass(frozen=True, slots=True)
class ScanResult:
    scan_id: int
    status: str
    inventory_count: int
    resolved_count: int
    error_count: int
    candidates: tuple[Candidate, ...] = ()
    unclassified: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()
    artifact_path: str | None = None
    error_summary: str = ""
