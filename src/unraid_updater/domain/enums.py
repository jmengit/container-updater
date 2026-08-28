"""Closed sets used by the report-only domain."""
from __future__ import annotations

from enum import StrEnum


class Policy(StrEnum):
    PINNED = "pinned"
    NOTIFY = "notify"
    PATCH = "patch"
    MINOR = "minor"
    MAJOR_ONLY = "major-only"
    ALL = "all"


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNCLASSIFIED = "unclassified"


class ChangeType(StrEnum):
    NONE = "none"
    DIGEST = "digest"
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"


class CandidateStatus(StrEnum):
    DISCOVERED = "discovered"
    SOAKING = "soaking"
    APPROVAL_READY = "approval_ready"
    APPROVED = "approved"
    QUEUED = "queued"
    PREFLIGHT_BLOCKED = "preflight_blocked"
    DEFERRED = "deferred"
    MANUAL_REVIEW = "manual_review"
    PINNED = "pinned"
    UNRESOLVED = "unresolved"
    UNCLASSIFIED = "unclassified"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    DEFERRED = "deferred"
    REVOKED = "revoked"
    REVIEW = "review"


class ExecutionState(StrEnum):
    QUEUED = "queued"
    CLAIMED = "claimed"
    PREFLIGHT = "preflight"
    BACKUP_PREPARED = "backup_prepared"
    MUTATION_STARTED = "mutation_started"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    ROLLBACK_STARTED = "rollback_started"
    ROLLED_BACK = "rolled_back"
    BLOCKED = "blocked"
    FAILED = "failed"
    NEEDS_ATTENTION = "needs_attention"
