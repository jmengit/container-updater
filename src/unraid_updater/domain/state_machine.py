"""Centralized candidate and approval lifecycle transition guards."""
from __future__ import annotations

from collections.abc import Iterable

from .enums import ApprovalDecision, CandidateStatus, ExecutionState


class InvalidTransition(ValueError):
    """Raised when a lifecycle transition would violate the safety contract."""


_CANDIDATE_TRANSITIONS: dict[str, set[str]] = {
    CandidateStatus.DISCOVERED.value: {
        CandidateStatus.SOAKING.value,
        CandidateStatus.APPROVAL_READY.value,
        CandidateStatus.MANUAL_REVIEW.value,
        CandidateStatus.PINNED.value,
        CandidateStatus.UNRESOLVED.value,
        CandidateStatus.UNCLASSIFIED.value,
    },
    CandidateStatus.SOAKING.value: {
        CandidateStatus.APPROVAL_READY.value,
        CandidateStatus.MANUAL_REVIEW.value,
        CandidateStatus.SUPERSEDED.value,
    },
    CandidateStatus.APPROVAL_READY.value: {
        CandidateStatus.APPROVED.value,
        CandidateStatus.DEFERRED.value,
        CandidateStatus.MANUAL_REVIEW.value,
        CandidateStatus.SUPERSEDED.value,
    },
    CandidateStatus.APPROVED.value: {
        CandidateStatus.QUEUED.value,
        CandidateStatus.REVOKED.value,
        CandidateStatus.EXPIRED.value,
        CandidateStatus.PREFLIGHT_BLOCKED.value,
        CandidateStatus.SUPERSEDED.value,
    },
    CandidateStatus.DEFERRED.value: {
        CandidateStatus.APPROVAL_READY.value,
        CandidateStatus.SUPERSEDED.value,
    },
}

_EXECUTION_TRANSITIONS: dict[str, set[str]] = {
    ExecutionState.QUEUED.value: {ExecutionState.CLAIMED.value, ExecutionState.BLOCKED.value},
    ExecutionState.CLAIMED.value: {ExecutionState.PREFLIGHT.value, ExecutionState.BLOCKED.value, ExecutionState.FAILED.value},
    ExecutionState.PREFLIGHT.value: {ExecutionState.BACKUP_PREPARED.value, ExecutionState.BLOCKED.value, ExecutionState.FAILED.value},
    ExecutionState.BACKUP_PREPARED.value: {ExecutionState.MUTATION_STARTED.value, ExecutionState.FAILED.value},
    ExecutionState.MUTATION_STARTED.value: {ExecutionState.VERIFYING.value, ExecutionState.ROLLBACK_STARTED.value, ExecutionState.FAILED.value},
    ExecutionState.VERIFYING.value: {ExecutionState.SUCCEEDED.value, ExecutionState.ROLLBACK_STARTED.value, ExecutionState.FAILED.value},
    ExecutionState.ROLLBACK_STARTED.value: {ExecutionState.ROLLED_BACK.value, ExecutionState.NEEDS_ATTENTION.value},
}
_TERMINAL_EXECUTION = {
    ExecutionState.SUCCEEDED.value,
    ExecutionState.ROLLED_BACK.value,
    ExecutionState.BLOCKED.value,
    ExecutionState.FAILED.value,
    ExecutionState.NEEDS_ATTENTION.value,
}


def transition(current: str, target: str, *, allowed: dict[str, set[str]]) -> str:
    if target not in allowed.get(current, set()):
        raise InvalidTransition(f"invalid transition {current!r} -> {target!r}")
    return target


def transition_candidate(current: CandidateStatus | str, target: CandidateStatus | str) -> CandidateStatus:
    current_value, target_value = str(current), str(target)
    transition(current_value, target_value, allowed=_CANDIDATE_TRANSITIONS)
    return CandidateStatus(target_value)


def transition_execution(current: ExecutionState | str, target: ExecutionState | str) -> ExecutionState:
    current_value, target_value = str(current), str(target)
    transition(current_value, target_value, allowed=_EXECUTION_TRANSITIONS)
    return ExecutionState(target_value)


def is_terminal_execution(state: ExecutionState | str) -> bool:
    return str(state) in _TERMINAL_EXECUTION


def active_approval_decision(decisions: Iterable[ApprovalDecision | str]) -> str | None:
    """Return the latest non-revoked decision, useful for append-only histories."""
    latest: str | None = None
    for decision in decisions:
        value = str(decision)
        if value == ApprovalDecision.REVOKED.value:
            latest = None
        elif value in {ApprovalDecision.APPROVED.value, ApprovalDecision.DEFERRED.value}:
            latest = value
    return latest
