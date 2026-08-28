from __future__ import annotations

from datetime import UTC, datetime, timedelta

from unraid_updater.domain.enums import CandidateStatus, ChangeType, Policy, Risk
from unraid_updater.domain.models import Candidate, Deployment, PolicySpec
from unraid_updater.domain.policy import best_flavored_tag, classify

NOW = datetime(2026, 8, 28, tzinfo=UTC)


def deployment(state: str = "running") -> Deployment:
    return Deployment(scan_id=1, container_id=1, state=state, repository="example/app:1.0.0")


def candidate(change: ChangeType = ChangeType.PATCH, days: int = 8) -> Candidate:
    return Candidate(
        container_id=1,
        current_version="1.0.0",
        current_image="example/app:1.0.0",
        target_tag="1.0.1",
        change_type=change,
        first_seen_at=NOW - timedelta(days=days),
    )


def policy(risk: Risk = Risk.LOW, breaking: bool = False) -> PolicySpec:
    return PolicySpec(policy=Policy.MINOR, risk=risk, breaking_review=breaking)


def test_plain_tag_never_switches_to_full_or_chromium() -> None:
    assert best_flavored_tag(["4.5.5", "4.5.6-full"], "4.5.4") == "4.5.5"
    assert best_flavored_tag(["8.35.0", "8.36.0-chromium"], "8.26.0") == "8.35.0"


def test_stopped_container_is_manual() -> None:
    result = classify(deployment("exited"), candidate(), policy(), now=NOW)
    assert result.status is CandidateStatus.MANUAL_REVIEW
    assert "stopped" in result.reason_codes


def test_medium_risk_is_manual_in_v1() -> None:
    result = classify(deployment(), candidate(), policy(Risk.MEDIUM), now=NOW)
    assert result.status is CandidateStatus.MANUAL_REVIEW
    assert "risk_not_low" in result.reason_codes


def test_low_risk_soaked_patch_is_approval_ready() -> None:
    result = classify(deployment(), candidate(), policy(), now=NOW)
    assert result.status is CandidateStatus.APPROVAL_READY


def test_incomplete_soak_waits() -> None:
    result = classify(deployment(), candidate(days=1), policy(), now=NOW)
    assert result.status is CandidateStatus.SOAKING


def test_breaking_review_never_becomes_ready() -> None:
    result = classify(deployment(), candidate(), policy(breaking=True), now=NOW)
    assert result.status is CandidateStatus.MANUAL_REVIEW
