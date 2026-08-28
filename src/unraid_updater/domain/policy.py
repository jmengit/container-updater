"""Deterministic flavor, version, policy, and soak decisions."""
from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from .enums import CandidateStatus, ChangeType, Policy, Risk
from .models import Candidate, Classification, Deployment, PolicySpec

DEFAULT_SOAK_DAYS = {"major": 30, "minor": 14, "patch": 7, "digest": 7}
AUTOMATIC_POLICIES = {Policy.PATCH.value, Policy.MINOR.value}


def version_tuple(value: str | None) -> tuple[int, int, int] | None:
    """Return numeric semver prefix, ignoring a leading v and flavor suffix."""
    if not value:
        return None
    match = re.search(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?", value)
    return tuple(map(int, match.groups(default="0"))) if match else None


def flavor(value: str | None) -> str:
    """Normalize a tag into its flavor family.

    A plain tag is a different family from every suffixed tag.  LinuxServer's
    ``-lsNNN`` build suffix is intentionally treated as the same family.
    """
    if not value:
        return ""
    tag = value.rsplit("@", 1)[0].rsplit(":", 1)[-1]
    match = re.search(r"\d+\.\d+(?:\.\d+)?(.*)$", tag)
    suffix = (match.group(1) if match else "").lower()
    if re.fullmatch(r"-ls\d+", suffix):
        return "-ls"
    return suffix


def same_flavor(current: str | None, candidate: str | None) -> bool:
    return flavor(current) == flavor(candidate)


def resolve_flavor(tags: list[str], current: str | None) -> list[str]:
    """Filter registry tags to the installed tag's flavor family."""
    if not current:
        return []
    return [tag for tag in tags if same_flavor(current, tag)]


def best_flavored_tag(tags: list[str], current: str | None) -> str | None:
    """Pick the newest strictly newer tag without flavor drift."""
    current_version = version_tuple(current)
    if not current_version:
        return None
    choices = [
        (version_tuple(tag), tag)
        for tag in resolve_flavor(tags, current)
        if version_tuple(tag) and version_tuple(tag) > current_version
    ]
    return max(choices, key=lambda item: item[0])[1] if choices else None


def bump_type(current: str | None, latest: str | None) -> ChangeType:
    old, new = version_tuple(current), version_tuple(latest)
    if not old or not new or new <= old:
        return ChangeType.NONE
    if new[0] != old[0]:
        return ChangeType.MAJOR
    if new[1] != old[1]:
        return ChangeType.MINOR
    return ChangeType.PATCH if new[2] != old[2] else ChangeType.DIGEST


def parse_soak_days(label: str | None, default: int) -> int:
    match = re.fullmatch(r"(\d+)d", label or "")
    return int(match.group(1)) if match else default


def policy_allows(policy: Policy | str | None, change: ChangeType | str) -> bool:
    policy_value, change_value = str(policy or ""), str(change)
    return change_value in {
        Policy.PINNED.value: set(),
        Policy.NOTIFY.value: set(),
        Policy.PATCH.value: {ChangeType.PATCH.value},
        Policy.MINOR.value: {ChangeType.MINOR.value, ChangeType.PATCH.value},
        Policy.MAJOR_ONLY.value: {ChangeType.MAJOR.value},
        Policy.ALL.value: {x.value for x in ChangeType if x is not ChangeType.NONE},
    }.get(policy_value, set())


def classify(
    deployment: Deployment,
    candidate: Candidate,
    policy: PolicySpec,
    *,
    now: datetime | None = None,
    first_seen_at: datetime | None = None,
) -> Classification:
    """Classify a candidate; medium risk is intentionally manual in v1."""
    now = now or datetime.now(UTC)
    change = ChangeType(str(candidate.change_type))
    reasons: list[str] = []
    explanations: list[str] = []
    soak_days = policy.soak_days(change)
    seen = first_seen_at or candidate.first_seen_at or now
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=UTC)
    age_days = max(0, (now - seen.astimezone(UTC)).days)

    if not candidate.target:
        return Classification(CandidateStatus.UNRESOLVED, ("unresolved",), ("No candidate tag or digest was resolved.",), soak_days, age_days)
    if not policy.explicit:
        return Classification(CandidateStatus.UNCLASSIFIED, ("policy_or_risk_missing",), ("Explicit policy and risk labels are required.",), soak_days, age_days)
    if str(policy.policy) == Policy.PINNED.value:
        return Classification(CandidateStatus.PINNED, ("pinned_policy",), ("The workload is pinned and requires manual handling.",), soak_days, age_days)
    if deployment.state != "running":
        return Classification(CandidateStatus.MANUAL_REVIEW, ("stopped",), ("Stopped containers are manual-only.",), soak_days, age_days)
    if str(policy.risk) != Risk.LOW.value:
        reasons.append("risk_not_low")
        explanations.append("Only explicitly low-risk workloads are approval-ready in v1.")
    if not policy_allows(policy.policy, change):
        reasons.append("policy_disallows_change")
        explanations.append("The workload policy does not permit this change type.")
    if policy.breaking_review:
        reasons.append("breaking_review_required")
        explanations.append("Breaking-change review is required.")
    if policy.issue_review != "none":
        reasons.append("issue_review_required")
        explanations.append("Issue review is required.")
    if reasons:
        return Classification(CandidateStatus.MANUAL_REVIEW, tuple(reasons), tuple(explanations), soak_days, age_days)
    if age_days < soak_days:
        return Classification(CandidateStatus.SOAKING, ("soak_incomplete",), ("The candidate has not completed its soak period.",), soak_days, age_days)
    return Classification(CandidateStatus.APPROVAL_READY, ("policy_gates_passed",), ("The candidate passed report-only approval gates.",), soak_days, age_days)


def classification_to_row(classification: Classification, candidate: Candidate) -> dict[str, Any]:
    return {
        "status": classification.status.value,
        "reason_codes": list(classification.reason_codes),
        "explanations": list(classification.explanations),
        "age_days": classification.age_days,
        "soak_days": classification.soak_days,
        "candidate": candidate.target,
    }
