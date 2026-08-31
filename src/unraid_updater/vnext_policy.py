"""Label-owned policy and collision-safe release holds.

This module is intentionally independent of WUD and SQLite so discovery, the CLI,
and the browser can use the same deterministic decisions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Mapping

LABEL_VERSION = "io.jmengit.upgrade.version"
LABEL_POLICY = "io.jmengit.upgrade.policy"
LABEL_RESEARCH = "io.jmengit.upgrade.research"
LABEL_SOURCE = "io.jmengit.upgrade.source"
LABEL_HOLD_DAYS = "io.jmengit.upgrade.hold-days"

class UpdateVersion(StrEnum):
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"

class ExecutionPolicy(StrEnum):
    MANUAL = "manual"
    AUTO = "auto"

class ResearchMode(StrEnum):
    NONE = "none"
    NOTES = "notes"
    ISSUES = "issues"

@dataclass(frozen=True, slots=True)
class LabelPolicy:
    version: UpdateVersion
    policy: ExecutionPolicy
    research: ResearchMode
    source: str | None = None
    hold_days: int | None = None

    @classmethod
    def from_labels(cls, labels: Mapping[str, Any]) -> "LabelPolicy":
        def required(key: str) -> str:
            value = labels.get(key)
            if value is None or not str(value).strip():
                raise ValueError(f"missing required label: {key}")
            return str(value).strip().lower()
        try:
            version = UpdateVersion(required(LABEL_VERSION))
            policy = ExecutionPolicy(required(LABEL_POLICY))
            research = ResearchMode(required(LABEL_RESEARCH))
        except ValueError as exc:
            raise ValueError(f"invalid upgrade policy label: {exc}") from exc
        source = str(labels[LABEL_SOURCE]).strip() if labels.get(LABEL_SOURCE) else None
        if source and not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?", source):
            raise ValueError("source must be an HTTPS GitHub owner/repository URL")
        hold: int | None = None
        if labels.get(LABEL_HOLD_DAYS) not in (None, ""):
            raw = str(labels[LABEL_HOLD_DAYS]).strip()
            if not re.fullmatch(r"(?:0|[1-9][0-9]{0,2})", raw) or not 0 <= int(raw) <= 365:
                raise ValueError("hold-days must be an integer from 0 through 365")
            hold = int(raw)
        return cls(version, policy, research, source, hold)

    @classmethod
    def from_docker_labels(cls, labels: Mapping[str, Any]) -> "LabelPolicy":
        return cls.from_labels(labels)

    def as_labels(self) -> dict[str, str]:
        result = {LABEL_VERSION: self.version.value, LABEL_POLICY: self.policy.value, LABEL_RESEARCH: self.research.value}
        if self.source:
            result[LABEL_SOURCE] = self.source
        if self.hold_days is not None:
            result[LABEL_HOLD_DAYS] = str(self.hold_days)
        return result

@dataclass(frozen=True, slots=True)
class HoldDecision:
    change_class: str
    eligible_at: datetime | None
    line_eligible_at: datetime | None
    exact_eligible_at: datetime | None
    reason: str
    timestamp_confidence: str = "authoritative"

    @property
    def eligible(self) -> bool:
        return self.eligible_at is None or datetime.now(UTC) >= self.eligible_at

def semver(value: str | None) -> tuple[int, int, int] | None:
    """Parse a plain semantic version from a tag/image value.

    Build/prerelease identifiers are deliberately not interpreted as release
    ordering here; callers must resolve them through an authoritative source.
    """
    if not value:
        return None
    match = re.fullmatch(r"[vV]?(\d+)\.(\d+)(?:\.(\d+))?(?:[-+][0-9A-Za-z.-]+)?", str(value).strip())
    if not match:
        return None
    return tuple(int(x or 0) for x in match.groups())  # type: ignore[return-value]

def change_class(installed: str | None, target: str | None) -> str:
    current, final = semver(installed), semver(target)
    if not current or not final:
        return "unknown"
    if final[0] != current[0]: return "major"
    if final[1] != current[1]: return "minor"
    if final[2] != current[2]: return "patch"
    return "none"

def _dt(value: datetime | str | None) -> datetime | None:
    if value is None: return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)

def hold_decision(*, installed: str | None, target: str | None, line_release_at: datetime | str | None,
                  target_release_at: datetime | str | None, global_holds: Mapping[str, int],
                  override_days: int | None = None, now: datetime | None = None,
                  timestamp_confidence: str = "authoritative") -> HoldDecision:
    kind = change_class(installed, target)
    if kind not in {"patch", "minor", "major"}:
        return HoldDecision(kind, None, None, None, "no update or unclassifiable transition", timestamp_confidence)
    days = override_days if override_days is not None else int(global_holds[kind])
    if not 0 <= days <= 365: raise ValueError("hold days must be between 0 and 365")
    try:
        line = _dt(line_release_at)
        exact = _dt(target_release_at)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("release timestamps must be valid ISO-8601 values") from exc
    line_deadline = line + timedelta(days=days) if line else None
    exact_deadline = exact + timedelta(days=days) if exact else None
    eligible = max((x for x in (line_deadline, exact_deadline) if x is not None), default=None)
    return HoldDecision(kind, eligible, line_deadline, exact_deadline,
                        "hold passed" if eligible is None or (now or datetime.now(UTC)) >= eligible else "release hold active",
                        timestamp_confidence)

def validate_global_holds(values: Mapping[str, Any]) -> dict[str, int]:
    result = {}
    for kind in ("patch", "minor", "major"):
        raw = values.get(kind, values.get(f"HOLD_DAYS_{kind.upper()}"))
        if raw is None: raise ValueError(f"missing HOLD_DAYS_{kind.upper()}")
        try: value = int(str(raw))
        except (TypeError, ValueError) as exc: raise ValueError(f"invalid HOLD_DAYS_{kind.upper()}") from exc
        if not 0 <= value <= 365: raise ValueError(f"HOLD_DAYS_{kind.upper()} must be 0..365")
        result[kind] = value
    return result

def effective_policy(labels: Mapping[str, Any], global_holds: Mapping[str, int]) -> LabelPolicy:
    policy = LabelPolicy.from_labels(labels)
    validate_global_holds(global_holds)
    return policy

__all__ = ["LabelPolicy", "HoldDecision", "UpdateVersion", "ExecutionPolicy", "ResearchMode", "hold_decision", "change_class", "validate_global_holds", "effective_policy"]
