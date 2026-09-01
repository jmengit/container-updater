"""Pure, conservative release identity and timestamp resolution helpers."""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

_SEMVER = re.compile(r"^[vV]?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
_DIGEST = re.compile(r"^sha256:[0-9a-fA-F]{64}$")


class ResolutionError(ValueError):
    """Metadata cannot be safely resolved."""


@dataclass(frozen=True, slots=True)
class TimestampResult:
    value: datetime | None
    confidence: str
    source: str
    reason: str = ""


@dataclass(frozen=True, slots=True)
class ReleaseIdentity:
    repository: str
    tag: str
    digest: str | None
    release_at: datetime | None
    timestamp_confidence: str
    match_method: str


def parse_version(value: str | None) -> tuple[int, int, int] | None:
    """Parse an exact three-component semantic version, ignoring prerelease ordering."""
    if value is None:
        return None
    match = _SEMVER.fullmatch(str(value).strip())
    if not match:
        return None
    return tuple(int(match.group(i)) for i in (1, 2, 3))  # type: ignore[return-value]


def normalize_digest(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    text = str(value).strip()
    if not _DIGEST.fullmatch(text):
        raise ResolutionError("digest must be a complete sha256:<64 hex> value")
    return text.lower()


def parse_timestamp(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip())
        except ValueError as exc:
            raise ResolutionError("timestamp must be valid ISO-8601") from exc
    else:
        raise ResolutionError("timestamp must be datetime or ISO-8601")
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def resolve_timestamp(metadata: Mapping[str, Any], *, first_seen_at: Any = None,
                      fallback_enabled: bool = True) -> TimestampResult:
    """Prefer authoritative release/published/created fields in documented order."""
    for key in ("release_at", "released_at", "published_at", "created_at"):
        if key in metadata and metadata[key] not in (None, ""):
            try:
                value = parse_timestamp(metadata[key])
            except ResolutionError:
                continue
            if value is not None:
                return TimestampResult(value, "authoritative", key)
    if fallback_enabled and first_seen_at not in (None, ""):
        try:
            value = parse_timestamp(first_seen_at)
        except ResolutionError:
            value = None
        if value is not None:
            return TimestampResult(value, "first_seen_conservative", "first_seen",
                                   "authoritative release timestamp unavailable")
    return TimestampResult(None, "unknown", "none", "authoritative release timestamp unavailable")


def release_identity(*, repository: str, tag: str, digest: str | None = None,
                     metadata: Mapping[str, Any] | None = None,
                     first_seen_at: Any = None, fallback_enabled: bool = True,
                     match_method: str = "exact_tag") -> ReleaseIdentity:
    """Build a stable identity from exact repository/tag/digest data only."""
    repo, target = str(repository).strip(), str(tag).strip()
    if not repo or not target:
        raise ResolutionError("repository and tag are required")
    timestamp = resolve_timestamp(metadata or {}, first_seen_at=first_seen_at,
                                  fallback_enabled=fallback_enabled)
    return ReleaseIdentity(repo, target, normalize_digest(digest), timestamp.value,
                           timestamp.confidence, match_method)


__all__ = [
    "ReleaseIdentity",
    "ResolutionError",
    "TimestampResult",
    "normalize_digest",
    "parse_timestamp",
    "parse_version",
    "release_identity",
    "resolve_timestamp",
]

# Compatibility aliases used by callers that prefer explicit names.
exact_digest = normalize_digest
resolve_release_identity = release_identity


def change_class(installed: str | None, target: str | None) -> str:
    current, final = parse_version(installed), parse_version(target)
    if not current or not final:
        return "unknown"
    if final[0] != current[0]:
        return "major"
    if final[1] != current[1]:
        return "minor"
    if final[2] != current[2]:
        return "patch"
    return "none"

__all__.append("change_class")
