"""Deterministic, offline-friendly vNext research reports.

Collection is intentionally separate: callers provide bounded evidence records;
this module validates sources and builds the report without making network calls.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse

from .evidence import redact

MODES = {"none", "notes", "issues"}
STATUSES = {"passed", "concerns", "failed", "skipped_by_policy"}


class ResearchValidationError(ValueError):
    """Research input violates the evidence or source contract."""


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    url: str
    title: str
    kind: str
    excerpt: str = ""
    published_at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "title": self.title[:300],
            "kind": self.kind[:80],
            "excerpt": self.excerpt[:2000],
            "published_at": self.published_at,
        }


def github_source(value: str) -> str:
    parsed = urlparse(str(value).strip())
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise ResearchValidationError("research source must be an HTTPS GitHub URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ResearchValidationError("research source cannot contain credentials, query, or fragment")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2 or any(part in {".", ".."} for part in parts):
        raise ResearchValidationError("research source must identify owner/repository")
    return f"https://github.com/{parts[0]}/{parts[1].removesuffix('.git')}"


def _evidence(items: Iterable[Mapping[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        try:
            record = EvidenceRecord(
                url=str(item["url"]),
                title=str(item.get("title", "")),
                kind=str(item.get("kind", "document")),
                excerpt=str(item.get("excerpt", "")),
                published_at=str(item["published_at"]) if item.get("published_at") else None,
            )
            parsed = urlparse(record.url)
            if parsed.scheme != "https" or not parsed.netloc:
                raise ResearchValidationError("evidence URLs must be HTTPS")
        except (KeyError, TypeError) as exc:
            raise ResearchValidationError("malformed evidence record") from exc
        if record.url in seen:
            continue
        seen.add(record.url)
        result.append(record.as_dict())
        if len(result) >= limit:
            break
    return result


def build_report(
    *,
    revision: str,
    mode: str,
    source: str | None = None,
    evidence: Iterable[Mapping[str, Any]] = (),
    status: str | None = None,
    concerns: Iterable[str] = (),
    max_evidence: int = 32,
) -> dict[str, Any]:
    mode = str(mode).lower()
    if mode not in MODES:
        raise ResearchValidationError("research mode must be none, notes, or issues")
    if not revision or len(str(revision)) > 256:
        raise ResearchValidationError("research revision is required and bounded")
    normalized_source = github_source(source) if source else None
    if mode == "none":
        if list(evidence):
            raise ResearchValidationError("none mode cannot contain evidence")
        final_status = "skipped_by_policy"
        records: list[dict[str, Any]] = []
    else:
        records = _evidence(evidence, limit=max(0, min(int(max_evidence), 128)))
        final_status = status or ("passed" if records else "concerns")
        if final_status not in {"passed", "concerns", "failed"}:
            raise ResearchValidationError("invalid research status")
    report = {
        "revision": str(revision),
        "mode": mode,
        "status": final_status,
        "source": normalized_source,
        "evidence": records,
        "concerns": [str(item)[:500] for item in concerns][:32],
    }
    report["report_hash"] = hashlib.sha256(repr(redact(report)).encode()).hexdigest()
    return report


__all__ = ["EvidenceRecord", "MODES", "ResearchValidationError", "build_report", "github_source"]
