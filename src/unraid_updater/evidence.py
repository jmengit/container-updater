"""Redacted, durable JSON/JSONL evidence projections."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping

_SECRET = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential)")


class EvidenceError(ValueError):
    """Evidence path or record is unsafe."""


def safe_root(root: str | Path) -> Path:
    path = Path(root).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    resolved = path.resolve()
    if not resolved.is_dir():
        raise EvidenceError("evidence root must be a directory")
    return resolved


def safe_path(root: str | Path, relative: str | Path) -> Path:
    base = safe_root(root)
    candidate = (base / Path(relative)).resolve()
    if candidate != base and base not in candidate.parents:
        raise EvidenceError("evidence path escapes configured root")
    if candidate.exists() and candidate.is_symlink():
        raise EvidenceError("evidence path may not be a symlink")
    return candidate


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): ("[REDACTED]" if _SECRET.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, tuple):
        return [redact(v) for v in value]
    return value


def _json(value: Any) -> str:
    return json.dumps(redact(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def write_json(root: str | Path, relative: str | Path, value: Any) -> Path:
    target = safe_path(root, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(_json(value) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return target


def append_jsonl(root: str | Path, relative: str | Path, value: Any) -> Path:
    target = safe_path(root, relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(_json(value) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return target


def _hash_record(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(_json(record).encode("utf-8")).hexdigest()


def append_audit(root: str | Path, relative: str | Path, value: Mapping[str, Any]) -> dict[str, Any]:
    target = safe_path(root, relative)
    previous = ""
    if target.exists():
        lines = [line for line in target.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            previous = str(json.loads(lines[-1]).get("event_hash", ""))
    record = dict(redact(value))
    record["prev_hash"] = previous
    record["event_hash"] = _hash_record(record)
    append_jsonl(root, relative, record)
    return record


def verify_audit(root: str | Path, relative: str | Path) -> bool:
    target = safe_path(root, relative)
    previous = ""
    if not target.exists():
        return True
    for line in target.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("prev_hash", "") != previous:
            return False
        claimed = record.pop("event_hash", None)
        if claimed != _hash_record(record):
            return False
        previous = claimed
    return True


__all__ = ["EvidenceError", "safe_root", "safe_path", "redact", "write_json", "append_jsonl", "append_audit", "verify_audit"]
