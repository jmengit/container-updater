"""Import existing report JSON without invoking any mutation code."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .db import Database


def normalize_status(item: dict[str, Any]) -> str:
    status = str(item.get("status") or "").lower()
    aliases = {
        "automatic": "approval_ready",
        "eligible": "approval_ready",
        "manual": "manual_review",
        "blocked": "manual_review",
        "wait": "soaking",
    }
    if status in aliases:
        return aliases[status]
    if status:
        return status
    if item.get("eligible"):
        return "approval_ready"
    if item.get("age_days", 0) < item.get("soak_days", 0):
        return "soaking"
    return "manual_review"


def import_report(db: Database, report: dict[str, Any], trigger: str = "legacy_import") -> dict[str, int]:
    scan_id = db.start_scan(trigger)
    imported = 0
    try:
        for raw in report.get("candidates", []):
            item = dict(raw)
            item["status"] = normalize_status(item)
            db.upsert_candidate(item, scan_id)
            imported += 1
        summary = {"imported": imported, "inventory_count": int(report.get("inventory_count", 0))}
        db.finish_scan(scan_id, "success", summary)
        db.audit("system", "scan.imported", "scan", str(scan_id), summary)
        return summary
    except Exception as exc:
        db.finish_scan(scan_id, "failed", {"imported": imported}, str(exc))
        raise


def latest_report(directory: str | Path) -> Path | None:
    path = Path(directory)
    if not path.exists():
        return None
    candidates = sorted(path.glob("runs/*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None


def import_latest(db: Database, directory: str | Path) -> dict[str, int] | None:
    report_path = latest_report(directory)
    if not report_path:
        return None
    return import_report(db, json.loads(report_path.read_text(encoding="utf-8")))
