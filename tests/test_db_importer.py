from __future__ import annotations

from pathlib import Path

import pytest

from unraid_updater.db import Database
from unraid_updater.importer import import_report


def database(tmp_path: Path) -> Database:
    db = Database(f"sqlite:///{tmp_path / 'updater.db'}")
    db.initialize()
    return db


def report(status: str = "approval_ready") -> dict:
    return {
        "inventory_count": 1,
        "candidates": [{
            "container": "Example", "state": "running", "image": "example/app:1.0.0",
            "current": "1.0.0", "candidate": "1.0.1", "change": "patch",
            "policy": "minor", "risk": "low", "status": status,
            "soak_days": 7, "reason_codes": [],
        }],
    }


def test_import_is_idempotent_and_records_scan(tmp_path: Path) -> None:
    db = database(tmp_path)
    import_report(db, report())
    import_report(db, report())
    assert len(db.list_candidates()) == 1
    assert db.latest_scan()["status"] == "success"


def test_rescan_refreshes_policy_for_same_revision(tmp_path: Path) -> None:
    db = database(tmp_path)
    payload = report()
    payload["candidates"][0]["revision_hash"] = "same"
    payload["candidates"][0]["policy"] = "manual"
    import_report(db, payload)
    payload["candidates"][0]["policy"] = "patch"
    import_report(db, payload)
    assert db.list_candidates()[0]["policy"] == "patch"


def test_approval_is_bound_to_exact_revision(tmp_path: Path) -> None:
    db = database(tmp_path)
    import_report(db, report())
    item = db.list_candidates()[0]
    approval_id = db.record_decision(item["id"], item["revision_hash"], "approved", "saturn")
    assert approval_id > 0
    with pytest.raises(ValueError, match="changed"):
        db.record_decision(item["id"], "stale", "approved", "saturn")


def test_non_ready_candidate_cannot_be_approved(tmp_path: Path) -> None:
    db = database(tmp_path)
    import_report(db, report("manual_review"))
    item = db.list_candidates()[0]
    with pytest.raises(ValueError, match="not approval-ready"):
        db.record_decision(item["id"], item["revision_hash"], "approved", "saturn")


def test_database_rejects_non_sqlite_url() -> None:
    with pytest.raises(ValueError, match="sqlite"):
        Database("postgresql://example")
