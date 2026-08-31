from __future__ import annotations

from pathlib import Path

from unraid_updater.db import Database
from unraid_updater.service import UpdaterService


def row(tag: str) -> dict:
    return {
        "name": "app", "status": "running", "updateAvailable": True,
        "labels": {
            "io.jmengit.upgrade.version": "patch",
            "io.jmengit.upgrade.policy": "manual",
            "io.jmengit.upgrade.research": "none",
        },
        "image": {"tag": {"value": "1.0.0"}},
        "updateKind": {"kind": "tag", "semverDiff": "patch"},
        "result": {"tag": tag},
    }


def test_newer_exact_target_supersedes_older_revision(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    service = UpdaterService(db)
    live = [{"container": "app", "state": "running", "image": "repo/app:1.0.0"}]
    service.reconcile_rows([row("1.0.1")], live)
    service.reconcile_rows([row("1.0.2")], live)
    candidates = service.candidates()
    assert {item["status"] for item in candidates} == {"superseded", "manual_review"}
    assert sum(item["status"] == "superseded" for item in candidates) == 1
    assert sum(item["target"] == "repo/app:1.0.2" for item in candidates) == 1


def test_distinct_containers_are_not_superseded(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    service = UpdaterService(db)
    one = row("1.0.1")
    two = row("1.0.1")
    two["name"] = "other"
    live = [
        {"container": "app", "state": "running", "image": "repo/app:1.0.0"},
        {"container": "other", "state": "running", "image": "repo/app:1.0.0"},
    ]
    service.reconcile_rows([one, two], live)
    assert all(item["status"] == "manual_review" for item in service.candidates())
    assert len(service.candidates()) == 2


def test_failed_scan_does_not_resolve_existing_candidates(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    service = UpdaterService(db)
    live = [{"container": "app", "state": "running", "image": "repo/app:1.0.0"}]
    service.reconcile_rows([row("1.0.1")], live)
    assert service.candidates()[0]["status"] == "manual_review"
    # Empty successful scans are authoritative and therefore resolve the row.
    service.reconcile_rows([], live)
    assert service.candidates()[0]["status"] == "resolved"
