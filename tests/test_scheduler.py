from __future__ import annotations

from pathlib import Path

import pytest

from unraid_updater.db import Database
from unraid_updater.scheduler import build_scheduler, run_scan


def test_scheduler_is_configured_for_wud_scan(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    scheduler = build_scheduler(db, list, list, "45 6 * * *", "America/Chicago")
    assert scheduler.get_job("wud-api-scan") is not None


def test_scheduler_rejects_invalid_cron(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    with pytest.raises(ValueError, match="five cron fields"):
        build_scheduler(db, list, list, "invalid", "America/Chicago")


def test_wud_scan_persists_empty_snapshot(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    db.initialize()
    assert run_scan(db, list, list) == {
        "imported": 0, "inventory_count": 0, "updates": 0,
        "resolved": 0,
    }
    latest = db.latest_scan()
    assert latest is not None
    assert latest["trigger"] == "wud_api"
