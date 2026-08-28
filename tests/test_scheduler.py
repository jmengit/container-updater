from __future__ import annotations

from pathlib import Path

import pytest

from unraid_updater.db import Database
from unraid_updater.scheduler import build_scheduler, run_import


def test_scheduler_disabled_without_import_directory(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    assert build_scheduler(db, "", "45 6 * * *", "America/Chicago") is None


def test_scheduler_rejects_invalid_cron(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    with pytest.raises(ValueError, match="five cron fields"):
        build_scheduler(db, str(tmp_path), "invalid", "America/Chicago")


def test_missing_report_directory_is_nonfatal(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    db.initialize()
    assert run_import(db, str(tmp_path / 'missing')) is None
    assert db.latest_scan() is None
