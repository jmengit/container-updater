from pathlib import Path

from unraid_updater.cli import main
from unraid_updater.db import Database
from unraid_updater.migration import export_policy_overrides


def test_mutating_cli_commands_fail_closed(tmp_path, capsys):
    assert main(["--database", f"sqlite:///{tmp_path / 'db.sqlite'}", "approve", "1"]) == 2
    assert "unavailable" in capsys.readouterr().err


def test_export_overrides(tmp_path):
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    db.initialize()
    assert export_policy_overrides(db) == []
    out = tmp_path / "overrides.json"
    assert main(["--database", f"sqlite:///{tmp_path / 'db.sqlite'}", "export-overrides", str(out)]) == 0
    assert out.exists()
