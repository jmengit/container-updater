"""Read-only migration helpers for legacy SQLite policy overrides."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


def export_policy_overrides(database: Any) -> list[dict[str, Any]]:
    path = getattr(database, "path", database)
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    try:
        try:
            rows = connection.execute(
                "SELECT container_name, policy, risk, actor, updated_at FROM container_policy_overrides ORDER BY container_name"
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        return [dict(row) for row in rows]
    finally:
        connection.close()


def write_policy_export(database: Any, output: str | Path) -> Path:
    target = Path(output).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(export_policy_overrides(database), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target
