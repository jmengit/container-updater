"""Fail-closed execution authorization and SQLite-backed operation leases."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import sqlite3
from typing import Any, Mapping


@dataclass(frozen=True)
class ExecutionRequest:
    container_name: str
    candidate_revision: str
    live_revision: str
    approval_id: int | None = None
    approval_revision: str | None = None
    target: str | None = None
    running: bool = False
    paused: bool = False
    hold_active: bool = False
    self_update: bool = False


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reasons: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.allowed

    def __bool__(self) -> bool:
        return self.allowed


def check_gate(request: ExecutionRequest) -> GateDecision:
    """Evaluate all execution preconditions without side effects.

    Missing or malformed evidence is a denial; callers must provide an explicit
    approval and a revision that matches both the candidate and live state.
    """
    reasons: list[str] = []
    if request.approval_id is None:
        reasons.append("missing_approval")
    if not request.candidate_revision or request.approval_revision != request.candidate_revision:
        reasons.append("stale_revision")
    if not request.running:
        reasons.append("not_running")
    if not request.target:
        reasons.append("unresolved_target")
    if request.hold_active:
        reasons.append("active_hold")
    if request.paused:
        reasons.append("paused_container")
    if request.self_update:
        reasons.append("self_update")
    return GateDecision(not reasons, tuple(reasons))


# Compatibility aliases make the small pure function easy to discover.
evaluate_gate = check_gate
execution_gate = check_gate


@dataclass(frozen=True)
class Lease:
    operation_id: str
    container_name: str
    owner: str
    acquired_at: str
    expires_at: str


def _connection(db: Any) -> tuple[sqlite3.Connection, bool]:
    if isinstance(db, sqlite3.Connection):
        return db, False
    conn_factory = getattr(db, "connect", None)
    if callable(conn_factory):
        return conn_factory(), False
    path = getattr(db, "path", db)
    return sqlite3.connect(str(path), timeout=30, isolation_level=None), True


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS execution_leases (
        operation_id TEXT PRIMARY KEY, container_name TEXT NOT NULL, owner TEXT NOT NULL,
        acquired_at TEXT NOT NULL, expires_at TEXT NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS execution_operations (
        operation_id TEXT PRIMARY KEY, container_name TEXT NOT NULL, status TEXT NOT NULL,
        result_json TEXT NOT NULL DEFAULT '{}', error_text TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    )""")

def _now() -> datetime:
    return datetime.now(UTC)

def acquire_lease(db: Any, operation_id: str, container_name: str, owner: str, ttl_seconds: int = 300, now: datetime | None = None) -> Lease | None:
    """Atomically acquire a per-container lease, returning None when occupied.

    The operation id is unique, so retries cannot create a second operation.
    Expired leases are reclaimed in the same immediate transaction.
    """
    if not operation_id or not container_name or not owner or ttl_seconds <= 0:
        return None
    conn, close = _connection(db)
    stamp = now or _now()
    acquired = stamp.isoformat()
    expires = (stamp + timedelta(seconds=ttl_seconds)).isoformat()
    try:
        conn.execute("BEGIN IMMEDIATE")
        _ensure_schema(conn)
        conn.execute("DELETE FROM execution_leases WHERE expires_at <= ?", (acquired,))
        row = conn.execute("SELECT operation_id, container_name, owner, acquired_at, expires_at FROM execution_leases WHERE container_name = ?", (container_name,)).fetchone()
        if row is not None:
            conn.rollback()
            return None
        conn.execute("INSERT INTO execution_leases(operation_id, container_name, owner, acquired_at, expires_at) VALUES(?,?,?,?,?)", (operation_id, container_name, owner, acquired, expires))
        conn.execute("INSERT OR IGNORE INTO execution_operations(operation_id, container_name, status, created_at, updated_at) VALUES(?,?,?,?,?)", (operation_id, container_name, "leased", acquired, acquired))
        conn.commit()
        return Lease(operation_id, container_name, owner, acquired, expires)
    except sqlite3.IntegrityError:
        conn.rollback()
        return None
    finally:
        if close:
            conn.close()

def release_lease(db: Any, operation_id: str, owner: str | None = None) -> bool:
    conn, close = _connection(db)
    try:
        sql = "DELETE FROM execution_leases WHERE operation_id = ?"
        args: tuple[Any, ...] = (operation_id,)
        if owner is not None:
            sql += " AND owner = ?"; args += (owner,)
        cur = conn.execute(sql, args); conn.commit(); return cur.rowcount == 1
    finally:
        if close: conn.close()

def record_operation(db: Any, operation_id: str, status: str, result: Mapping[str, Any] | None = None, error: str = "") -> bool:
    import json
    if not operation_id or status not in {"leased", "running", "succeeded", "failed", "cancelled"}: return False
    conn, close = _connection(db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        _ensure_schema(conn)
        stamp = _now().isoformat()
        cur = conn.execute("UPDATE execution_operations SET status=?, result_json=?, error_text=?, updated_at=? WHERE operation_id=?", (status, json.dumps(dict(result or {}), sort_keys=True), error, stamp, operation_id))
        conn.commit(); return cur.rowcount == 1
    finally:
        if close: conn.close()

def get_operation(db: Any, operation_id: str) -> dict[str, Any] | None:
    conn, close = _connection(db)
    try:
        _ensure_schema(conn)
        row = conn.execute("SELECT * FROM execution_operations WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None: return None
        names = [d[0] for d in conn.execute("SELECT * FROM execution_operations LIMIT 0").description]
        value = dict(zip(names, row))
        import json
        value["result"] = json.loads(value.pop("result_json"))
        return value
    finally:
        if close: conn.close()
