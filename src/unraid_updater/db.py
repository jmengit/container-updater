"""Small SQLite persistence layer for scans, candidates, approvals, and audit."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS scans (
 id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT,
 trigger TEXT NOT NULL, status TEXT NOT NULL, summary_json TEXT NOT NULL DEFAULT '{}',
 error_text TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS candidates (
 id INTEGER PRIMARY KEY, container_name TEXT NOT NULL, state TEXT NOT NULL,
 current_image TEXT NOT NULL, current_version TEXT, target TEXT,
 change_type TEXT NOT NULL, policy TEXT, risk TEXT, first_seen_at TEXT,
 soak_days INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
 reason_codes_json TEXT NOT NULL DEFAULT '[]', revision_hash TEXT NOT NULL UNIQUE,
 last_scan_id INTEGER REFERENCES scans(id), updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
 id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL REFERENCES candidates(id),
 candidate_revision TEXT NOT NULL, decision TEXT NOT NULL,
 actor TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
 expires_at TEXT, revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, actor TEXT NOT NULL,
 event_type TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL,
 details_json TEXT NOT NULL, prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS executions (
 id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL REFERENCES candidates(id),
 approval_id INTEGER NOT NULL REFERENCES approvals(id), candidate_revision TEXT NOT NULL,
 live_revision TEXT NOT NULL, actor TEXT NOT NULL, status TEXT NOT NULL,
 started_at TEXT NOT NULL, finished_at TEXT, result_json TEXT NOT NULL DEFAULT '{}',
 error_text TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS research_assessments (
 id INTEGER PRIMARY KEY, candidate_id INTEGER NOT NULL REFERENCES candidates(id),
 candidate_revision TEXT NOT NULL, repository TEXT NOT NULL,
 status TEXT NOT NULL, report_json TEXT NOT NULL DEFAULT '{}',
 error_text TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS container_controls (
 container_name TEXT PRIMARY KEY, paused INTEGER NOT NULL DEFAULT 0,
 reason TEXT NOT NULL DEFAULT '', actor TEXT NOT NULL,
 updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates(status);
CREATE INDEX IF NOT EXISTS idx_approvals_candidate ON approvals(candidate_id, created_at);
"""


def utcnow() -> str:
    return datetime.now(UTC).isoformat()


def sqlite_path(database_url: str) -> Path:
    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        raise ValueError("Only sqlite:/// DATABASE_URL values are supported in v1")
    return Path(database_url[len(prefix) :])


class Database:
    def __init__(self, database_url: str) -> None:
        self.path = sqlite_path(database_url)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    def start_scan(self, trigger: str) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO scans(started_at,trigger,status) VALUES(?,?,?)",
                (utcnow(), trigger, "running"),
            )
            return int(cursor.lastrowid)

    def finish_scan(self, scan_id: int, status: str, summary: dict[str, Any], error: str = "") -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE scans SET finished_at=?, status=?, summary_json=?, error_text=? WHERE id=?",
                (utcnow(), status, json.dumps(summary, sort_keys=True), error, scan_id),
            )

    def upsert_candidate(self, item: dict[str, Any], scan_id: int) -> int:
        revision = item.get("revision_hash") or hashlib.sha256(
            json.dumps(
                {
                    "container": item.get("container"),
                    "current_image": item.get("image") or item.get("current_image"),
                    "candidate": item.get("candidate") or item.get("target"),
                    "policy": item.get("policy"),
                    "risk": item.get("risk"),
                    "status": item.get("status"),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        values = (
            item.get("container", "unknown"), item.get("state", "unknown"),
            item.get("image") or item.get("current_image", ""), item.get("current"),
            item.get("candidate") or item.get("target"), item.get("change", "unknown"),
            item.get("policy"), item.get("risk"), item.get("first_seen"),
            int(item.get("soak_days", 0) or 0), item.get("status", "unresolved"),
            json.dumps(item.get("reason_codes") or item.get("reasons") or []), revision,
            scan_id, utcnow(),
        )
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO candidates(container_name,state,current_image,current_version,target,
                change_type,policy,risk,first_seen_at,soak_days,status,reason_codes_json,
                revision_hash,last_scan_id,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(revision_hash) DO UPDATE SET last_scan_id=excluded.last_scan_id,
                state=excluded.state, current_image=excluded.current_image,
                current_version=excluded.current_version, target=excluded.target,
                change_type=excluded.change_type, policy=excluded.policy, risk=excluded.risk,
                first_seen_at=excluded.first_seen_at, soak_days=excluded.soak_days,
                status=excluded.status, reason_codes_json=excluded.reason_codes_json,
                updated_at=excluded.updated_at""", values,
            )
            row = connection.execute(
                "SELECT id FROM candidates WHERE revision_hash=?", (revision,)
            ).fetchone()
            return int(row["id"])

    def list_candidates(self, status: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM candidates"
        args: tuple[Any, ...] = ()
        if status:
            sql += " WHERE status=?"
            args = (status,)
        sql += " ORDER BY updated_at DESC, container_name"
        with self.connect() as connection:
            rows = connection.execute(sql, args).fetchall()
        return [self._candidate(dict(row)) for row in rows]

    def get_candidate(self, candidate_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM candidates WHERE id=?", (candidate_id,)).fetchone()
        return self._candidate(dict(row)) if row else None

    @staticmethod
    def _candidate(row: dict[str, Any]) -> dict[str, Any]:
        row["reason_codes"] = json.loads(row.pop("reason_codes_json", "[]"))
        return row

    def record_decision(
        self, candidate_id: int, revision: str, decision: str, actor: str, reason: str = ""
    ) -> int:
        if decision not in {"approved", "deferred", "revoked"}:
            raise ValueError("invalid decision")
        candidate = self.get_candidate(candidate_id)
        if not candidate or candidate["revision_hash"] != revision:
            raise ValueError("candidate changed; refresh before deciding")
        if decision == "approved" and candidate["status"] != "approval_ready":
            raise ValueError("candidate is not approval-ready")
        expires = (datetime.now(UTC) + timedelta(hours=24)).isoformat() if decision == "approved" else None
        with self.connect() as connection:
            cursor = connection.execute(
                """INSERT INTO approvals(candidate_id,candidate_revision,decision,actor,reason,
                created_at,expires_at) VALUES(?,?,?,?,?,?,?)""",
                (candidate_id, revision, decision, actor, reason[:500], utcnow(), expires),
            )
            approval_id = int(cursor.lastrowid)
        self.audit(actor, f"candidate.{decision}", "candidate", str(candidate_id), {
            "candidate_revision": revision, "approval_id": approval_id, "reason": reason[:500]
        })
        return approval_id

    def active_approval(self, candidate_id: int, revision: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """SELECT * FROM approvals WHERE candidate_id=? AND candidate_revision=?
                AND decision='approved' AND revoked_at IS NULL AND expires_at > ?
                ORDER BY id DESC LIMIT 1""",
                (candidate_id, revision, utcnow()),
            ).fetchone()
        return dict(row) if row else None

    def save_research(
        self, candidate_id: int, revision: str, repository: str,
        status: str, report: dict[str, Any], error: str = "",
    ) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """INSERT INTO research_assessments(candidate_id,candidate_revision,
                repository,status,report_json,error_text,created_at) VALUES(?,?,?,?,?,?,?)""",
                (candidate_id, revision, repository, status, json.dumps(report), error[:1000], utcnow()),
            )
        return int(cursor.lastrowid)

    def latest_research(self, candidate_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM research_assessments WHERE candidate_id=? ORDER BY id DESC LIMIT 1",
                (candidate_id,),
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["report"] = json.loads(result.pop("report_json"))
        return result

    def set_container_paused(
        self, container_name: str, paused: bool, actor: str, reason: str = ""
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO container_controls(container_name,paused,reason,actor,updated_at)
                VALUES(?,?,?,?,?) ON CONFLICT(container_name) DO UPDATE SET
                paused=excluded.paused,reason=excluded.reason,actor=excluded.actor,
                updated_at=excluded.updated_at""",
                (container_name, int(paused), reason[:500], actor, utcnow()),
            )
        self.audit(
            actor, "container.paused" if paused else "container.resumed",
            "container", container_name, {"reason": reason[:500]},
        )

    def container_controls(self) -> dict[str, dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM container_controls").fetchall()
        return {str(row["container_name"]): dict(row) for row in rows}

    def start_execution(
        self, candidate_id: int, approval_id: int, revision: str,
        live_revision: str, actor: str,
    ) -> int:
        with self.connect() as connection:
            running = connection.execute(
                "SELECT id FROM executions WHERE candidate_id=? AND status='running'",
                (candidate_id,),
            ).fetchone()
            if running:
                raise ValueError("an execution is already running for this candidate")
            cursor = connection.execute(
                """INSERT INTO executions(candidate_id,approval_id,candidate_revision,
                live_revision,actor,status,started_at) VALUES(?,?,?,?,?,'running',?)""",
                (candidate_id, approval_id, revision, live_revision, actor, utcnow()),
            )
            return int(cursor.lastrowid)

    def finish_execution(
        self, execution_id: int, status: str, result: dict[str, Any], error: str = ""
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """UPDATE executions SET status=?,finished_at=?,result_json=?,error_text=?
                WHERE id=?""",
                (status, utcnow(), json.dumps(result, sort_keys=True), error, execution_id),
            )

    def audit(self, actor: str, event_type: str, entity_type: str, entity_id: str, details: dict[str, Any]) -> None:
        occurred = utcnow()
        payload = json.dumps(details, sort_keys=True, separators=(",", ":"))
        with self.connect() as connection:
            row = connection.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
            previous = row["event_hash"] if row else ""
            event_hash = hashlib.sha256(
                f"{previous}|{occurred}|{actor}|{event_type}|{entity_type}|{entity_id}|{payload}".encode()
            ).hexdigest()
            connection.execute(
                """INSERT INTO audit_events(occurred_at,actor,event_type,entity_type,
                entity_id,details_json,prev_hash,event_hash) VALUES(?,?,?,?,?,?,?,?)""",
                (occurred, actor, event_type, entity_type, entity_id, payload, previous, event_hash),
            )

    def latest_scan(self) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return None
        result = dict(row)
        result["summary"] = json.loads(result.pop("summary_json", "{}"))
        return result

    def counts(self) -> dict[str, int]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT status, COUNT(*) count FROM candidates GROUP BY status"
            ).fetchall()
        return {row["status"]: int(row["count"]) for row in rows}
