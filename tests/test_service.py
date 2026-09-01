from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from unraid_updater.db import Database
from unraid_updater.execution_gate import acquire_lease, get_operation
from unraid_updater.service import MutationUnavailable, ServiceConfig, ServiceError, UpdaterService


def raw(name: str = "app") -> dict:
    return {
        "name": name,
        "status": "running",
        "updateAvailable": True,
        "labels": {
            "io.jmengit.upgrade.version": "patch",
            "io.jmengit.upgrade.policy": "manual",
            "io.jmengit.upgrade.research": "none",
        },
        "image": {"tag": {"value": "1.0.0"}},
        "updateKind": {"kind": "tag", "semverDiff": "patch"},
        "result": {"tag": "1.0.1"},
    }


def test_reconcile_persists_candidate_and_projection(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    service = UpdaterService(db, ServiceConfig(evidence_root=tmp_path / "evidence"))
    result = service.reconcile_rows([raw()], [{"container": "app", "state": "running", "image": "repo/app:1.0.0"}])
    assert result["imported"] == 1
    assert len(service.candidates()) == 1
    assert (tmp_path / "evidence" / "scans" / f"{result['scan_id']}.json").exists()
    assert service.status()["scan"]["status"] == "success"
    assert service.logs()


def test_reconcile_resolves_candidates_missing_from_successful_scan(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    service = UpdaterService(db)
    service.reconcile_rows([raw()], [{"container": "app", "state": "running", "image": "repo/app:1.0.0"}])
    result = service.reconcile_rows([], [{"container": "app", "state": "running", "image": "repo/app:1.0.0"}])
    assert result["resolved"] == 1
    assert service.candidates()[0]["status"] == "resolved"


def test_evaluate_candidate_writes_hold_and_is_fail_closed_for_mutation(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    service = UpdaterService(db, ServiceConfig(evidence_root=tmp_path / "evidence"))
    service.reconcile_rows([raw()], [{"container": "app", "state": "running", "image": "repo/app:1.0.0"}])
    candidate = service.candidates()[0]
    result = service.evaluate_candidate(
        candidate["id"],
        line_release_at=datetime.now(UTC) - timedelta(days=10),
        target_release_at=datetime.now(UTC) - timedelta(days=3),
    )
    assert result["hold"]["change_class"] == "patch"
    try:
        service.execute(candidate["id"])
    except MutationUnavailable:
        pass
    else:
        raise AssertionError("execution unexpectedly became available")


def test_decision_is_revision_bound(tmp_path: Path) -> None:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    service = UpdaterService(db)
    service.reconcile_rows([raw()], [{"container": "app", "state": "running", "image": "repo/app:1.0.0"}])
    candidate = service.candidates()[0]
    try:
        service.decide(candidate["id"], "wrong", "approved", "saturn")
    except ServiceError as exc:
        assert "stale" in str(exc)
    else:
        raise AssertionError("stale decision unexpectedly succeeded")


def ready_service(tmp_path: Path) -> tuple[UpdaterService, dict]:
    db = Database(f"sqlite:///{tmp_path / 'db.sqlite'}")
    service = UpdaterService(db)
    service.reconcile_rows(
        [raw()], [{"container": "app", "state": "running", "image": "repo/app:1.0.0"}]
    )
    candidate = service.candidates()[0]
    with db.connect() as connection:
        connection.execute(
            "UPDATE candidates SET status='approval_ready' WHERE id=?", (candidate["id"],)
        )
    candidate = service.candidate(candidate["id"])
    assert candidate
    service.decide(candidate["id"], candidate["revision_hash"], "approved", "saturn")
    return service, candidate


def test_execute_is_idempotent_and_records_result(tmp_path: Path, monkeypatch) -> None:
    service, candidate = ready_service(tmp_path)
    calls = []
    monkeypatch.setattr(
        "unraid_updater.service.execute_update",
        lambda **kwargs: calls.append(kwargs) or {"status": "succeeded", "target": kwargs["target_image"]},
    )
    kwargs = {
        "candidate_id": candidate["id"],
        "revision": candidate["revision_hash"],
        "live_revision": "live-r1",
        "actor": "saturn",
        "socket_path": "socket",
        "template_dir": tmp_path,
        "backup_root": tmp_path / "backup",
    }
    first = service.execute(**kwargs)
    second = service.execute(**kwargs)
    assert first == second
    assert len(calls) == 1
    with service.db.connect() as connection:
        execution = connection.execute(
            "SELECT status FROM executions WHERE candidate_id=?", (candidate["id"],)
        ).fetchone()
    assert execution["status"] == "succeeded"


def test_execute_rejects_paused_and_active_lease(tmp_path: Path, monkeypatch) -> None:
    service, candidate = ready_service(tmp_path)
    service.db.set_container_paused("app", True, "saturn")
    common = {
        "candidate_id": candidate["id"], "revision": candidate["revision_hash"],
        "live_revision": "live-r1", "actor": "saturn", "socket_path": "socket",
        "template_dir": tmp_path, "backup_root": tmp_path / "backup",
    }
    try:
        service.execute(**common)
    except ServiceError as exc:
        assert "paused_container" in str(exc)
    else:
        raise AssertionError("paused execution unexpectedly succeeded")
    service.db.set_container_paused("app", False, "saturn")
    assert acquire_lease(service.db.path, "other-op", "app", "other")
    monkeypatch.setattr("unraid_updater.service.execute_update", lambda **_kwargs: {})
    try:
        service.execute(**common)
    except ServiceError as exc:
        assert "already in progress" in str(exc)
    else:
        raise AssertionError("concurrent execution unexpectedly succeeded")
    assert get_operation(service.db.path, "other-op")["status"] == "leased"
