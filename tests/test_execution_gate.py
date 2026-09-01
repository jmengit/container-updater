from datetime import UTC, datetime, timedelta

from unraid_updater.execution_gate import (
    ExecutionRequest,
    acquire_lease,
    check_gate,
    get_operation,
    record_operation,
    release_lease,
)


def req(**kw):
    d = {
        "container_name": "app",
        "candidate_revision": "r1",
        "live_revision": "r1",
        "approval_id": 1,
        "approval_revision": "r1",
        "target": "image:2",
        "running": True,
    }
    d.update(kw)
    return ExecutionRequest(**d)

def test_gate_fail_closed_reasons():
    d=check_gate(ExecutionRequest(container_name="", candidate_revision="", live_revision="", target=None))
    assert not d.allowed
    assert {"missing_approval","stale_revision","not_running","unresolved_target"} <= set(d.reasons)

def test_gate_rejects_each_safety_condition():
    for field in ("approval_id","approval_revision","live_revision","running","target","hold_active","paused","self_update"):
        if field in {"approval_id", "approval_revision", "live_revision", "target"}:
            kw = {field: None}
        else:
            kw = {field: field != "running"}
        assert not check_gate(req(**kw)).allowed

def test_atomic_lease_and_idempotency(tmp_path):
    path=tmp_path/"db.sqlite"; when=datetime(2026,1,1,tzinfo=UTC)
    a=acquire_lease(path,"op-1","app","worker",60,when); assert a
    assert acquire_lease(path,"op-2","app","worker",60,when) is None
    assert acquire_lease(path,"op-1","other","worker",60,when) is None
    assert record_operation(path,"op-1","succeeded",{"changed":True})
    assert get_operation(path,"op-1")["result"]=={"changed":True}
    assert release_lease(path,"op-1","worker")

def test_expired_lease_is_reclaimed(tmp_path):
    path=tmp_path/"db.sqlite"; old=datetime(2026,1,1,tzinfo=UTC)
    assert acquire_lease(path,"old","app","w",1,old)
    assert acquire_lease(path,"new","app","w",1,old+timedelta(seconds=2))
