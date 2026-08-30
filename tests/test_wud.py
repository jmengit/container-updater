from __future__ import annotations

from unraid_updater.wud import normalize, scan


def live() -> dict:
    return {
        "container": "Example", "state": "running", "image": "example/app:1.2.3",
        "image_id": "sha256:local", "template_path": "/template.xml",
        "template_hash": "abc", "managed_by": "dockerMan",
    }


def wud(change: str = "patch", policy: str = "patch", risk: str = "low") -> dict:
    return {
        "id": "wud-id", "name": "Example", "status": "running",
        "image": {"tag": {"value": "1.2.3"}}, "updateAvailable": True,
        "updateKind": {"kind": "tag", "localValue": "1.2.3", "remoteValue": "1.2.4", "semverDiff": change},
        "result": {"tag": "1.2.4"},
        "labels": {"io.jmengit.upgrade.policy": policy, "io.jmengit.upgrade.risk": risk},
    }


def test_wud_tag_candidate_uses_live_repository() -> None:
    item = normalize(wud(), {"Example": live()})
    assert item["candidate"] == "example/app:1.2.4"
    assert item["status"] == "approval_ready"


def test_template_policy_labels_override_stale_wud_runtime_labels() -> None:
    raw = wud(policy="manual", risk="medium")
    local = live()
    local["labels"] = {
        "io.jmengit.upgrade.policy": "patch",
        "io.jmengit.upgrade.risk": "low",
    }
    item = normalize(raw, {"Example": local})
    assert item["policy"] == "patch"
    assert item["risk"] == "low"
    assert item["status"] == "approval_ready"


def test_unlabeled_and_digest_updates_are_manual() -> None:
    raw = wud(); raw["labels"] = {}; raw["updateKind"] = {
        "kind": "digest", "localValue": "sha256:old", "remoteValue": "sha256:new", "semverDiff": None,
    }; raw["result"] = {"digest": "sha256:new"}
    item = normalize(raw, {"Example": live()})
    assert item["status"] == "manual_review"
    assert "digest_or_unresolved_target" in item["reason_codes"]


def test_paused_container_is_never_approval_ready() -> None:
    item = normalize(wud(), {"Example": live()}, paused=True)
    assert item["status"] == "manual_review"
    assert "paused_by_user" in item["reason_codes"]


def test_browser_override_and_gate_control_classification() -> None:
    item = normalize(
        wud(policy="manual", risk="medium"), {"Example": live()},
        override={"policy": "minor", "risk": "low"},
        gates={"low": {"allowed_changes": ["patch"], "manual_review": False,
                        "research_required": False}},
    )
    assert item["policy"] == "minor"
    assert item["risk"] == "low"
    assert item["status"] == "approval_ready"


def test_research_gate_prevents_approval_ready() -> None:
    item = normalize(
        wud(), {"Example": live()},
        gates={"low": {"allowed_changes": ["patch"], "manual_review": False,
                        "research_required": True}},
    )
    assert item["status"] == "manual_review"
    assert "research_required" in item["reason_codes"]


def test_only_update_available_rows_become_candidates(tmp_path) -> None:
    from unraid_updater.db import Database
    db = Database(f"sqlite:///{tmp_path / 'wud.db'}"); db.initialize()
    no_update = wud(); no_update["name"] = "Other"; no_update["updateAvailable"] = False
    summary = scan(db, [wud(), no_update], [live()])
    assert summary == {"imported": 1, "inventory_count": 2, "updates": 1, "resolved": 0}
    assert len(db.list_candidates()) == 1
