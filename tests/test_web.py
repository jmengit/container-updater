from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from unraid_updater.config import Settings
from unraid_updater.importer import import_report
from unraid_updater.web import create_app


def client(tmp_path: Path, monkeypatch=None, *, app_mode: str = "report_only") -> TestClient:
    settings = Settings(
        app_mode=app_mode,
        execution_confirmation=(
            "I_UNDERSTAND_CONTAINER_UPDATES_MUTATE_UNRAID"
            if app_mode == "approval_driven" else ""
        ),
        database_url=f"sqlite:///{tmp_path / 'web.db'}",
        admin_username="saturn",
        admin_password="correct horse battery staple",
        session_secret="x" * 48,
        trusted_hosts=("testserver",),
    )
    if monkeypatch is not None:
        monkeypatch.setattr("unraid_updater.web.inventory", lambda *_args: [{
            "container": "Example", "state": "running", "image": "example/app:1.0.0",
            "image_id": "sha256:1", "health": "healthy", "template_path": "/template.xml",
            "template_hash": "abc", "provider": "local", "provider_name": "Local Docker",
            "managed_by": "dockerMan",
        }])
        monkeypatch.setattr("unraid_updater.web.get_containers", lambda *_args: [])
    app = create_app(settings)
    return TestClient(app)


def token(html: str) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    assert match
    return match.group(1)


def login(c: TestClient) -> None:
    page = c.get("/login")
    response = c.post("/login", data={
        "username": "saturn", "password": "correct horse battery staple", "csrf": token(page.text)
    }, follow_redirects=False)
    assert response.status_code == 303


def test_health_is_public_and_report_only(tmp_path: Path) -> None:
    with client(tmp_path) as c:
        assert c.get("/api/v1/health").json() == {"status": "ok", "mode": "report_only"}
        assert c.get("/api/v1/summary").status_code == 401


def test_service_read_endpoints_require_authentication(tmp_path: Path) -> None:
    with client(tmp_path) as c:
        for path in ("/api/status", "/api/candidates", "/api/logs", "/api/audit"):
            assert c.get(path).status_code in {302, 401}


def test_login_and_dashboard_security_headers(tmp_path: Path, monkeypatch) -> None:
    with client(tmp_path, monkeypatch) as c:
        login(c)
        response = c.get("/")
        assert response.status_code == 200
        assert "Containers and policy" in response.text
        assert "LLM research is off" in response.text
        assert "Manual intervention queue" in response.text
        assert "Approval queue" in response.text
        assert "Example" in response.text
        assert response.headers["x-frame-options"] == "DENY"
        assert "default-src 'self'" in response.headers["content-security-policy"]


def test_policy_settings_can_save_and_reset_override(tmp_path: Path, monkeypatch) -> None:
    with client(tmp_path, monkeypatch) as c:
        login(c)
        page = c.get("/settings/policies")
        assert page.status_code == 200
        assert "Container policies" in page.text
        response = c.post("/settings/policies/container", data={
            "csrf": token(page.text), "container_name": "Example",
            "policy": "patch", "risk": "low",
        }, follow_redirects=False)
        assert response.status_code == 303
        assert c.app.state.db.policy_overrides()["Example"]["policy"] == "patch"
        page = c.get("/settings/policies")
        response = c.post("/settings/policies/container/reset", data={
            "csrf": token(page.text), "container_name": "Example",
        }, follow_redirects=False)
        assert response.status_code == 303
        assert "Example" not in c.app.state.db.policy_overrides()


def test_medium_gate_cannot_be_weakened(tmp_path: Path, monkeypatch) -> None:
    with client(tmp_path, monkeypatch) as c:
        login(c)
        page = c.get("/settings/policies")
        response = c.post("/settings/policies/gates", data={
            "csrf": token(page.text), "low_description": "low",
            "medium_description": "medium", "high_description": "high",
            "critical_description": "critical", "low_patch": "on",
        }, follow_redirects=False)
        assert response.status_code == 303
        gates = c.app.state.db.get_setting("risk_gates")
        assert gates["medium"]["manual_review"] is True
        assert gates["medium"]["allowed_changes"] == []


def test_manual_scan_uses_wud_without_legacy_state(tmp_path: Path, monkeypatch) -> None:
    with client(tmp_path, monkeypatch) as c:
        login(c)
        page = c.get("/")
        response = c.post("/scans", data={"csrf": token(page.text)}, follow_redirects=False)
        assert response.status_code == 303
        summary = c.get("/api/v1/summary").json()
        assert summary["latest_scan"]["trigger"] == "manual_wud_api"


def test_dashboard_exposes_authoritative_label_editor(tmp_path: Path, monkeypatch) -> None:
    with client(tmp_path, monkeypatch) as c:
        login(c)
        page = c.get("/")
        assert page.status_code == 200
        assert '/containers/Example/labels' in page.text
        assert "Edit labels" in page.text


def test_container_label_editor_writes_only_owned_labels(tmp_path: Path, monkeypatch) -> None:
    template = tmp_path / "example.xml"
    template.write_text(
        "<Container><Name>Example</Name><Repository>example/app:1</Repository>"
        "<Labels><Label>custom=value</Label></Labels></Container>"
    )
    settings = Settings(
        app_mode="report_only", database_url=f"sqlite:///{tmp_path / 'labels.db'}",
        admin_username="saturn", admin_password="correct horse battery staple",
        session_secret="x" * 48, trusted_hosts=("testserver",),
        docker_template_dir=str(tmp_path),
    )
    item = {
        "container": "Example", "state": "running", "image": "example/app:1",
        "image_id": "sha256:1", "health": "healthy", "template_path": str(template),
        "template_hash": "abc", "provider": "local", "provider_name": "Local Docker",
        "managed_by": "dockerMan", "labels": {"custom": "value"},
        "runtime_vnext_labels_synced": False,
    }
    monkeypatch.setattr("unraid_updater.web.inventory", lambda *_args: [item])
    monkeypatch.setattr("unraid_updater.web.get_containers", lambda *_args: [])
    with TestClient(create_app(settings)) as c:
        login(c)
        page = c.get("/containers/Example/labels")
        assert page.status_code == 200
        response = c.post("/containers/Example/labels", data={
            "csrf": token(page.text), "version": "minor", "policy": "manual",
            "research": "issues", "source": "https://github.com/example/app",
            "hold_days": "7",
        }, follow_redirects=False)
        assert response.status_code == 303
        text = template.read_text()
        assert "custom=value" in text
        assert "io.jmengit.upgrade.version=minor" in text
        assert "io.jmengit.upgrade.policy=manual" in text
        assert "io.jmengit.upgrade.research=issues" in text
        assert template.with_suffix(".xml.bak").exists()


def test_research_route_is_disabled_by_default(tmp_path: Path, monkeypatch) -> None:
    with client(tmp_path, monkeypatch) as c:
        login(c)
        db = c.app.state.db
        import_report(db, {"inventory_count": 1, "candidates": [{
            "container": "Example", "state": "running", "image": "example/app:1",
            "current_version": "1", "target": "2", "change_type": "major",
            "status": "manual_review", "reason_codes": ["major_change"],
        }]})
        page = c.get("/")
        candidate_id = db.list_candidates()[0]["id"]
        response = c.post(
            f"/candidates/{candidate_id}/research",
            data={"csrf": token(page.text), "repository": "example/project"},
        )
        assert response.status_code == 503


def test_pause_control_is_durable_and_audited(tmp_path: Path, monkeypatch) -> None:
    with client(tmp_path, monkeypatch) as c:
        login(c)
        page = c.get("/")
        response = c.post(
            "/containers/Example/pause",
            data={"csrf": token(page.text), "reason": "maintenance"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        control = c.app.state.db.container_controls()["Example"]
        assert control["paused"] == 1
        assert control["reason"] == "maintenance"


def test_login_rejects_bad_csrf(tmp_path: Path) -> None:
    with client(tmp_path) as c:
        response = c.post("/login", data={"username": "saturn", "password": "bad", "csrf": "bad"})
        assert response.status_code == 403


def test_approval_records_intent_but_has_no_execution_route(tmp_path: Path) -> None:
    with client(tmp_path) as c:
        login(c)
        db = c.app.state.db
        import_report(db, {"inventory_count": 1, "candidates": [{
            "container": "Example", "state": "running", "image": "example/app:1.0.0",
            "current": "1.0.0", "candidate": "1.0.1", "change": "patch", "policy": "minor",
            "risk": "low", "status": "approval_ready", "soak_days": 7,
        }]})
        item = db.list_candidates()[0]
        page = c.get(f"/candidates/{item['id']}")
        response = c.post(f"/candidates/{item['id']}/approve", data={
            "revision": item["revision_hash"], "csrf": token(page.text)
        }, follow_redirects=False)
        assert response.status_code == 303
        assert c.post("/api/v1/executions", json={}).status_code == 404


def test_execute_route_uses_shared_service_and_enforces_csrf(tmp_path: Path, monkeypatch) -> None:
    with client(tmp_path, monkeypatch, app_mode="approval_driven") as c:
        login(c)
        db = c.app.state.db
        import_report(db, {"candidates": [{
            "container": "Example", "state": "running", "image": "example/app:1.0.0",
            "target": "example/app:1.0.1", "change_type": "patch", "policy": "minor",
            "risk": "low", "status": "approval_ready",
        }]})
        item = db.list_candidates()[0]
        page = c.get(f"/candidates/{item['id']}")
        csrf = token(page.text)
        db.record_decision(item["id"], item["revision_hash"], "approved", "saturn")
        calls = []
        monkeypatch.setattr(
            c.app.state.service,
            "execute",
            lambda **kwargs: calls.append(kwargs) or {"status": "succeeded"},
        )
        bad = c.post(f"/candidates/{item['id']}/execute", data={
            "csrf": "bad", "revision": item["revision_hash"], "live_revision": "live-r1",
            "confirm_container": "Example",
        })
        assert bad.status_code == 403
        response = c.post(f"/candidates/{item['id']}/execute", data={
            "csrf": csrf, "revision": item["revision_hash"], "live_revision": "live-r1",
            "confirm_container": "Example",
        }, follow_redirects=False)
        assert response.status_code == 303
        assert calls[0]["candidate_id"] == item["id"]


def test_execute_route_rejects_wrong_container_confirmation(tmp_path: Path, monkeypatch) -> None:
    with client(tmp_path, monkeypatch, app_mode="approval_driven") as c:
        login(c)
        db = c.app.state.db
        import_report(db, {"candidates": [{
            "container": "Example", "state": "running", "image": "example/app:1.0.0",
            "target": "example/app:1.0.1", "change_type": "patch", "policy": "minor",
            "risk": "low", "status": "approval_ready",
        }]})
        item = db.list_candidates()[0]
        page = c.get(f"/candidates/{item['id']}")
        response = c.post(f"/candidates/{item['id']}/execute", data={
            "csrf": token(page.text), "revision": item["revision_hash"],
            "live_revision": "live-r1", "confirm_container": "Wrong",
        })
        assert response.status_code == 409


def test_stale_revision_returns_conflict(tmp_path: Path) -> None:
    with client(tmp_path) as c:
        login(c)
        db = c.app.state.db
        import_report(db, {"candidates": [{
            "container": "Example", "state": "running", "image": "example/app:1.0.0",
            "candidate": "1.0.1", "change": "patch", "policy": "minor", "risk": "low",
            "status": "approval_ready",
        }]})
        item = db.list_candidates()[0]
        page = c.get(f"/candidates/{item['id']}")
        response = c.post(f"/candidates/{item['id']}/approve", data={
            "revision": "stale", "csrf": token(page.text)
        })
        assert response.status_code == 409
