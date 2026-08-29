from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from unraid_updater.config import Settings
from unraid_updater.importer import import_report
from unraid_updater.web import create_app


def client(tmp_path: Path, monkeypatch=None) -> TestClient:
    settings = Settings(
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


def test_login_and_dashboard_security_headers(tmp_path: Path, monkeypatch) -> None:
    with client(tmp_path, monkeypatch) as c:
        login(c)
        response = c.get("/")
        assert response.status_code == 200
        assert "Update candidates" in response.text
        assert "1 containers visible" in response.text
        assert "Unraid inventory" in response.text
        assert response.headers["x-frame-options"] == "DENY"
        assert "default-src 'self'" in response.headers["content-security-policy"]


def test_manual_scan_uses_wud_without_legacy_state(tmp_path: Path, monkeypatch) -> None:
    with client(tmp_path, monkeypatch) as c:
        login(c)
        page = c.get("/")
        response = c.post("/scans", data={"csrf": token(page.text)}, follow_redirects=False)
        assert response.status_code == 303
        summary = c.get("/api/v1/summary").json()
        assert summary["latest_scan"]["trigger"] == "manual_wud_api"


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
