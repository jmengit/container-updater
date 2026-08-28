from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from unraid_updater.config import Settings
from unraid_updater.importer import import_report
from unraid_updater.web import create_app


def client(tmp_path: Path) -> TestClient:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'web.db'}",
        admin_username="saturn",
        admin_password="correct horse battery staple",
        session_secret="x" * 48,
        trusted_hosts=("testserver",),
    )
    return TestClient(create_app(settings))


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


def test_login_and_dashboard_security_headers(tmp_path: Path) -> None:
    with client(tmp_path) as c:
        login(c)
        response = c.get("/")
        assert response.status_code == 200
        assert "Nothing needs approval" in response.text
        assert response.headers["x-frame-options"] == "DENY"
        assert "default-src 'self'" in response.headers["content-security-policy"]


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
