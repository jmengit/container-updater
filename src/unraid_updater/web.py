"""Authenticated report-only FastAPI UI and JSON API."""
from __future__ import annotations

import hmac
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import Settings
from .db import Database
from .docker_runtime import (
    ExecutionBlocked,
    execute_update,
    inspect_live,
    inventory,
    target_repository,
)
from .portainer import target_inventory
from .scheduler import build_scheduler
from .wud import WudError, get_containers
from .wud import scan as scan_wud

ROOT = Path(__file__).parent
TEMPLATES = Jinja2Templates(directory=ROOT / "templates")
PASSWORD_HASHER = PasswordHasher()
ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return str(token)


def authenticated(request: Request) -> bool:
    return request.session.get("user") is not None


def require_auth(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    return str(user)


def check_csrf(request: Request, supplied: str) -> None:
    expected = str(request.session.get("csrf", ""))
    if not expected or not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=403, detail="invalid CSRF token")


def verify_password(configured: str, supplied: str) -> bool:
    if configured.startswith("$argon2"):
        try:
            return PASSWORD_HASHER.verify(configured, supplied)
        except VerificationError:
            return False
    return hmac.compare_digest(configured, supplied)


def limited(remote: str) -> bool:
    now = time.monotonic()
    queue = ATTEMPTS[remote]
    while queue and now - queue[0] > 300:
        queue.popleft()
    if len(queue) >= 8:
        return True
    queue.append(now)
    return False


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate_for_server()
    db = Database(settings.database_url)

    def target_inventory_rows() -> list[dict[str, Any]]:
        if settings.target_type == "unraid":
            return inventory(
                settings.docker_socket,
                settings.self_container_name,
                Path(settings.docker_template_dir),
            )
        return target_inventory(
            settings.portainer_url,
            settings.portainer_token,
            settings.portainer_endpoint_id,
        )

    def wud_rows() -> list[dict[str, Any]]:
        return get_containers(
            settings.wud_url,
            settings.wud_username,
            settings.wud_password,
            settings.wud_verify_tls,
        )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        db.initialize()
        scheduler = build_scheduler(
            db, wud_rows, target_inventory_rows, settings.scan_cron, settings.timezone
        )
        scheduler.start()
        try:
            yield
        finally:
            scheduler.shutdown(wait=False)

    app = FastAPI(title="Container Updater", version="0.4.1", lifespan=lifespan)
    app.state.settings = settings
    app.state.db = db
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.trusted_hosts))
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret,
        same_site="strict",
        https_only=settings.app_base_url.startswith("https://"),
        max_age=3600,
    )
    app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.update({
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'self'; style-src 'self'; script-src 'self'",
            "Cache-Control": "no-store",
        })
        return response

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        if authenticated(request):
            return RedirectResponse("/", status_code=303)
        return TEMPLATES.TemplateResponse(request, "login.html", {"csrf": csrf_token(request)})

    @app.post("/login")
    def login(request: Request, username: str = Form(), password: str = Form(), csrf: str = Form()):
        check_csrf(request, csrf)
        remote = request.client.host if request.client else "unknown"
        if limited(remote):
            raise HTTPException(status_code=429, detail="too many login attempts")
        if not hmac.compare_digest(username, settings.admin_username) or not verify_password(
            settings.admin_password, password
        ):
            db.audit("anonymous", "auth.failed", "session", remote, {})
            raise HTTPException(status_code=401, detail="invalid credentials")
        request.session.clear()
        request.session.update({"user": username, "csrf": secrets.token_urlsafe(32)})
        db.audit(username, "auth.login", "session", remote, {})
        return RedirectResponse("/", status_code=303)

    @app.post("/logout")
    def logout(request: Request, csrf: str = Form()):
        user = require_auth(request)
        check_csrf(request, csrf)
        request.session.clear()
        db.audit(user, "auth.logout", "session", "current", {})
        return RedirectResponse("/login", status_code=303)

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        if not authenticated(request):
            return RedirectResponse("/login", status_code=303)
        candidates = db.list_candidates()
        target_error = ""
        wud_error = ""
        try:
            target_containers = target_inventory_rows()
        except (OSError, RuntimeError) as exc:
            target_containers = []
            target_error = str(exc)
        try:
            watched = wud_rows()
        except WudError as exc:
            watched = []
            wud_error = str(exc)
        return TEMPLATES.TemplateResponse(request, "dashboard.html", {
            "user": require_auth(request), "csrf": csrf_token(request),
            "counts": db.counts(), "latest_scan": db.latest_scan(),
            "candidates": candidates, "mode": settings.app_mode,
            "target_containers": target_containers, "watched": watched,
            "target_error": target_error, "wud_error": wud_error,
            "target_type": settings.target_type,
            "template_ready": settings.target_type != "unraid" or Path(settings.docker_template_dir).is_dir(),
        })

    @app.get("/candidates/{candidate_id}", response_class=HTMLResponse)
    def candidate_page(request: Request, candidate_id: int):
        if not authenticated(request):
            return RedirectResponse("/login", status_code=303)
        candidate = db.get_candidate(candidate_id)
        if not candidate:
            raise HTTPException(status_code=404, detail="candidate not found")
        live = None
        approval = db.active_approval(candidate_id, candidate["revision_hash"])
        if settings.app_mode == "approval_driven" and candidate["status"] == "approval_ready":
            try:
                live = inspect_live(
                    candidate["container_name"], settings.docker_socket,
                    Path(settings.docker_template_dir),
                )
            except ExecutionBlocked:
                live = None
        return TEMPLATES.TemplateResponse(request, "candidate.html", {
            "candidate": candidate, "csrf": csrf_token(request), "mode": settings.app_mode,
            "live": live, "approval": approval,
        })

    def decide(request: Request, candidate_id: int, revision: str, csrf: str, decision: str, reason: str):
        actor = require_auth(request)
        check_csrf(request, csrf)
        try:
            db.record_decision(candidate_id, revision, decision, actor, reason)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return RedirectResponse(f"/candidates/{candidate_id}", status_code=303)

    @app.post("/candidates/{candidate_id}/approve")
    def approve(request: Request, candidate_id: int, revision: str = Form(), csrf: str = Form()):
        return decide(request, candidate_id, revision, csrf, "approved", "")

    @app.post("/candidates/{candidate_id}/defer")
    def defer(
        request: Request, candidate_id: int, revision: str = Form(),
        csrf: str = Form(), reason: str = Form(default="")
    ):
        return decide(request, candidate_id, revision, csrf, "deferred", reason)

    @app.post("/candidates/{candidate_id}/execute")
    def execute_candidate(
        request: Request,
        candidate_id: int,
        csrf: str = Form(...),
        revision: str = Form(...),
        live_revision: str = Form(...),
        confirm_container: str = Form(...),
    ):
        actor = require_auth(request)
        check_csrf(request, csrf)
        if settings.app_mode != "approval_driven":
            raise HTTPException(status_code=409, detail="Execution is disabled")
        candidate = db.get_candidate(candidate_id)
        if candidate is None:
            raise HTTPException(status_code=404, detail="candidate not found")
        if candidate["revision_hash"] != revision:
            raise HTTPException(status_code=409, detail="candidate revision changed")
        if candidate["status"] != "approval_ready":
            raise HTTPException(status_code=409, detail="candidate is not approval-ready")
        if candidate["risk"] != "low" or candidate["change_type"] not in {"patch", "minor"}:
            raise HTTPException(status_code=409, detail="only low-risk patch/minor execution is allowed")
        if candidate["state"] != "running":
            raise HTTPException(status_code=409, detail="stopped containers are never updated")
        if confirm_container != candidate["container_name"]:
            raise HTTPException(status_code=409, detail="container confirmation did not match")
        approval = db.active_approval(candidate_id, revision)
        if approval is None:
            raise HTTPException(status_code=409, detail="a current approval is required")
        evidence = inspect_live(
            candidate["container_name"], settings.docker_socket,
            Path(settings.docker_template_dir),
        )
        if evidence.revision != live_revision:
            raise HTTPException(status_code=409, detail="live evidence changed; review again")
        target = target_repository(candidate["current_image"], candidate["target"])
        execution_id = db.start_execution(
            candidate_id, approval["id"], revision, live_revision, actor
        )
        try:
            result = execute_update(
                name=candidate["container_name"], target_image=target,
                expected_live_revision=live_revision,
                socket_path=settings.docker_socket,
                template_dir=Path(settings.docker_template_dir),
                backup_root=Path(settings.docker_backup_root),
                self_name=settings.self_container_name,
            )
        except (ExecutionBlocked, RuntimeError) as exc:
            db.finish_execution(execution_id, "failed", {}, str(exc))
            db.audit(actor, "execution.failed", "candidate", str(candidate_id), {
                "execution_id": execution_id, "error": str(exc), "target": target
            })
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        db.finish_execution(execution_id, "succeeded", result)
        db.audit(actor, "execution.succeeded", "candidate", str(candidate_id), {
            "execution_id": execution_id, **result
        })
        return RedirectResponse(f"/candidates/{candidate_id}", status_code=303)

    @app.get("/api/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": settings.app_mode}

    @app.get("/api/v1/inventory")
    def inventory_api(request: Request):
        require_auth(request)
        if settings.app_mode != "approval_driven":
            raise HTTPException(status_code=409, detail="Docker inventory is disabled")
        return {"containers": inventory(
            settings.docker_socket,
            settings.self_container_name,
            Path(settings.docker_template_dir),
        )}

    @app.get("/api/v1/fleet")
    def fleet_api(request: Request):
        require_auth(request)
        return {"target_type": settings.target_type, "containers": target_inventory_rows(), "wud": wud_rows()}

    @app.get("/api/v1/summary")
    def summary(request: Request) -> dict[str, Any]:
        require_auth(request)
        return {"mode": settings.app_mode, "counts": db.counts(), "latest_scan": db.latest_scan()}

    @app.get("/api/v1/candidates")
    def candidates_api(request: Request, candidate_status: str | None = None):
        require_auth(request)
        return {"items": db.list_candidates(candidate_status)}

    @app.post("/scans")
    def scan(request: Request, csrf: str = Form()):
        actor = require_auth(request)
        check_csrf(request, csrf)
        result = scan_wud(db, wud_rows(), target_inventory_rows(), trigger="manual_wud_api")
        db.audit(actor, "scan.requested", "scan", "manual", {"imported": result})
        return RedirectResponse("/", status_code=303)

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app
