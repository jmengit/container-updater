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
from .importer import import_latest
from .scheduler import build_scheduler

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

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        db.initialize()
        if settings.legacy_state_dir and db.latest_scan() is None:
            import_latest(db, settings.legacy_state_dir)
        scheduler = build_scheduler(
            db, settings.legacy_state_dir, settings.scan_cron, settings.timezone
        )
        if scheduler:
            scheduler.start()
        try:
            yield
        finally:
            if scheduler:
                scheduler.shutdown(wait=False)

    app = FastAPI(title="Unraid Container Updater", version="0.1.0", lifespan=lifespan)
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
        return TEMPLATES.TemplateResponse(request, "dashboard.html", {
            "user": require_auth(request), "csrf": csrf_token(request),
            "counts": db.counts(), "latest_scan": db.latest_scan(),
            "candidates": candidates, "mode": settings.app_mode,
        })

    @app.get("/candidates/{candidate_id}", response_class=HTMLResponse)
    def candidate_page(request: Request, candidate_id: int):
        if not authenticated(request):
            return RedirectResponse("/login", status_code=303)
        candidate = db.get_candidate(candidate_id)
        if not candidate:
            raise HTTPException(status_code=404, detail="candidate not found")
        return TEMPLATES.TemplateResponse(request, "candidate.html", {
            "candidate": candidate, "csrf": csrf_token(request), "mode": settings.app_mode,
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

    @app.get("/api/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": settings.app_mode}

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
        result = import_latest(db, settings.legacy_state_dir) if settings.legacy_state_dir else None
        db.audit(actor, "scan.requested", "scan", "manual", {"imported": result})
        return RedirectResponse("/", status_code=303)

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app
