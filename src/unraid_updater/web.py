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
from .docker_runtime import ExecutionBlocked, inspect_live, inventory
from .label_edit import (
    LabelEditError,
    apply_policy_labels,
    github_source_hint,
    policy_labels,
)
from .policy_config import CHANGES, POLICIES, RISKS, normalized_gates, validate_tags
from .portainer import target_inventory
from .research import ResearchConfig, ResearchError, assess
from .scheduler import build_scheduler
from .service import ServiceError, UpdaterService
from .wud import WudError, get_containers
from .wud import scan as scan_wud

ROOT = Path(__file__).parent
TEMPLATES = Jinja2Templates(directory=ROOT / "templates")
PASSWORD_HASHER = PasswordHasher()


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


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    settings.validate_for_server()
    db = Database(settings.database_url)
    service = UpdaterService(db)
    attempts: dict[str, deque[float]] = defaultdict(deque)

    def limited(remote: str) -> bool:
        now = time.monotonic()
        queue = attempts[remote]
        while queue and now - queue[0] > 300:
            queue.popleft()
        if len(queue) >= 8:
            return True
        queue.append(now)
        return False

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

    def target_container(name: str) -> dict[str, Any]:
        matches = [row for row in target_inventory_rows() if row["container"] == name]
        if len(matches) != 1:
            raise HTTPException(status_code=404, detail="container not found")
        return matches[0]

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

    app = FastAPI(title="Container Updater", version="0.8.2", lifespan=lifespan)
    app.state.settings = settings
    app.state.db = db
    app.state.service = service

    @app.get("/api/status")
    def api_status(request: Request):
        require_auth(request)
        return JSONResponse(service.status())

    @app.get("/api/candidates")
    def api_candidates(request: Request, status_filter: str | None = None):
        require_auth(request)
        return JSONResponse(service.candidates(status_filter))

    @app.get("/api/logs")
    def api_logs(request: Request):
        require_auth(request)
        return JSONResponse(service.logs())

    @app.get("/api/audit")
    def api_audit(request: Request):
        require_auth(request)
        return JSONResponse(service.audit())

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
        candidates = [row for row in db.list_candidates() if row["status"] != "resolved"]
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
        controls = db.container_controls()
        overrides = db.policy_overrides()
        candidate_by_name = {row["container_name"]: row for row in candidates}
        wud_by_name = {str(row.get("name", "")): row for row in watched}
        policy_rows = []
        for item in target_containers:
            name = item["container"]
            labels = item.get("labels") or (wud_by_name.get(name, {}).get("labels") or {})
            owned_labels = policy_labels(labels)
            policy = labels.get("io.jmengit.upgrade.policy")
            risk = labels.get("io.jmengit.upgrade.risk")
            override = overrides.get(name)
            if override:
                policy, risk = override["policy"], override["risk"]
            candidate = candidate_by_name.get(name)
            control = controls.get(name, {})
            research = db.latest_research(candidate["id"]) if candidate else None
            policy_rows.append({
                **item, "policy": policy or "missing", "risk": risk or "missing",
                "vnext_labels": owned_labels,
                "vnext_ready": all(key in owned_labels for key in (
                    "io.jmengit.upgrade.version", "io.jmengit.upgrade.policy",
                    "io.jmengit.upgrade.research",
                )),
                "labels_missing": not policy or not risk, "policy_override": bool(override),
                "candidate": candidate, "paused": bool(control.get("paused")),
                "pause_reason": control.get("reason", ""), "research": research,
            })
        return TEMPLATES.TemplateResponse(request, "dashboard.html", {
            "user": require_auth(request), "csrf": csrf_token(request),
            "counts": db.counts(), "latest_scan": db.latest_scan(),
            "candidates": candidates, "mode": settings.app_mode,
            "target_containers": target_containers, "watched": watched,
            "target_error": target_error, "wud_error": wud_error,
            "target_type": settings.target_type,
            "template_ready": settings.target_type != "unraid" or Path(settings.docker_template_dir).is_dir(),
            "policy_rows": policy_rows, "research_enabled": settings.research_enabled,
            "research_configured": bool(
                settings.research_enabled and settings.llm_base_url and settings.llm_model
            ),
            "risk_gates": normalized_gates(db.get_setting("risk_gates", {})),
        })

    @app.get("/settings/policies", response_class=HTMLResponse)
    def policy_settings(request: Request):
        if not authenticated(request):
            return RedirectResponse("/login", status_code=303)
        return TEMPLATES.TemplateResponse(request, "policy_settings.html", {
            "csrf": csrf_token(request), "mode": settings.app_mode,
            "containers": target_inventory_rows(), "overrides": db.policy_overrides(),
            "gates": normalized_gates(db.get_setting("risk_gates", {})),
            "policies": POLICIES, "risks": RISKS, "changes": CHANGES,
        })

    @app.post("/settings/policies/container")
    def save_container_policy(
        request: Request, container_name: str = Form(), policy: str = Form(),
        risk: str = Form(), csrf: str = Form(),
    ):
        actor = require_auth(request)
        check_csrf(request, csrf)
        if container_name not in {row["container"] for row in target_inventory_rows()}:
            raise HTTPException(status_code=404, detail="container not found")
        try:
            validate_tags(policy, risk)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        db.set_policy_override(container_name, policy, risk, actor)
        try:
            scan_wud(db, wud_rows(), target_inventory_rows(), trigger="policy_changed")
        except WudError:
            pass
        return RedirectResponse("/settings/policies", status_code=303)

    @app.post("/settings/policies/gates")
    def save_risk_gates(
        request: Request, csrf: str = Form(), low_description: str = Form(),
        medium_description: str = Form(), high_description: str = Form(),
        critical_description: str = Form(), low_patch: str | None = Form(None),
        low_minor: str | None = Form(None), low_research: str | None = Form(None),
        medium_research: str | None = Form(None), high_research: str | None = Form(None),
        critical_research: str | None = Form(None),
    ):
        actor = require_auth(request)
        check_csrf(request, csrf)
        descriptions = {"low": low_description, "medium": medium_description,
                        "high": high_description, "critical": critical_description}
        research = {"low": low_research, "medium": medium_research,
                    "high": high_research, "critical": critical_research}
        value = {}
        for risk in RISKS:
            value[risk] = {
                "description": descriptions[risk],
                "allowed_changes": (["patch"] if low_patch and risk == "low" else [])
                + (["minor"] if low_minor and risk == "low" else []),
                "research_required": bool(research[risk]), "manual_review": risk != "low",
            }
        db.set_setting("risk_gates", normalized_gates(value), actor)
        try:
            scan_wud(db, wud_rows(), target_inventory_rows(), trigger="risk_gates_changed")
        except WudError:
            pass
        return RedirectResponse("/settings/policies", status_code=303)

    @app.post("/settings/policies/container/reset")
    def reset_container_policy(
        request: Request, container_name: str = Form(), csrf: str = Form(),
    ):
        actor = require_auth(request)
        check_csrf(request, csrf)
        db.remove_policy_override(container_name, actor)
        try:
            scan_wud(db, wud_rows(), target_inventory_rows(), trigger="policy_reset")
        except WudError:
            pass
        return RedirectResponse("/settings/policies", status_code=303)

    @app.get("/containers/{container_name}/labels", response_class=HTMLResponse)
    def edit_container_labels(container_name: str, request: Request):
        if not authenticated(request):
            return RedirectResponse("/login", status_code=303)
        if settings.target_type != "unraid":
            raise HTTPException(status_code=409, detail="native label editing is only available for Unraid")
        item = target_container(container_name)
        if item.get("managed_by") != "dockerMan" or not item.get("template_path"):
            raise HTTPException(status_code=409, detail="container has no unique dockerMan template")
        labels = policy_labels(item.get("labels") or {})
        hint = github_source_hint(str(item.get("image") or ""))
        source_status = (
            "explicit GitHub source configured" if labels.get("io.jmengit.upgrade.source")
            else str(hint["status"])
        )
        return TEMPLATES.TemplateResponse(request, "container_labels.html", {
            "csrf": csrf_token(request), "mode": settings.app_mode, "container": item,
            "labels": labels, "source_hint": hint, "source_status": source_status,
            "runtime_synced": bool(item.get("runtime_vnext_labels_synced")),
        })

    @app.post("/containers/{container_name}/labels")
    def save_container_labels(
        container_name: str, request: Request, csrf: str = Form(),
        version: str = Form(), policy: str = Form(), research: str = Form(),
        changelog_summary: str | None = Form(default=None),
        source: str = Form(default=""), hold_days: str = Form(default=""),
    ):
        actor = require_auth(request)
        check_csrf(request, csrf)
        if settings.target_type != "unraid":
            raise HTTPException(status_code=409, detail="native label editing is only available for Unraid")
        item = target_container(container_name)
        template_path = Path(str(item.get("template_path") or ""))
        if item.get("managed_by") != "dockerMan" or not item.get("template_path"):
            raise HTTPException(status_code=409, detail="container has no unique dockerMan template")
        desired = {
            "io.jmengit.upgrade.version": version,
            "io.jmengit.upgrade.policy": policy,
            "io.jmengit.upgrade.research": research,
            "io.jmengit.upgrade.changelog-summary": (
                "true" if changelog_summary == "true" else "false"
            ),
        }
        if source.strip():
            desired["io.jmengit.upgrade.source"] = source.strip()
        if hold_days.strip():
            desired["io.jmengit.upgrade.hold-days"] = hold_days.strip()
        try:
            LabelPolicy.from_labels(desired)
            apply_policy_labels(
                template_path, desired, template_root=Path(settings.docker_template_dir), backup=True,
            )
        except (ValueError, LabelEditError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        db.audit(actor, "container.labels.updated", "container", container_name, {
            "labels": desired, "template_path": str(template_path), "runtime_sync_required": True,
        })
        try:
            scan_wud(db, wud_rows(), target_inventory_rows(), trigger="labels_changed")
        except WudError:
            pass
        return RedirectResponse(f"/containers/{container_name}/labels?saved=1", status_code=303)

    @app.post("/containers/{container_name}/pause")
    def pause_container(
        container_name: str, request: Request, csrf: str = Form(), reason: str = Form(default="")
    ):
        actor = require_auth(request)
        check_csrf(request, csrf)
        db.set_container_paused(container_name, True, actor, reason)
        return RedirectResponse("/", status_code=303)

    @app.post("/containers/{container_name}/resume")
    def resume_container(container_name: str, request: Request, csrf: str = Form()):
        actor = require_auth(request)
        check_csrf(request, csrf)
        db.set_container_paused(container_name, False, actor)
        return RedirectResponse("/", status_code=303)

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
        labels = candidate.get("labels") or {}
        explicit_source = str(labels.get("io.jmengit.upgrade.source") or "")
        resolver_source = str((candidate.get("source") or {}).get("url", ""))
        source = explicit_source or resolver_source
        research_repository = source.removeprefix("https://github.com/").strip("/")
        source_status = (
            "explicit label" if explicit_source else
            "resolver evidence" if resolver_source else
            str(github_source_hint(str(candidate.get("image") or ""))["status"])
        )
        return TEMPLATES.TemplateResponse(request, "candidate.html", {
            "candidate": candidate, "csrf": csrf_token(request), "mode": settings.app_mode,
            "live": live, "evidence": live, "approval": approval,
            "research_enabled": settings.research_enabled,
            "research_repository": research_repository,
            "research_source_status": source_status,
            "research": db.latest_research(candidate_id),
            "research_configured": bool(
                settings.research_enabled and settings.llm_base_url and settings.llm_model
            ),
            "action_state": (
                "execute" if approval and live else
                "approve" if candidate["status"] == "approval_ready" else
                "blocked"
            ),
        })

    def decide(request: Request, candidate_id: int, revision: str, csrf: str, decision: str, reason: str):
        actor = require_auth(request)
        check_csrf(request, csrf)
        try:
            service.decide(candidate_id, revision, decision, actor, reason)
        except (ValueError, ServiceError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return RedirectResponse(f"/candidates/{candidate_id}", status_code=303)

    @app.post("/candidates/{candidate_id}/approve")
    def approve(request: Request, candidate_id: int, revision: str = Form(), csrf: str = Form()):
        candidate = service.candidate(candidate_id)
        if candidate and service.db.container_controls().get(candidate["container_name"], {}).get("paused"):
            raise HTTPException(status_code=409, detail="container is paused")
        actor = require_auth(request)
        check_csrf(request, csrf)
        try:
            service.approve(candidate_id, revision, actor)
        except ServiceError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return RedirectResponse(f"/candidates/{candidate_id}", status_code=303)

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
        candidate = service.candidate(candidate_id)
        if candidate is None:
            raise HTTPException(status_code=404, detail="candidate not found")
        if confirm_container != candidate["container_name"]:
            raise HTTPException(status_code=409, detail="container confirmation did not match")
        try:
            service.execute(
                candidate_id=candidate_id,
                revision=revision,
                live_revision=live_revision,
                actor=actor,
                socket_path=settings.docker_socket,
                template_dir=Path(settings.docker_template_dir),
                backup_root=Path(settings.docker_backup_root),
                self_name=settings.self_container_name,
            )
        except (ExecutionBlocked, RuntimeError, ServiceError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
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
        items = db.list_candidates(candidate_status)
        if candidate_status is None:
            items = [row for row in items if row["status"] != "resolved"]
        return {"items": items}

    @app.post("/scans")
    def scan(request: Request, csrf: str = Form()):
        actor = require_auth(request)
        check_csrf(request, csrf)
        result = scan_wud(db, wud_rows(), target_inventory_rows(), trigger="manual_wud_api")
        db.audit(actor, "scan.requested", "scan", "manual", {"imported": result})
        return RedirectResponse("/", status_code=303)

    @app.post("/candidates/{candidate_id}/research")
    def research_candidate(
        candidate_id: int, request: Request, repository: str = Form(), csrf: str = Form()
    ):
        actor = require_auth(request)
        check_csrf(request, csrf)
        if not settings.research_enabled:
            raise HTTPException(status_code=503, detail="research is disabled")
        candidate = db.get_candidate(candidate_id)
        if not candidate:
            raise HTTPException(status_code=404, detail="candidate not found")
        config = ResearchConfig(
            llm_base_url=settings.llm_base_url,
            llm_api_key=settings.llm_api_key,
            llm_model=settings.llm_model,
            github_token=settings.github_token,
            verify_tls=settings.research_verify_tls,
            llm_headers=tuple(
                (name, value) for name, value in (
                    ("CF-Access-Client-Id", settings.llm_cf_access_client_id),
                    ("CF-Access-Client-Secret", settings.llm_cf_access_client_secret),
                ) if value
            ),
        )
        try:
            labels = candidate.get("labels") or {}
            report = assess(
                config, repository, candidate.get("current_version") or "unknown",
                candidate.get("target") or "unknown",
                summarize_changelog=(
                    str(labels.get("io.jmengit.upgrade.changelog-summary", "false")).lower()
                    == "true"
                ),
            )
            status_value, error = "success", ""
        except ResearchError as exc:
            report, status_value, error = {}, "failed", str(exc)
        assessment_id = db.save_research(
            candidate_id, candidate["revision_hash"], repository, status_value, report, error
        )
        db.audit(actor, "research.completed", "candidate", str(candidate_id), {
            "assessment_id": assessment_id, "status": status_value, "repository": repository,
        })
        return RedirectResponse(f"/candidates/{candidate_id}", status_code=303)

    @app.get("/api/v1/candidates/{candidate_id}/research")
    def research_api(candidate_id: int, request: Request):
        require_auth(request)
        return {"item": db.latest_research(candidate_id), "advisory_only": True}

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return app
