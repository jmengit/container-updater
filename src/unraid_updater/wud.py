"""WUD REST API client and conservative candidate normalization."""
from __future__ import annotations

import base64
import json
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .db import Database


class WudError(RuntimeError):
    """A bounded WUD request or response failed."""


def get_containers(
    base_url: str,
    username: str = "",
    password: str = "",
    verify_tls: bool = True,
) -> list[dict[str, Any]]:
    """Read watched containers from WUD's documented REST API."""
    url = f"{base_url.rstrip('/')}/api/containers"
    if not url.startswith(("http://", "https://")):
        raise WudError("WUD_URL must be http:// or https://")
    headers = {"Accept": "application/json"}
    if username or password:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    context = None if verify_tls else ssl._create_unverified_context()
    try:
        with urlopen(Request(url, headers=headers), timeout=30, context=context) as response:
            payload = json.load(response)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise WudError(f"WUD request failed: {exc}") from exc
    if isinstance(payload, dict):
        payload = payload.get("data", payload)
    if not isinstance(payload, list):
        raise WudError("WUD /api/containers did not return an array")
    return payload


def _target_image(current_image: str, remote_tag: str | None) -> str:
    if not remote_tag:
        return ""
    repository = current_image.rsplit("@", 1)[0]
    last_slash = repository.rfind("/")
    if repository.rfind(":") > last_slash:
        repository = repository[: repository.rfind(":")]
    return f"{repository}:{remote_tag}"


def normalize(
    raw: dict[str, Any], live_by_name: dict[str, dict[str, Any]], paused: bool = False
) -> dict[str, Any]:
    """Normalize WUD state while keeping unlabeled/risky updates manual."""
    name = str(raw.get("name") or raw.get("displayName") or "unknown")
    live = live_by_name.get(name, {})
    image = raw.get("image") or {}
    tag = image.get("tag") or {}
    kind = raw.get("updateKind") or {}
    result = raw.get("result") or {}
    # dockerMan template labels are authoritative desired state. WUD may still
    # expose stale runtime labels until a container has been recreated.
    labels = {**(raw.get("labels") or {}), **(live.get("labels") or {})}
    change = str(kind.get("semverDiff") or kind.get("kind") or "unknown")
    policy = str(labels.get("io.jmengit.upgrade.policy", "manual"))
    risk = str(labels.get("io.jmengit.upgrade.risk", "medium"))
    running = str(raw.get("status", live.get("state", "unknown"))) == "running"
    available = raw.get("updateAvailable") is True
    remote_tag = result.get("tag") if kind.get("kind") == "tag" else None
    current_image = str(live.get("image") or "")
    target = _target_image(current_image, str(remote_tag) if remote_tag else None)
    eligible = (
        available
        and running
        and change in {"patch", "minor"}
        and policy in {"patch", "minor"}
        and risk == "low"
        and bool(target)
        and not paused
    )
    reasons: list[str] = []
    if not available:
        reasons.append("no_update")
    if not running:
        reasons.append("not_running")
    if change not in {"patch", "minor"}:
        reasons.append(f"change_{change}")
    if policy not in {"patch", "minor"}:
        reasons.append(f"policy_{policy}")
    if risk != "low":
        reasons.append(f"risk_{risk}")
    if available and not target:
        reasons.append("digest_or_unresolved_target")
    if paused:
        reasons.append("paused_by_user")
    return {
        "container": name,
        "state": str(raw.get("status", live.get("state", "unknown"))),
        "image": current_image,
        "current": str(tag.get("value") or kind.get("localValue") or ""),
        "candidate": target or str(result.get("tag") or result.get("digest") or kind.get("remoteValue") or ""),
        "change": change,
        "policy": policy,
        "risk": risk,
        "status": "approval_ready" if eligible else "manual_review",
        "reason_codes": reasons,
        "wud_id": str(raw.get("id", "")),
        "labels": labels,
    }


def scan(
    db: Database,
    containers: list[dict[str, Any]],
    live: list[dict[str, Any]],
    trigger: str = "wud_api",
) -> dict[str, int]:
    """Persist one WUD snapshot as candidate state."""
    scan_id = db.start_scan(trigger)
    live_by_name = {str(item["container"]): item for item in live}
    imported = 0
    updates = 0
    try:
        for raw in containers:
            if raw.get("updateAvailable") is not True:
                continue
            item = normalize(
                raw, live_by_name,
                bool(db.container_controls().get(str(raw.get("name", "")), {}).get("paused")),
            )
            db.upsert_candidate(item, scan_id)
            imported += 1
            updates += 1
        summary = {"imported": imported, "inventory_count": len(containers), "updates": updates}
        db.finish_scan(scan_id, "success", summary)
        db.audit("system", "scan.wud", "scan", str(scan_id), summary)
        return summary
    except Exception as exc:
        db.finish_scan(scan_id, "failed", {"imported": imported}, str(exc))
        raise
