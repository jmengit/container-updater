"""Read-only inventory adapter for remote Portainer environments."""
from __future__ import annotations

import json
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class PortainerError(RuntimeError):
    """A bounded Portainer inventory request failed."""


def _get(instance: dict[str, object], path: str) -> Any:
    base_url = str(instance.get("url", "")).rstrip("/")
    token = str(instance.get("token", ""))
    if not base_url.startswith(("https://", "http://")) or not token:
        raise PortainerError("Portainer instance requires url and token")
    verify_tls = instance.get("verify_tls", True) is not False
    context = None if verify_tls else ssl._create_unverified_context()
    request = Request(
        f"{base_url}{path}", headers={"X-API-Key": token, "Accept": "application/json"}
    )
    try:
        with urlopen(request, timeout=15, context=context) as response:
            return json.load(response)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise PortainerError(f"Portainer request failed: {exc}") from exc


def inventory(instance: dict[str, object]) -> list[dict[str, Any]]:
    """Return containers for configured endpoint(s), without mutation capability."""
    label = str(instance.get("name") or instance.get("url") or "Portainer")
    configured = instance.get("endpoint_ids")
    if configured is None and instance.get("endpoint_id") is not None:
        configured = [instance["endpoint_id"]]
    endpoints = _get(instance, "/api/endpoints")
    allowed = {int(item) for item in configured} if isinstance(configured, list) else None
    result: list[dict[str, Any]] = []
    for endpoint in endpoints:
        endpoint_id = int(endpoint["Id"])
        if allowed is not None and endpoint_id not in allowed:
            continue
        containers = _get(
            instance,
            f"/api/endpoints/{endpoint_id}/docker/containers/json?{urlencode({'all': 1})}",
        )
        for container in containers:
            names = container.get("Names") or []
            name = str(names[0]).lstrip("/") if names else str(container.get("Id", ""))[:12]
            labels = container.get("Labels") or {}
            result.append({
                "container": name,
                "state": str(container.get("State", "unknown")),
                "image": str(container.get("Image", "")),
                "image_id": str(container.get("ImageID", "")),
                "health": str(container.get("Status", "")),
                "template_path": "",
                "template_hash": "",
                "provider": "portainer",
                "provider_name": label,
                "endpoint_id": endpoint_id,
                "endpoint_name": str(endpoint.get("Name", endpoint_id)),
                "managed_by": "Portainer stack" if labels.get("com.docker.compose.project") else "Portainer",
                "stack": str(labels.get("com.docker.compose.project", "")),
            })
    return sorted(result, key=lambda row: (row["endpoint_name"].lower(), row["container"].lower()))


def target_inventory(url: str, token: str, endpoint_id: int) -> list[dict[str, Any]]:
    """Inventory exactly one configured Portainer endpoint."""
    return inventory({"name": "Portainer", "url": url, "token": token, "endpoint_ids": [endpoint_id]})