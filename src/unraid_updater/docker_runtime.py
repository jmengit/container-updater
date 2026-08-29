"""Guarded Docker-socket inventory and template-preserving execution."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import docker
from docker.errors import DockerException, NotFound

TEMPLATE_DIR = Path("/boot/config/plugins/dockerMan/templates-user")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class ExecutionBlocked(RuntimeError):
    """A safety invariant rejected execution before mutation."""


@dataclass(frozen=True, slots=True)
class LiveEvidence:
    name: str
    state: str
    image: str
    image_id: str
    template_path: Path
    template_hash: str
    template_repository: str

    @property
    def revision(self) -> str:
        basis = f"{self.name}|{self.state}|{self.image}|{self.image_id}|{self.template_hash}"
        return hashlib.sha256(
            basis.encode()
        ).hexdigest()


def client_from_socket(socket_path: str = "/var/run/docker.sock"):
    return docker.DockerClient(base_url=f"unix://{socket_path}", timeout=180)


def find_template(name: str, template_dir: Path = TEMPLATE_DIR) -> Path:
    if not NAME_RE.fullmatch(name):
        raise ExecutionBlocked("invalid container name")
    matches = [
        path for path in template_dir.glob("*.xml")
        if f"<Name>{name}</Name>" in path.read_text(encoding="utf-8", errors="ignore")
    ]
    if len(matches) != 1:
        raise ExecutionBlocked(f"expected one dockerMan template for {name}, found {len(matches)}")
    return matches[0]


def template_repository(path: Path) -> str:
    match = re.search(r"<Repository>(.*?)</Repository>", path.read_text(encoding="utf-8"), re.DOTALL)
    if not match:
        raise ExecutionBlocked("dockerMan template has no Repository")
    return match.group(1).strip()


def replace_template_repository(path: Path, repository: str) -> None:
    text = path.read_text(encoding="utf-8")
    changed, count = re.subn(
        r"<Repository>.*?</Repository>",
        f"<Repository>{repository}</Repository>", text, count=1, flags=re.DOTALL,
    )
    if count != 1:
        raise ExecutionBlocked("could not update dockerMan Repository")
    path.write_text(changed, encoding="utf-8")


def inspect_live(
    name: str, socket_path: str, template_dir: Path = TEMPLATE_DIR
) -> LiveEvidence:
    try:
        container = client_from_socket(socket_path).containers.get(name)
        container.reload()
    except (DockerException, NotFound) as exc:
        raise ExecutionBlocked(f"cannot inspect {name}: {exc}") from exc
    attrs = container.attrs
    template = find_template(name, template_dir)
    repository = template_repository(template)
    configured_image = str(attrs.get("Config", {}).get("Image", ""))
    if configured_image != repository:
        raise ExecutionBlocked("live image and dockerMan template repository differ")
    return LiveEvidence(
        name=name,
        state=str(attrs.get("State", {}).get("Status", "unknown")),
        image=configured_image,
        image_id=str(attrs.get("Image", "")),
        template_path=template,
        template_hash=hashlib.sha256(template.read_bytes()).hexdigest(),
        template_repository=repository,
    )


def inventory(
    socket_path: str, excluded_name: str, template_dir: Path = TEMPLATE_DIR
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    client = client_from_socket(socket_path)
    for container in client.containers.list(all=True):
        container.reload()
        attrs = container.attrs
        name = container.name or ""
        if not name or name == excluded_name:
            continue
        try:
            template = find_template(name, template_dir)
            template_hash = hashlib.sha256(template.read_bytes()).hexdigest()
        except ExecutionBlocked:
            template, template_hash = None, ""
        result.append({
            "container": name,
            "state": str(attrs.get("State", {}).get("Status", "unknown")),
            "image": str(attrs.get("Config", {}).get("Image", "")),
            "image_id": str(attrs.get("Image", "")),
            "health": str(attrs.get("State", {}).get("Health", {}).get("Status", "")),
            "template_path": str(template or ""),
            "template_hash": template_hash,
            "provider": "local",
            "provider_name": "Local Docker",
            "managed_by": "dockerMan" if template else "docker",
        })
    return sorted(result, key=lambda row: row["container"].lower())


def target_repository(current_image: str, candidate: str) -> str:
    """Replace only the tag; preserve registry/repository and candidate flavor."""
    base = current_image.split("@", 1)[0]
    slash = base.rfind("/")
    colon = base.rfind(":")
    if colon > slash:
        base = base[:colon]
    return f"{base}:{candidate}"


def backup_evidence(evidence: LiveEvidence, backup_root: Path, attrs: dict[str, Any]) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    backup = backup_root / f"{stamp}-{evidence.name}"
    backup.mkdir(parents=True, mode=0o700)
    shutil.copy2(evidence.template_path, backup / "template.xml")
    (backup / "inspect.json").write_text(
        json.dumps(attrs, indent=2, sort_keys=True), encoding="utf-8"
    )
    (backup / "manifest.json").write_text(json.dumps({
        "created_at": datetime.now(UTC).isoformat(), "name": evidence.name,
        "image": evidence.image, "image_id": evidence.image_id,
        "template_path": str(evidence.template_path),
        "template_hash": evidence.template_hash,
    }, indent=2, sort_keys=True), encoding="utf-8")
    return backup


def _creation_config(attrs: dict[str, Any], target_image: str) -> dict[str, Any]:
    allowed = {
        "Hostname", "Domainname", "User", "AttachStdin", "AttachStdout", "AttachStderr",
        "ExposedPorts", "Tty", "OpenStdin", "StdinOnce", "Env", "Cmd", "Healthcheck",
        "ArgsEscaped", "Entrypoint", "NetworkDisabled", "MacAddress", "OnBuild", "Labels",
        "StopSignal", "StopTimeout", "Shell",
    }
    config = {key: value for key, value in attrs["Config"].items() if key in allowed}
    config["Image"] = target_image
    config["HostConfig"] = attrs["HostConfig"]
    endpoints = attrs.get("NetworkSettings", {}).get("Networks", {})
    config["NetworkingConfig"] = {"EndpointsConfig": endpoints}
    return config


def _healthy(attrs: dict[str, Any]) -> bool:
    state = attrs.get("State", {})
    health = state.get("Health", {}).get("Status", "")
    return state.get("Status") == "running" and health not in {"starting", "unhealthy"}


def execute_update(
    *, name: str, target_image: str, expected_live_revision: str,
    socket_path: str, template_dir: Path, backup_root: Path, self_name: str,
) -> dict[str, Any]:
    """Pull, recreate, verify, and retain instant rollback until success."""
    if name == self_name:
        raise ExecutionBlocked("self-update is forbidden")
    evidence = inspect_live(name, socket_path, template_dir)
    if evidence.state != "running":
        raise ExecutionBlocked("stopped containers are never updated or started")
    if evidence.revision != expected_live_revision:
        raise ExecutionBlocked("live evidence changed after confirmation")
    if target_image == evidence.image:
        raise ExecutionBlocked("target image equals current image")

    client = client_from_socket(socket_path)
    old = client.containers.get(name)
    old.reload()
    attrs = old.attrs
    backup = backup_evidence(evidence, backup_root, attrs)
    rollback_name = f"{name}.updater-rollback-{int(time.time())}"
    created = None
    try:
        client.images.pull(target_image)
        target_id = client.images.get(target_image).id
        if target_id == evidence.image_id:
            raise ExecutionBlocked("registry target resolves to the already-running image")
        config = _creation_config(attrs, target_image)
        old.stop(timeout=int(attrs.get("Config", {}).get("StopTimeout") or 30))
        old.rename(rollback_name)
        replace_template_repository(evidence.template_path, target_image)
        response = client.api.create_container_from_config(config, name=name)
        created = client.containers.get(response["Id"])
        created.start()
        after: dict[str, Any] = {}
        for _ in range(12):
            created.reload()
            after = created.attrs
            if _healthy(after):
                break
            time.sleep(5)
        else:
            raise RuntimeError("replacement did not become running/healthy within 60 seconds")
        old.remove(force=True)
        return {
            "status": "succeeded", "backup_dir": str(backup),
            "before_image_id": evidence.image_id,
            "after_image_id": str(after.get("Image", "")),
            "target_image": target_image,
        }
    except Exception as exc:
        rollback_error = ""
        try:
            if created is not None:
                created.remove(force=True)
            shutil.copy2(backup / "template.xml", evidence.template_path)
            old.reload()
            old.rename(name)
            old.start()
            old.reload()
            if not _healthy(old.attrs):
                raise RuntimeError("retained original did not return running/healthy")
        except (DockerException, OSError, RuntimeError) as rollback_exc:
            rollback_error = str(rollback_exc)
        message = f"update failed: {exc}; rollback="
        message += f"failed: {rollback_error}" if rollback_error else "succeeded"
        raise RuntimeError(message) from exc
