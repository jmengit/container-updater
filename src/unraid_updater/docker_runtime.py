"""Guarded Docker-socket inventory and template-preserving execution."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:  # Keep the offline/template helpers importable without the Docker SDK.
    import docker
    from docker.errors import DockerException, NotFound
except ModuleNotFoundError:  # pragma: no cover - exercised by minimal/offline installs
    docker = None  # type: ignore[assignment]

    class DockerException(Exception):
        """Fallback used when the optional Docker SDK is not installed."""

    class NotFound(DockerException):
        """Fallback Docker not-found exception."""

from .label_edit import runtime_labels_match
from .label_edit import validate_container_name as _validate_label_container_name
from .vnext_policy import LABEL_POLICY, LABEL_RESEARCH, LABEL_VERSION

TEMPLATE_DIR = Path("/boot/config/plugins/dockerMan/templates-user")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
REQUIRED_POLICY_LABELS = (LABEL_VERSION, LABEL_POLICY, LABEL_RESEARCH)


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
    if docker is None:
        raise ExecutionBlocked("Docker SDK is not installed")
    return docker.DockerClient(base_url=f"unix://{socket_path}", timeout=180)


def find_template(name: str, template_dir: Path = TEMPLATE_DIR) -> Path:
    try:
        _validate_label_container_name(name)
    except ValueError:
        raise ExecutionBlocked("invalid container name")
    root = template_dir.resolve()
    if not root.exists() or not root.is_dir():
        raise ExecutionBlocked("dockerMan template directory is unavailable")
    matches = [
        path for path in template_dir.glob("*.xml")
        if path.is_file() and path.resolve().parent == root
        and f"<Name>{name}</Name>" in path.read_text(encoding="utf-8", errors="ignore")
    ]
    if len(matches) != 1:
        raise ExecutionBlocked(f"expected one dockerMan template for {name}, found {len(matches)}")
    return matches[0]


def template_repository(path: Path) -> str:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ExecutionBlocked("invalid dockerMan template XML") from exc
    repositories = [node.text.strip() for node in root.iter("Repository") if node.text and node.text.strip()]
    if len(repositories) != 1:
        raise ExecutionBlocked("dockerMan template has no Repository")
    return repositories[0]


def template_labels(path: Path) -> dict[str, str]:
    """Read labels from dockerMan XML and ExtraParams (desired state)."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ExecutionBlocked("invalid dockerMan template XML") from exc
    labels: dict[str, str] = {}
    for node in root.iter("Label"):
        if node.text and "=" in node.text:
            key, value = node.text.split("=", 1)
            labels[key.strip()] = value.strip()
    params = next((node.text or "" for node in root.iter("ExtraParams")), "")
    try:
        parts = shlex.split(params)
    except ValueError:
        raise ExecutionBlocked("invalid dockerMan ExtraParams")
    index = 0
    while index < len(parts):
        value = ""
        if parts[index] == "--label" and index + 1 < len(parts):
            value = parts[index + 1]
            index += 2
        elif parts[index].startswith("--label="):
            value = parts[index].split("=", 1)[1]
            index += 1
        else:
            index += 1
        if "=" in value:
            key, label_value = value.split("=", 1)
            labels[key] = label_value
    return labels


def replace_template_repository(path: Path, repository: str) -> None:
    try:
        tree = ET.parse(path)
    except (OSError, ET.ParseError) as exc:
        raise ExecutionBlocked("invalid dockerMan template XML") from exc
    nodes = list(tree.getroot().iter("Repository"))
    if len(nodes) != 1 or not repository or "<" in repository or ">" in repository:
        raise ExecutionBlocked("could not update dockerMan Repository")
    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, backup)
    nodes[0].text = repository
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        with temporary.open("wb") as handle:
            tree.write(handle, encoding="utf-8", xml_declaration=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


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
            desired_labels = template_labels(template)
        except ExecutionBlocked:
            template, template_hash, desired_labels = None, "", {}
        runtime_labels = dict(attrs.get("Config", {}).get("Labels") or {})
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
            "labels": {**runtime_labels, **desired_labels},
            "runtime_policy_labels_present": all(
                key in runtime_labels
                for key in ("io.jmengit.upgrade.policy", "io.jmengit.upgrade.risk")
            ),
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
    backup_root = backup_root.expanduser().resolve()
    backup_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    backup = backup_root / f"{stamp}-{evidence.name}"
    backup.mkdir(parents=False, mode=0o700)
    shutil.copy2(evidence.template_path, backup / "template.xml")
    config = dict(attrs.get("Config") or {})
    config.pop("Env", None)
    sanitized = {
        "Config": config,
        "HostConfig": attrs.get("HostConfig") or {},
        "NetworkSettings": {"Networks": (attrs.get("NetworkSettings") or {}).get("Networks") or {}},
        "Image": attrs.get("Image", ""),
        "Name": attrs.get("Name", ""),
        "State": attrs.get("State") or {},
    }
    (backup / "inspect.json").write_text(
        json.dumps(sanitized, indent=2, sort_keys=True, default=str), encoding="utf-8"
    )
    manifest = {
        "created_at": datetime.now(UTC).isoformat(), "name": evidence.name,
        "image": evidence.image, "image_id": evidence.image_id,
        "template_path": str(evidence.template_path),
        "template_hash": evidence.template_hash,
    }
    (backup / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    (backup / "manifest.sha256").write_text(f"{digest}  manifest.json\n", encoding="ascii")
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
    try:
        _validate_label_container_name(name)
    except ValueError as exc:
        raise ExecutionBlocked("invalid container name") from exc
    try:
        _validate_label_container_name(self_name)
    except ValueError as exc:
        raise ExecutionBlocked("invalid configured self container name") from exc
    if name == self_name:
        raise ExecutionBlocked("self-update is forbidden")
    if not target_image or any(char in target_image for char in "\r\n<>"):
        raise ExecutionBlocked("invalid target image")
    evidence = inspect_live(name, socket_path, template_dir)
    if evidence.state != "running":
        raise ExecutionBlocked("stopped containers are never updated or started")
    if evidence.revision != expected_live_revision:
        raise ExecutionBlocked("live evidence changed after confirmation")
    if target_image == evidence.image:
        raise ExecutionBlocked("target image equals current image")
    desired_labels = template_labels(evidence.template_path)
    if any(key not in desired_labels for key in REQUIRED_POLICY_LABELS):
        raise ExecutionBlocked("dockerMan template is missing required vNext policy labels")
    client = client_from_socket(socket_path)
    old = client.containers.get(name)
    old.reload()
    attrs = old.attrs
    runtime_labels = dict(attrs.get("Config", {}).get("Labels") or {})
    if not runtime_labels_match(desired_labels, runtime_labels):
        raise ExecutionBlocked("running container policy labels differ from dockerMan template")
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
        created.reload()
        created_labels = dict(created.attrs.get("Config", {}).get("Labels") or {})
        if not runtime_labels_match(desired_labels, created_labels):
            raise ExecutionBlocked("recreated container policy labels do not match template")
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
        after_image_id = str(after.get("Image", ""))
        if after_image_id != str(target_id):
            raise RuntimeError("replacement image identity does not match pulled target")
        old.remove(force=True)
        return {
            "status": "succeeded", "backup_dir": str(backup),
            "before_image_id": evidence.image_id,
            "after_image_id": after_image_id,
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
