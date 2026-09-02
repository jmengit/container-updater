"""Safe XML-aware dockerMan policy-label editing."""
from __future__ import annotations

import os
import re
import shlex
import shutil
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .vnext_policy import (
    LABEL_CHANGELOG_SUMMARY,
    LABEL_HOLD_DAYS,
    LABEL_POLICY,
    LABEL_RESEARCH,
    LABEL_SOURCE,
    LABEL_VERSION,
)

LABEL_PREFIX = "io.jmengit.upgrade."
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class LabelEditError(ValueError):
    """A template cannot be safely inspected or changed."""


def github_source_hint(image: str) -> dict[str, str | bool]:
    """Return a clearly unverified GitHub hint for a simple public GHCR path."""
    value = image.strip().split("@", 1)[0]
    if not value.lower().startswith("ghcr.io/"):
        return {"url": "", "status": "not inferred", "verified": False}
    path = value[len("ghcr.io/"):]
    last = path.rsplit("/", 1)[-1]
    if ":" in last:
        path = path.rsplit(":", 1)[0]
    parts = path.split("/")
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        return {"url": "", "status": "ambiguous GHCR path", "verified": False}
    return {"url": f"https://github.com/{parts[0]}/{parts[1]}",
            "status": "suggested from GHCR namespace; not verified", "verified": False}


def validate_container_name(name: str) -> str:
    if not NAME_RE.fullmatch(str(name)):
        raise LabelEditError("invalid container name")
    return str(name)


def _root(path: Path, root: Path | None = None) -> Path:
    path = path.expanduser().resolve()
    if root is not None:
        base = root.expanduser().resolve()
        if path != base and base not in path.parents:
            raise LabelEditError("template path escapes configured root")
    return path


def _split_params(value: str) -> list[str]:
    try:
        return shlex.split(value)
    except ValueError as exc:
        raise LabelEditError("invalid dockerMan ExtraParams") from exc


def _labels_from_params(value: str) -> dict[str, str]:
    parts = _split_params(value)
    labels: dict[str, str] = {}
    index = 0
    while index < len(parts):
        label = ""
        if parts[index] == "--label":
            if index + 1 >= len(parts):
                raise LabelEditError("dockerMan ExtraParams has --label without a value")
            label = parts[index + 1]
            index += 2
        elif parts[index].startswith("--label="):
            label = parts[index].split("=", 1)[1]
            index += 1
        else:
            index += 1
        if "=" in label:
            key, value = label.split("=", 1)
            labels[key.strip()] = value
    return labels


def parse_template_labels(path: str | Path) -> dict[str, str]:
    """Parse desired labels, with deployable ExtraParams taking precedence."""
    try:
        root = ET.parse(_root(Path(path))).getroot()
    except (OSError, ET.ParseError) as exc:
        raise LabelEditError("invalid dockerMan XML template") from exc
    labels: dict[str, str] = {}
    # Read legacy/non-deployable nodes for migration and backward compatibility.
    for node in root.iter("Label"):
        text = node.text or ""
        if "=" in text:
            key, value = text.split("=", 1)
            labels[key.strip()] = value
    params = next((node.text or "" for node in root.iter("ExtraParams")), "")
    labels.update(_labels_from_params(params))
    return labels


def policy_labels(labels: Mapping[str, Any]) -> dict[str, str]:
    return {key: str(labels[key]) for key in (
        LABEL_VERSION, LABEL_POLICY, LABEL_RESEARCH, LABEL_CHANGELOG_SUMMARY,
        LABEL_SOURCE, LABEL_HOLD_DAYS,
    ) if labels.get(key) not in (None, "")}


def policy_diff(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, dict[str, str | None]]:
    keys = sorted(set(policy_labels(before)) | set(policy_labels(after)))
    return {key: {"before": str(before[key]) if key in before else None,
                  "after": str(after[key]) if key in after else None}
            for key in keys if before.get(key) != after.get(key)}


def _without_owned_labels(parts: list[str]) -> list[str]:
    """Remove only updater-owned --label args, preserving every unrelated token."""
    kept: list[str] = []
    index = 0
    while index < len(parts):
        token = parts[index]
        if token == "--label":
            if index + 1 >= len(parts):
                raise LabelEditError("dockerMan ExtraParams has --label without a value")
            value = parts[index + 1]
            if value.split("=", 1)[0].startswith(LABEL_PREFIX):
                index += 2
                continue
            kept.extend((token, value))
            index += 2
            continue
        if token.startswith("--label="):
            value = token.split("=", 1)[1]
            if value.split("=", 1)[0].startswith(LABEL_PREFIX):
                index += 1
                continue
        kept.append(token)
        index += 1
    return kept


def apply_policy_labels(path: str | Path, desired: Mapping[str, Any], *,
                        template_root: str | Path | None = None, backup: bool = True) -> dict[str, Any]:
    """Atomically replace updater labels in deployable ExtraParams; preserve everything else."""
    target = _root(Path(path), Path(template_root) if template_root else None)
    if not target.is_file():
        raise LabelEditError("dockerMan template does not exist")
    try:
        tree = ET.parse(target)
    except (OSError, ET.ParseError) as exc:
        raise LabelEditError("invalid dockerMan XML template") from exc
    root = tree.getroot()
    before = parse_template_labels(target)
    wanted = policy_labels(desired)

    extra = next(iter(root.iter("ExtraParams")), None)
    if extra is None:
        extra = ET.SubElement(root, "ExtraParams")
    parts = _without_owned_labels(_split_params(extra.text or ""))
    for key, value in sorted(wanted.items()):
        parts.extend(("--label", f"{key}={value}"))
    extra.text = shlex.join(parts)

    # Remove stale updater-owned <Label> nodes: Unraid does not deploy these and
    # keeping two representations makes the editor lie about desired state.
    for parent in root.iter():
        for node in list(parent):
            if node.tag == "Label" and (node.text or "").split("=", 1)[0].strip().startswith(LABEL_PREFIX):
                parent.remove(node)

    if backup:
        shutil.copy2(target, target.with_suffix(target.suffix + ".bak"))
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            tree.write(handle, encoding="utf-8", xml_declaration=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, target)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise
    return {"path": str(target), "backup": str(target.with_suffix(target.suffix + ".bak")),
            "diff": policy_diff(before, wanted)}


def runtime_labels_match(desired: Mapping[str, Any], runtime: Mapping[str, Any]) -> bool:
    expected = policy_labels(desired)
    return bool(expected) and all(str(runtime.get(key, "")) == value for key, value in expected.items())
