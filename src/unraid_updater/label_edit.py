"""Safe XML-aware dockerMan policy-label editing."""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .vnext_policy import (
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


def parse_template_labels(path: str | Path) -> dict[str, str]:
    """Parse XML labels from dockerMan's repeated <Label>key=value</Label> form."""
    try:
        root = ET.parse(_root(Path(path))).getroot()
    except (OSError, ET.ParseError) as exc:
        raise LabelEditError("invalid dockerMan XML template") from exc
    labels: dict[str, str] = {}
    for node in root.iter("Label"):
        text = node.text or ""
        if "=" not in text:
            continue
        key, value = text.split("=", 1)
        labels[key.strip()] = value
    return labels


def policy_labels(labels: Mapping[str, Any]) -> dict[str, str]:
    return {key: str(labels[key]) for key in (LABEL_VERSION, LABEL_POLICY, LABEL_RESEARCH, LABEL_SOURCE, LABEL_HOLD_DAYS) if key in labels}


def policy_diff(current: Mapping[str, Any], desired: Mapping[str, Any]) -> dict[str, str | None]:
    """Return only updater-owned changes; unrelated labels never appear."""
    owned = {LABEL_VERSION, LABEL_POLICY, LABEL_RESEARCH, LABEL_SOURCE, LABEL_HOLD_DAYS}
    return {key: (str(desired[key]) if key in desired else None) for key in sorted(owned)
            if (str(current[key]) if key in current else None) != (str(desired[key]) if key in desired else None)}


def apply_policy_labels(path: str | Path, desired: Mapping[str, Any], *, template_root: str | Path | None = None,
                        backup: bool = True) -> Path:
    target = _root(Path(path), Path(template_root) if template_root else None)
    try:
        tree = ET.parse(target)
    except (OSError, ET.ParseError) as exc:
        raise LabelEditError("invalid dockerMan XML template") from exc
    root = tree.getroot()
    desired_owned = policy_labels(desired)
    seen: set[str] = set()
    for node in root.iter("Label"):
        text = node.text or ""
        if "=" not in text:
            continue
        key = text.split("=", 1)[0].strip()
        if key not in {LABEL_VERSION, LABEL_POLICY, LABEL_RESEARCH, LABEL_SOURCE, LABEL_HOLD_DAYS}:
            continue
        seen.add(key)
        if key in desired_owned:
            node.text = f"{key}={desired_owned[key]}"
        else:
            parent = next((p for p in root.iter() if node in list(p)), None)
            if parent is not None:
                parent.remove(node)
    labels_parent = next((n for n in root.iter() if n.tag == "Labels"), root)
    for key, value in desired_owned.items():
        if key not in seen:
            ET.SubElement(labels_parent, "Label").text = f"{key}={value}"
    if backup:
        shutil.copy2(target, target.with_suffix(target.suffix + ".bak"))
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            tree.write(handle, encoding="utf-8", xml_declaration=True)
            handle.flush(); os.fsync(handle.fileno())
        os.replace(temp_name, target)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)
    return target


def runtime_labels_match(template_labels: Mapping[str, Any], runtime_labels: Mapping[str, Any]) -> bool:
    return policy_labels(template_labels) == policy_labels(runtime_labels)


__all__ = ["LabelEditError", "apply_policy_labels", "parse_template_labels", "policy_diff", "policy_labels", "runtime_labels_match", "validate_container_name"]
