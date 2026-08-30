"""Operator-configurable policy labels and conservative gate semantics."""
from __future__ import annotations

from typing import Any

POLICIES = ("manual", "notify", "patch", "minor")
RISKS = ("low", "medium", "high", "critical")
CHANGES = ("patch", "minor", "major", "digest", "unknown")

DEFAULT_GATES: dict[str, dict[str, Any]] = {
    "low": {
        "description": "Low blast radius; patch/minor updates may become approval-ready.",
        "allowed_changes": ["patch", "minor"],
        "research_required": False,
        "manual_review": False,
    },
    "medium": {
        "description": "Meaningful service impact; cited research and manual review required.",
        "allowed_changes": [],
        "research_required": True,
        "manual_review": True,
    },
    "high": {
        "description": "Stateful, security-sensitive, or broad impact; manual intervention only.",
        "allowed_changes": [],
        "research_required": True,
        "manual_review": True,
    },
    "critical": {
        "description": "Core infrastructure or safety-critical; never executable by this updater.",
        "allowed_changes": [],
        "research_required": True,
        "manual_review": True,
    },
}


def normalized_gates(value: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Merge stored settings with safe defaults and enforce hard safety ceilings."""
    value = value or {}
    result: dict[str, dict[str, Any]] = {}
    for risk in RISKS:
        default = DEFAULT_GATES[risk]
        stored = value.get(risk)
        row: dict[str, Any] = stored if isinstance(stored, dict) else {}
        allowed = [x for x in row.get("allowed_changes", default["allowed_changes"]) if x in CHANGES]
        manual = bool(row.get("manual_review", default["manual_review"]))
        # Medium-or-higher execution remains an immutable safety boundary.
        if risk != "low":
            allowed, manual = [], True
        result[risk] = {
            "description": str(row.get("description", default["description"]))[:500],
            "allowed_changes": allowed,
            "research_required": bool(row.get("research_required", default["research_required"])),
            "manual_review": manual,
        }
    return result


def validate_tags(policy: str, risk: str) -> tuple[str, str]:
    if policy not in POLICIES:
        raise ValueError("invalid update policy")
    if risk not in RISKS:
        raise ValueError("invalid risk tag")
    return policy, risk
