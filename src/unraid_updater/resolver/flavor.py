"""Conservative image tag flavor helpers."""
from __future__ import annotations

import re


def flavor(value: str | None) -> str:
    if not value:
        return ""
    text = str(value).strip().lower()
    match = re.search(r"(?:^|[-_.])(alpine|slim|bookworm|bullseye|jammy|noble|cuda|rocm)(?:[-_.]|$)", text)
    return match.group(1) if match else ""


def same_flavor(left: str | None, right: str | None) -> bool:
    return flavor(left) == flavor(right)


def best(values: list[str] | tuple[str, ...], preferred: str | None = None) -> str | None:
    if not values:
        return None
    if preferred:
        for value in values:
            if flavor(value) == preferred:
                return value
    return values[0]


__all__ = ["best", "flavor", "same_flavor"]
