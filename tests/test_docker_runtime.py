from __future__ import annotations

from pathlib import Path

import pytest

from unraid_updater.docker_runtime import (
    ExecutionBlocked,
    find_template,
    replace_template_repository,
    target_repository,
    template_labels,
)


def template(directory: Path, name: str = "app", repo: str = "example/app:1.0.0") -> Path:
    path = directory / "my-app.xml"
    path.write_text(
        f"<Container><Name>{name}</Name><Repository>{repo}</Repository></Container>",
        encoding="utf-8",
    )
    return path


def test_target_repository_preserves_repository_and_flavor() -> None:
    assert target_repository("ghcr.io/acme/app:latest", "v1.2.3-full") == (
        "ghcr.io/acme/app:v1.2.3-full"
    )
    assert target_repository("registry:5000/acme/app:old", "1.2.3") == (
        "registry:5000/acme/app:1.2.3"
    )


def test_template_must_match_exactly_once(tmp_path: Path) -> None:
    expected = template(tmp_path)
    assert find_template("app", tmp_path) == expected
    template(tmp_path, name="other")
    with pytest.raises(ExecutionBlocked, match="found 0"):
        find_template("app", tmp_path)


def test_rejects_invalid_container_names(tmp_path: Path) -> None:
    with pytest.raises(ExecutionBlocked, match="invalid"):
        find_template("../../bad", tmp_path)


def test_replace_repository_only(tmp_path: Path) -> None:
    path = template(tmp_path)
    replace_template_repository(path, "example/app:1.0.1")
    text = path.read_text()
    assert "<Name>app</Name>" in text
    assert "<Repository>example/app:1.0.1</Repository>" in text


def test_template_labels_reads_dockerman_extra_params(tmp_path: Path) -> None:
    path = tmp_path / "my-app.xml"
    path.write_text(
        "<Container><ExtraParams>--label io.jmengit.upgrade.policy=patch "
        "--label=io.jmengit.upgrade.risk=critical</ExtraParams></Container>"
    )
    assert template_labels(path) == {
        "io.jmengit.upgrade.policy": "patch",
        "io.jmengit.upgrade.risk": "critical",
    }
