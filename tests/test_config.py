from __future__ import annotations

import pytest

from unraid_updater.config import Settings


def test_unknown_execution_mode_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_MODE", "execution_enabled")
    with pytest.raises(ValueError, match="report_only or approval_driven"):
        Settings.from_env()


def test_approval_driven_requires_exact_confirmation() -> None:
    settings = Settings(
        app_mode="approval_driven", admin_password="a" * 12,
        session_secret="x" * 32, execution_confirmation="wrong",
    )
    with pytest.raises(ValueError, match="exact execution confirmation"):
        settings.validate_for_server()


def test_approval_driven_accepts_exact_confirmation() -> None:
    Settings(
        app_mode="approval_driven", admin_password="a" * 12,
        session_secret="x" * 32,
        execution_confirmation="I_UNDERSTAND_CONTAINER_UPDATES_MUTATE_UNRAID",
    ).validate_for_server()


def test_server_requires_real_secrets() -> None:
    with pytest.raises(ValueError, match="ADMIN_PASSWORD"):
        Settings(admin_password="short", session_secret="x" * 32).validate_for_server()
    with pytest.raises(ValueError, match="SESSION_SECRET"):
        Settings(admin_password="a" * 12, session_secret="short").validate_for_server()


def test_safe_defaults_are_report_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_MODE", raising=False)
    assert Settings.from_env().app_mode == "report_only"


def test_portainer_instances_load_from_protected_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    config = tmp_path / "portainer.json"
    config.write_text('[{"name":"remote","url":"https://host","token":"secret"}]')
    monkeypatch.setenv("PORTAINER_INSTANCES_FILE", str(config))
    assert Settings.from_env().portainer_instances[0]["name"] == "remote"
