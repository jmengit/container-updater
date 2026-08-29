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


def test_only_one_supported_target_type() -> None:
    with pytest.raises(ValueError, match="TARGET_TYPE"):
        Settings(
            target_type="unraid,portainer", admin_password="a" * 12,
            session_secret="x" * 32,
        ).validate_for_server()


def test_portainer_target_requires_exactly_one_endpoint() -> None:
    with pytest.raises(ValueError, match="Portainer target"):
        Settings(
            target_type="portainer", admin_password="a" * 12,
            session_secret="x" * 32,
        ).validate_for_server()
