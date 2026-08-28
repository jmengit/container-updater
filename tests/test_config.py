from __future__ import annotations

import pytest

from unraid_updater.config import Settings


def test_execution_mode_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_MODE", "execution_enabled")
    with pytest.raises(ValueError, match="report_only"):
        Settings.from_env()


def test_server_requires_real_secrets() -> None:
    with pytest.raises(ValueError, match="ADMIN_PASSWORD"):
        Settings(admin_password="short", session_secret="x" * 32).validate_for_server()
    with pytest.raises(ValueError, match="SESSION_SECRET"):
        Settings(admin_password="a" * 12, session_secret="short").validate_for_server()


def test_safe_defaults_are_report_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("APP_MODE", raising=False)
    assert Settings.from_env().app_mode == "report_only"
