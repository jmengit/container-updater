"""Environment-backed application configuration with fail-safe defaults."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


def _secret(name: str, default: str = "") -> str:
    file_value = os.getenv(f"{name}_FILE")
    if file_value:
        return Path(file_value).read_text(encoding="utf-8").strip()
    return os.getenv(name, default)


def _json_secret(name: str) -> tuple[dict[str, object], ...]:
    raw = _secret(name)
    if not raw:
        return ()
    value = json.loads(raw)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{name} must be a JSON array of objects")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class Settings:
    app_mode: str = "report_only"
    database_url: str = "sqlite:////data/updater.db"
    timezone: str = "America/Chicago"
    scan_cron: str = "45 6 * * *"
    app_base_url: str = "http://localhost:8080"
    trusted_hosts: tuple[str, ...] = ("localhost", "127.0.0.1")
    admin_username: str = "admin"
    admin_password: str = ""
    session_secret: str = ""
    legacy_state_dir: str = ""
    log_level: str = "INFO"
    docker_socket: str = "/var/run/docker.sock"
    docker_template_dir: str = "/boot/config/plugins/dockerMan/templates-user"
    docker_backup_root: str = "/backups"
    self_container_name: str = "container-updater"
    execution_confirmation: str = ""
    portainer_instances: tuple[dict[str, object], ...] = ()

    @classmethod
    def from_env(cls) -> Settings:
        mode = os.getenv("APP_MODE", "report_only")
        if mode not in {"report_only", "approval_driven"}:
            raise ValueError("APP_MODE must be report_only or approval_driven")
        return cls(
            app_mode=mode,
            database_url=os.getenv("DATABASE_URL", "sqlite:////data/updater.db"),
            timezone=os.getenv("TIMEZONE", "America/Chicago"),
            scan_cron=os.getenv("SCAN_CRON", "45 6 * * *"),
            app_base_url=os.getenv("APP_BASE_URL", "http://localhost:8080"),
            trusted_hosts=tuple(
                value.strip()
                for value in os.getenv("TRUSTED_HOSTS", "localhost,127.0.0.1").split(",")
                if value.strip()
            ),
            admin_username=os.getenv("ADMIN_USERNAME", "admin"),
            admin_password=_secret("ADMIN_PASSWORD"),
            session_secret=_secret("SESSION_SECRET"),
            legacy_state_dir=os.getenv("LEGACY_STATE_DIR", ""),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            docker_socket=os.getenv("DOCKER_SOCKET", "/var/run/docker.sock"),
            docker_template_dir=os.getenv(
                "DOCKER_TEMPLATE_DIR", "/boot/config/plugins/dockerMan/templates-user"
            ),
            docker_backup_root=os.getenv("DOCKER_BACKUP_ROOT", "/backups"),
            self_container_name=os.getenv(
                "SELF_CONTAINER_NAME", "container-updater"
            ),
            execution_confirmation=os.getenv("EXECUTION_CONFIRMATION", ""),
            portainer_instances=_json_secret("PORTAINER_INSTANCES"),
        )

    def validate_for_server(self) -> None:
        if len(self.admin_password) < 12:
            raise ValueError("ADMIN_PASSWORD(_FILE) must contain at least 12 characters")
        if len(self.session_secret) < 32:
            raise ValueError("SESSION_SECRET(_FILE) must contain at least 32 characters")
        if self.app_mode == "approval_driven":
            expected = "I_UNDERSTAND_CONTAINER_UPDATES_MUTATE_UNRAID"
            if self.execution_confirmation != expected:
                raise ValueError("approval_driven mode requires the exact execution confirmation")
            if self.docker_socket != "/var/run/docker.sock":
                raise ValueError("approval_driven mode requires /var/run/docker.sock")
        if not self.trusted_hosts:
            raise ValueError("TRUSTED_HOSTS cannot be empty")
