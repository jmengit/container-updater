"""Environment-backed application configuration with fail-safe defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _secret(name: str, default: str = "") -> str:
    file_value = os.getenv(f"{name}_FILE")
    if file_value:
        path = Path(file_value)
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
        if default:
            return default
        return ""
    return os.getenv(name, default)


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
    log_level: str = "INFO"
    target_type: str = "unraid"
    docker_socket: str = "/var/run/docker.sock"
    docker_template_dir: str = "/boot/config/plugins/dockerMan/templates-user"
    docker_backup_root: str = "/backups"
    self_container_name: str = "container-updater"
    execution_confirmation: str = ""
    portainer_url: str = ""
    portainer_token: str = ""
    portainer_endpoint_id: int = 0
    wud_url: str = "http://whats-up-docker:3000"
    wud_username: str = ""
    wud_password: str = ""
    wud_verify_tls: bool = True
    research_enabled: bool = False
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""
    github_token: str = ""
    research_verify_tls: bool = True

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
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            target_type=os.getenv("TARGET_TYPE", "unraid").lower(),
            docker_socket=os.getenv("DOCKER_SOCKET", "/var/run/docker.sock"),
            docker_template_dir=os.getenv(
                "DOCKER_TEMPLATE_DIR", "/boot/config/plugins/dockerMan/templates-user"
            ),
            docker_backup_root=os.getenv("DOCKER_BACKUP_ROOT", "/backups"),
            self_container_name=os.getenv(
                "SELF_CONTAINER_NAME", "container-updater"
            ),
            execution_confirmation=os.getenv("EXECUTION_CONFIRMATION", ""),
            portainer_url=os.getenv("PORTAINER_URL", ""),
            portainer_token=_secret("PORTAINER_TOKEN"),
            portainer_endpoint_id=int(os.getenv("PORTAINER_ENDPOINT_ID", "0")),
            wud_url=os.getenv("WUD_URL", "http://whats-up-docker:3000"),
            wud_username=os.getenv("WUD_USERNAME", ""),
            wud_password=_secret("WUD_PASSWORD"),
            wud_verify_tls=os.getenv("WUD_VERIFY_TLS", "true").lower() == "true",
            research_enabled=os.getenv("RESEARCH_ENABLED", "false").lower() == "true",
            llm_base_url=os.getenv("LLM_BASE_URL", "").rstrip("/"),
            llm_api_key=_secret("LLM_API_KEY"),
            llm_model=os.getenv("LLM_MODEL", ""),
            github_token=_secret("GITHUB_TOKEN"),
            research_verify_tls=os.getenv("RESEARCH_VERIFY_TLS", "true").lower() == "true",
        )

    def validate_for_server(self) -> None:
        if self.target_type not in {"unraid", "portainer"}:
            raise ValueError("TARGET_TYPE must be unraid or portainer")
        if self.target_type == "portainer" and not (
            self.portainer_url and self.portainer_token and self.portainer_endpoint_id
        ):
            raise ValueError("Portainer target requires URL, token, and endpoint ID")
        if len(self.admin_password) < 12:
            raise ValueError("ADMIN_PASSWORD(_FILE) must contain at least 12 characters")
        if len(self.session_secret) < 32:
            raise ValueError("SESSION_SECRET(_FILE) must contain at least 32 characters")
        if self.research_enabled and not (self.llm_base_url and self.llm_api_key and self.llm_model):
            raise ValueError("research requires LLM base URL, API key, and model")
        if self.app_mode == "approval_driven":
            expected = "I_UNDERSTAND_CONTAINER_UPDATES_MUTATE_UNRAID"
            if self.execution_confirmation != expected:
                raise ValueError("approval_driven mode requires the exact execution confirmation")
            if self.docker_socket != "/var/run/docker.sock":
                raise ValueError("approval_driven mode requires /var/run/docker.sock")
        if not self.trusted_hosts:
            raise ValueError("TRUSTED_HOSTS cannot be empty")
