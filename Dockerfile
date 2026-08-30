FROM python:3.12.11-slim-bookworm AS builder
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv==0.8.17 && \
    uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev

FROM python:3.12.11-slim-bookworm
ARG APP_VERSION=0.6.1
LABEL org.opencontainers.image.source="https://github.com/jmengit/container-updater" \
      org.opencontainers.image.description="Single-target, WUD-backed container update dashboard" \
      org.opencontainers.image.version="${APP_VERSION}"
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_MODE=report_only
WORKDIR /app
RUN groupadd --gid 10001 updater && useradd --uid 10001 --gid updater --no-create-home updater && \
    mkdir /data && chown updater:updater /data
COPY --from=builder --chown=updater:updater /build/.venv /app/.venv
COPY --from=builder --chown=updater:updater /build/src /app/src
# Direct Docker socket access is equivalent to host-root authority. Production
# intentionally runs this narrowly-scoped app as root; no host rootfs is mounted.
USER root
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=3)" || exit 1
CMD ["python", "-m", "uvicorn", "unraid_updater.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
