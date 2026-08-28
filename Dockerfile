FROM python:3.12.11-slim-bookworm AS builder
WORKDIR /build
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv==0.8.17 && \
    uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev

FROM python:3.12.11-slim-bookworm
LABEL org.opencontainers.image.source="https://github.com/jmengit/unraid-container-updater" \
      org.opencontainers.image.description="Report-only Unraid container update dashboard"
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_MODE=report_only
WORKDIR /app
RUN groupadd --gid 10001 updater && useradd --uid 10001 --gid updater --no-create-home updater && \
    mkdir /data && chown updater:updater /data
COPY --from=builder --chown=updater:updater /build/.venv /app/.venv
COPY --from=builder --chown=updater:updater /build/src /app/src
USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/v1/health', timeout=3)" || exit 1
CMD ["uvicorn", "unraid_updater.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-server-header"]
