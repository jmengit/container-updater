"""Bounded in-process scheduler for WUD API scans."""
from __future__ import annotations

import logging
import threading
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .db import Database
from .wud import scan

LOGGER = logging.getLogger(__name__)
_LOCK = threading.Lock()


def run_scan(db: Database, fetch, inventory) -> dict[str, int] | None:
    """Scan once; overlapping invocations are skipped rather than queued."""
    if not _LOCK.acquire(blocking=False):
        return None
    try:
        return scan(db, fetch(), inventory())
    except Exception:
        LOGGER.exception("scheduled report import failed")
        return None
    finally:
        _LOCK.release()


def build_scheduler(db: Database, fetch, inventory, cron: str, timezone: str) -> BackgroundScheduler:
    fields = cron.split()
    if len(fields) != 5:
        raise ValueError("SCAN_CRON must contain exactly five cron fields")
    minute, hour, day, month, weekday = fields
    scheduler = BackgroundScheduler(timezone=ZoneInfo(timezone), daemon=True)
    scheduler.add_job(
        run_scan,
        CronTrigger(
            minute=minute, hour=hour, day=day, month=month, day_of_week=weekday,
            timezone=ZoneInfo(timezone),
        ),
        args=(db, fetch, inventory),
        id="wud-api-scan",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=900,
        replace_existing=True,
    )
    return scheduler
