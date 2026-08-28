"""Bounded in-process scheduler for read-only legacy report imports."""
from __future__ import annotations

import logging
import threading
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .db import Database
from .importer import import_latest

LOGGER = logging.getLogger(__name__)
_LOCK = threading.Lock()


def run_import(db: Database, legacy_state_dir: str) -> dict[str, int] | None:
    """Import once; overlapping invocations are skipped rather than queued."""
    if not legacy_state_dir or not _LOCK.acquire(blocking=False):
        return None
    try:
        return import_latest(db, legacy_state_dir)
    except Exception:
        LOGGER.exception("scheduled report import failed")
        return None
    finally:
        _LOCK.release()


def build_scheduler(
    db: Database, legacy_state_dir: str, cron: str, timezone: str
) -> BackgroundScheduler | None:
    if not legacy_state_dir:
        return None
    fields = cron.split()
    if len(fields) != 5:
        raise ValueError("SCAN_CRON must contain exactly five cron fields")
    minute, hour, day, month, weekday = fields
    scheduler = BackgroundScheduler(timezone=ZoneInfo(timezone), daemon=True)
    scheduler.add_job(
        run_import,
        CronTrigger(
            minute=minute, hour=hour, day=day, month=month, day_of_week=weekday,
            timezone=ZoneInfo(timezone),
        ),
        args=(db, legacy_state_dir),
        id="legacy-report-import",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=900,
        replace_existing=True,
    )
    return scheduler
