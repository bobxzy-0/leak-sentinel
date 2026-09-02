import asyncio
import logging
from datetime import datetime, timedelta
from time import monotonic
from zoneinfo import ZoneInfo

from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED, EVENT_JOB_MISSED
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import or_

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.models import MonitoredAsset, AssetStatusEnum
from app.services.scanner import scan_asset

logger = logging.getLogger(__name__)
scheduler: AsyncIOScheduler | None = None

async def scan_assets_job():
    started = monotonic()
    scanned = 0
    failed = 0
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(hours=24)
        active_count = db.query(MonitoredAsset).filter(
            MonitoredAsset.status == AssetStatusEnum.active,
        ).count()
        assets = db.query(MonitoredAsset).filter(
            MonitoredAsset.status == AssetStatusEnum.active,
            or_(
                MonitoredAsset.last_automatic_checked_at.is_(None),
                MonitoredAsset.last_automatic_checked_at <= cutoff,
            ),
        ).all()
        logger.info(
            "Automatic scan started: eligible=%s skipped_recent=%s cutoff=%s",
            len(assets), active_count - len(assets), cutoff.isoformat(timespec="seconds"),
        )
        for asset in assets:
            try:
                await scan_asset(db, asset, trigger="automatic")
                scanned += 1
            except Exception:
                failed += 1
                logger.exception("Automatic scan failed for asset %s", asset.id)
                db.rollback()
        logger.info(
            "Automatic scan finished: scanned=%s failed=%s skipped_recent=%s duration_ms=%s",
            scanned, failed, active_count - len(assets), round((monotonic() - started) * 1000),
        )
        return {"scanned": scanned, "failed": failed, "skipped_recent": active_count - len(assets)}
    finally:
        db.close()

def _log_job_event(event):
    if event.code == EVENT_JOB_MISSED:
        logger.warning("Automatic scan was missed at %s", event.scheduled_run_time)
    elif event.code == EVENT_JOB_ERROR:
        logger.error("Automatic scan job crashed: %s", event.exception)
    elif event.code == EVENT_JOB_EXECUTED:
        logger.info("Automatic scan scheduler tick completed")

def init_scheduler():
    global scheduler
    if scheduler is not None and scheduler.running:
        return
    app_timezone = ZoneInfo(settings.APP_TIMEZONE)
    scheduler = AsyncIOScheduler(event_loop=asyncio.get_running_loop(), timezone=app_timezone)
    scheduler.add_listener(_log_job_event, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED)
    scheduler.add_job(
        scan_assets_job, "interval", minutes=settings.SCAN_INTERVAL_MINUTES,
        id="scan_assets", max_instances=1, coalesce=True,
        misfire_grace_time=max(300, settings.SCAN_INTERVAL_MINUTES * 60),
        next_run_time=datetime.now(app_timezone),
    )
    scheduler.start()
    job = scheduler.get_job("scan_assets")
    logger.info(
        "Scheduler started: interval_minutes=%s next_run_time=%s",
        settings.SCAN_INTERVAL_MINUTES, job.next_run_time if job else None,
    )

def shutdown_scheduler():
    global scheduler
    if scheduler is not None and scheduler.running:
        scheduler.shutdown(wait=False)
    scheduler = None
