from apscheduler.schedulers.asyncio import AsyncIOScheduler
import logging
from datetime import datetime, timedelta
from sqlalchemy import or_
from app.core.config import settings
from app.core.database import SessionLocal
from app.models.models import MonitoredAsset, AssetStatusEnum
from app.services.scanner import scan_asset

logger = logging.getLogger(__name__)
scheduler = AsyncIOScheduler()

async def scan_assets_job():
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(hours=24)
        assets = db.query(MonitoredAsset).filter(
            MonitoredAsset.status == AssetStatusEnum.active,
            or_(MonitoredAsset.last_checked_at.is_(None), MonitoredAsset.last_checked_at <= cutoff),
        ).all()
        for asset in assets:
            try:
                await scan_asset(db, asset, trigger="automatic")
            except Exception:
                logger.exception("Scan failed for asset %s", asset.id)
                db.rollback()
    finally:
        db.close()

def init_scheduler():
    if scheduler.running:
        return
    scheduler.add_job(scan_assets_job, "interval", minutes=settings.SCAN_INTERVAL_MINUTES, id="scan_assets", max_instances=1, coalesce=True)
    scheduler.start()
    logger.info("Scheduler started")

def shutdown_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
