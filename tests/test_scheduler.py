import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.base import Base
from app.models.models import AssetStatusEnum, AssetTypeEnum, MonitoredAsset, User
from app.services.scheduler import scan_assets_job

TEST_ENGINE = create_engine(
    "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool,
)
TestSession = sessionmaker(bind=TEST_ENGINE)


def _asset(db, user_id, *, status=AssetStatusEnum.active, checked_at=None, automatic_checked_at=None):
    asset = MonitoredAsset(
        owner_id=user_id, asset_type=AssetTypeEnum.domain,
        value_ciphertext="encrypted", value_hash="hash", status=status,
        last_checked_at=checked_at, last_automatic_checked_at=automatic_checked_at,
    )
    db.add(asset)
    db.commit()
    return asset


def test_automatic_job_scans_only_due_assets():
    Base.metadata.create_all(bind=TEST_ENGINE)
    db = TestSession()
    user = User(email="scheduler@example.com", password_hash="hash")
    db.add(user)
    db.commit()
    due = _asset(db, user.id)
    old_time = datetime.utcnow() - timedelta(hours=25)
    old = _asset(db, user.id, checked_at=old_time, automatic_checked_at=old_time)
    manual_recent = _asset(db, user.id, checked_at=datetime.utcnow() - timedelta(hours=1))
    due_ids = {due.id, old.id, manual_recent.id}
    recent_time = datetime.utcnow() - timedelta(hours=1)
    _asset(db, user.id, checked_at=recent_time, automatic_checked_at=recent_time)
    _asset(db, user.id, status=AssetStatusEnum.paused)
    db.close()

    scanner = AsyncMock(return_value={})
    with patch("app.services.scheduler.SessionLocal", TestSession), patch(
        "app.services.scheduler.scan_asset", scanner,
    ):
        result = asyncio.run(scan_assets_job())

    assert {call.args[1].id for call in scanner.await_args_list} == due_ids
    assert all(call.kwargs["trigger"] == "automatic" for call in scanner.await_args_list)
    assert result == {"scanned": 3, "failed": 0, "skipped_recent": 1}
    Base.metadata.drop_all(bind=TEST_ENGINE)
