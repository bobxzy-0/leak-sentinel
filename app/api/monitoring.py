import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, HttpUrl
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.crypto import crypto_service
from app.core.database import get_db
from app.models.models import AlertChannel, AssetTypeEnum, ChannelTypeEnum, Finding, MonitoredAsset, User
from app.services.providers import HudsonRockProvider
from app.services.scanner import scan_asset

router = APIRouter()


class ChannelCreate(BaseModel):
    name: str
    channel_type: ChannelTypeEnum
    webhook_url: HttpUrl | None = None
    secret: str | None = None
    recipients: list[EmailStr] = []


class FreeSearchRequest(BaseModel):
    target_type: Literal["domain", "email", "username"]
    value: str


@router.post("/search/free")
async def free_search(body: FreeSearchRequest, user: User = Depends(get_current_user)):
    """Run a one-off Hudson Rock community lookup without saving an asset."""
    if not user:
        raise HTTPException(401, "Authentication required")
    value = body.value.strip()
    if not value or len(value) > 320:
        raise HTTPException(422, "Invalid search value")
    results = await HudsonRockProvider().search(AssetTypeEnum(body.target_type), value)
    return {
        "provider": "hudson_rock_community",
        "target_type": body.target_type,
        "value": value,
        "total": len(results),
        "items": [
            {"external_ref": r.external_ref, "severity": r.severity, "data": r.data}
            for r in results
        ],
    }


@router.post("/assets/{asset_id}/scan")
async def run_scan(asset_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user:
        raise HTTPException(401, "Authentication required")
    asset = db.query(MonitoredAsset).filter_by(id=asset_id, owner_id=user.id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    return await scan_asset(db, asset)


@router.get("/findings")
def list_findings(skip: int = 0, limit: int = 50, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user:
        raise HTTPException(401, "Authentication required")
    limit = min(max(limit, 1), 200)
    query = db.query(Finding).join(MonitoredAsset).filter(MonitoredAsset.owner_id == user.id)
    total = query.count()
    items = query.order_by(Finding.first_seen_at.desc()).offset(skip).limit(limit).all()
    return {"total": total, "items": items}


@router.post("/channels", status_code=201)
def create_channel(body: ChannelCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user:
        raise HTTPException(401, "Authentication required")
    if body.channel_type in (ChannelTypeEnum.dingtalk, ChannelTypeEnum.wecom) and not body.webhook_url:
        raise HTTPException(422, "webhook_url is required")
    if body.channel_type == ChannelTypeEnum.email and not body.recipients:
        raise HTTPException(422, "recipients are required")
    config = {}
    if body.webhook_url:
        config["webhook_url_ciphertext"] = crypto_service.encrypt(str(body.webhook_url))
    if body.secret:
        config["secret_ciphertext"] = crypto_service.encrypt(body.secret)
    if body.recipients:
        config["recipients_ciphertext"] = crypto_service.encrypt(json.dumps([str(x) for x in body.recipients]))
    channel = AlertChannel(owner_id=user.id, name=body.name, channel_type=body.channel_type, config_ciphertext=json.dumps(config))
    db.add(channel)
    db.commit()
    db.refresh(channel)
    return {"id": channel.id, "name": channel.name, "channel_type": channel.channel_type, "is_enabled": channel.is_enabled}


@router.get("/channels")
def list_channels(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user:
        raise HTTPException(401, "Authentication required")
    return db.query(AlertChannel).filter_by(owner_id=user.id).all()
