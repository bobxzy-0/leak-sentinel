import json
from typing import Literal

from datetime import datetime
from types import SimpleNamespace

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, HttpUrl
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.crypto import crypto_service
from app.core.database import get_db
from app.models.models import AlertChannel, AlertLog, AssetTypeEnum, ChannelTypeEnum, Finding, MonitoredAsset, ProviderCallLog, User
from app.services.providers import HudsonRockProvider
from app.services.finding_normalizer import normalize_finding
from app.services.scanner import scan_asset
from app.services.alert_channels.dingtalk import DingTalkChannel
from app.services.alert_channels.email import EmailChannel
from app.services.alert_channels.wecom import WecomChannel
from app.services.alert_channels.webhook import WebhookChannel

router = APIRouter()


class ChannelCreate(BaseModel):
    name: str
    channel_type: ChannelTypeEnum
    webhook_url: HttpUrl | None = None
    recipients: list[EmailStr] = []
    body_template: str | None = None


class ChannelUpdate(BaseModel):
    is_enabled: bool


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
    return await scan_asset(db, asset, trigger="manual")


@router.post("/assets/{asset_id}/scan/{provider}")
async def retry_provider_scan(
    asset_id: int, provider: str, db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not user:
        raise HTTPException(401, "Authentication required")
    asset = db.query(MonitoredAsset).filter_by(id=asset_id, owner_id=user.id).first()
    if not asset:
        raise HTTPException(404, "Asset not found")
    try:
        result = await scan_asset(db, asset, trigger="retry", provider_name=provider)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    outcome = result["outcomes"][0]
    if outcome["status"] == "disabled":
        raise HTTPException(409, "该情报源未配置或不适用于此资产类型")
    if outcome["status"] == "error":
        raise HTTPException(502, outcome["error"] or "情报源调用失败")
    return result


@router.get("/provider-calls")
def list_provider_calls(skip: int = 0, limit: int = 50, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user:
        raise HTTPException(401, "Authentication required")
    limit = min(max(limit, 1), 200)
    query = db.query(ProviderCallLog).join(MonitoredAsset).filter(MonitoredAsset.owner_id == user.id)
    total = query.count()
    items = query.order_by(ProviderCallLog.called_at.desc()).offset(skip).limit(limit).all()
    return {"total": total, "items": items}


@router.get("/findings")
def list_findings(skip: int = 0, limit: int = 50, asset_id: int | None = None, provider: str | None = None,
                  db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user:
        raise HTTPException(401, "Authentication required")
    limit = min(max(limit, 1), 200)
    query = db.query(Finding).join(MonitoredAsset).filter(MonitoredAsset.owner_id == user.id)
    if asset_id is not None:
        query = query.filter(Finding.asset_id == asset_id)
    source_groups = {
        "hudson_rock": ["hudson_rock"], "hibp": ["hibp_breach", "hibp_paste", "hibp_stealer_log"],
        "pwned_passwords": ["pwned_password"],
        "xposedornot": ["xposedornot"], "leakcheck": ["leakcheck"],
        "whiteintel": ["whiteintel"],
        "intelligence_x": ["intelligence_x"],
    }
    if provider in source_groups:
        query = query.filter(Finding.source.in_(source_groups[provider]))
    total = query.count()
    items = query.order_by(Finding.first_seen_at.desc()).offset(skip).limit(limit).all()
    return {"total": total, "items": [{
        "id": item.id, "source": item.source.value, "external_ref": item.external_ref,
        "severity": item.severity, "first_seen_at": item.first_seen_at,
        "normalized": normalize_finding(item.source.value, item.raw_data_json),
        "data": item.raw_data_json or {},
    } for item in items]}


@router.post("/channels", status_code=201)
def create_channel(body: ChannelCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not user:
        raise HTTPException(401, "Authentication required")
    if body.channel_type in (ChannelTypeEnum.webhook, ChannelTypeEnum.dingtalk, ChannelTypeEnum.wecom) and not body.webhook_url:
        raise HTTPException(422, "webhook_url is required")
    if body.channel_type == ChannelTypeEnum.email and not body.recipients:
        raise HTTPException(422, "recipients are required")
    config = {}
    if body.webhook_url:
        config["webhook_url_ciphertext"] = crypto_service.encrypt(str(body.webhook_url))
    if body.recipients:
        config["recipients_ciphertext"] = crypto_service.encrypt(json.dumps([str(x) for x in body.recipients]))
    if body.body_template:
        if len(body.body_template) > 8000:
            raise HTTPException(422, "body_template is too long")
        config["body_template_ciphertext"] = crypto_service.encrypt(body.body_template)
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


@router.put("/channels/{channel_id}")
def update_channel(channel_id: int, body: ChannelUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    channel = db.query(AlertChannel).filter_by(id=channel_id, owner_id=user.id).first()
    if not channel:
        raise HTTPException(404, "Alert channel not found")
    channel.is_enabled = body.is_enabled
    db.commit()
    return {"id": channel.id, "is_enabled": channel.is_enabled}


@router.delete("/channels/{channel_id}", status_code=204)
def delete_channel(channel_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    channel = db.query(AlertChannel).filter_by(id=channel_id, owner_id=user.id).first()
    if not channel:
        raise HTTPException(404, "Alert channel not found")
    db.query(AlertLog).filter(AlertLog.channel_id == channel.id).delete(synchronize_session=False)
    db.delete(channel)
    db.commit()


@router.post("/channels/{channel_id}/test")
async def test_channel(channel_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    channel = db.query(AlertChannel).filter_by(id=channel_id, owner_id=user.id).first()
    if not channel:
        raise HTTPException(404, "Alert channel not found")
    handlers = {
        ChannelTypeEnum.webhook: WebhookChannel(),
        ChannelTypeEnum.dingtalk: DingTalkChannel(),
        ChannelTypeEnum.wecom: WecomChannel(),
        ChannelTypeEnum.email: EmailChannel(),
    }
    config = json.loads(channel.config_ciphertext or "{}")
    test_finding = SimpleNamespace(
        severity=1,
        asset=SimpleNamespace(label="告警通道测试", asset_type=AssetTypeEnum.domain),
        source=SimpleNamespace(value="system_test"),
        external_ref="test-alert",
        first_seen_at=datetime.utcnow(),
        raw_data_json={"Domain": "example.com", "BreachDate": "2026-08-31", "DataClasses": ["邮箱", "密码"]},
    )
    if not await handlers[channel.channel_type].send(test_finding, config):
        raise HTTPException(502, "测试告警发送失败，请检查配置和服务日志")
    return {"success": True}


@router.get("/alert-logs")
def list_alert_logs(limit: int = 50, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    limit = min(max(limit, 1), 200)
    items = (db.query(AlertLog).join(AlertChannel).filter(AlertChannel.owner_id == user.id)
             .order_by(AlertLog.sent_at.desc()).limit(limit).all())
    return {"items": items}
