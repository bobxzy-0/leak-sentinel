from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.templating import Jinja2Templates
import os
from datetime import datetime, timedelta
from app.api.deps import get_current_user
from sqlalchemy.orm import Session
from app.models.models import AlertChannel, AlertLog, Finding, MonitoredAsset, ProviderCallLog
from app.core.crypto import crypto_service, mask_sensitive_value
from app.core.config import settings
from app.core.database import get_db
from app.core.time import format_localtime
from app.services.finding_normalizer import is_actionable_finding, normalize_finding

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))
templates.env.filters["localtime"] = format_localtime

APP_NAME = settings.APP_NAME

@router.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={"app_name": APP_NAME})

# Shell routes
@router.get("/")
@router.get("/assets")
@router.get("/settings")
async def app_shell(request: Request):
    return templates.TemplateResponse(request=request, name="app_shell.html", context={"app_name": APP_NAME})

# Fragments
@router.get("/views/dashboard")
async def view_dashboard(request: Request, user = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        raise HTTPException(status_code=401)
    assets_count = db.query(MonitoredAsset).filter(MonitoredAsset.owner_id == user.id).count()
    since = datetime.utcnow() - timedelta(days=7)
    recent_stored_findings = db.query(Finding).join(MonitoredAsset).filter(
        MonitoredAsset.owner_id == user.id, Finding.first_seen_at >= since
    ).all()
    new_findings_count = sum(
        is_actionable_finding(item.source.value, item.raw_data_json)
        for item in recent_stored_findings
    )
    calls = db.query(ProviderCallLog).join(MonitoredAsset).filter(
        MonitoredAsset.owner_id == user.id, ProviderCallLog.called_at >= since
    )
    call_count = calls.count()
    error_count = calls.filter(ProviderCallLog.status == "error").count()
    recent_calls = db.query(ProviderCallLog).join(MonitoredAsset).filter(
        MonitoredAsset.owner_id == user.id
    ).order_by(ProviderCallLog.called_at.desc()).limit(10).all()
    stored_findings = db.query(Finding).join(MonitoredAsset).filter(
        MonitoredAsset.owner_id == user.id
    ).order_by(Finding.first_seen_at.desc()).all()
    recent_findings = [
        item for item in stored_findings
        if is_actionable_finding(item.source.value, item.raw_data_json)
    ][:10]
    for finding in recent_findings:
        finding.normalized = normalize_finding(finding.source.value, finding.raw_data_json)
    sources = _source_statuses()
    return templates.TemplateResponse(request=request, name="fragments/dashboard.html", context={
        "assets_count": assets_count,
        "new_findings_count": new_findings_count,
        "call_count": call_count,
        "error_count": error_count,
        "recent_calls": recent_calls,
        "recent_findings": recent_findings,
        "sources": sources,
    })

    
@router.get("/views/assets")
async def view_assets(request: Request, user = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        raise HTTPException(status_code=401)
    assets = db.query(MonitoredAsset).filter(MonitoredAsset.owner_id == user.id).order_by(
        MonitoredAsset.sort_order.asc(), MonitoredAsset.id.asc()
    ).all()
    stored_findings = db.query(Finding).join(MonitoredAsset).filter(
        MonitoredAsset.owner_id == user.id
    ).all()
    source_providers = {
        "hibp_breach": "hibp", "hibp_paste": "hibp", "hibp_stealer_log": "hibp",
        "pwned_password": "pwned_passwords", "hudson_rock": "hudson_rock",
        "xposedornot": "xposedornot", "leakcheck": "leakcheck",
    }
    findings_by_asset: dict[int, dict[str, int]] = {}
    for finding in stored_findings:
        if not is_actionable_finding(finding.source.value, finding.raw_data_json):
            continue
        provider = source_providers.get(finding.source.value)
        if provider:
            provider_counts = findings_by_asset.setdefault(finding.asset_id, {})
            provider_counts[provider] = provider_counts.get(provider, 0) + 1
    for asset in assets:
        if asset.value_ciphertext:
            value = crypto_service.decrypt(asset.value_ciphertext)
            asset.value = mask_sensitive_value(value, asset.asset_type.value) if asset.asset_type.value in ("password", "api_key", "token") else value
        else:
            asset.value = ""
        states = {key: dict(value) for key, value in (asset.provider_status_json or {}).items()}
        for provider, count in findings_by_asset.get(asset.id, {}).items():
            state = states.setdefault(provider, {})
            # A failed latest call remains yellow so its error and retry action stay accessible.
            # Otherwise persisted findings must not be represented by a green "clean" icon.
            if state.get("status") != "error":
                state["status"] = "found"
                state["count"] = count
        asset.provider_status_json = states
    return templates.TemplateResponse(request=request, name="fragments/assets.html", context={
        "assets": assets, "leakcheck_pro": bool(settings.LEAKCHECK_API_KEY),
    })

@router.get("/views/assets/new")
async def view_assets_new(request: Request, user = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    return templates.TemplateResponse(request=request, name="fragments/asset_new.html", context={})


@router.get("/views/settings")
async def view_settings(request: Request, user = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        raise HTTPException(status_code=401)
    channels = db.query(AlertChannel).filter(AlertChannel.owner_id == user.id).order_by(AlertChannel.id.desc()).all()
    recent_alert_logs = (db.query(AlertLog).join(AlertChannel).filter(AlertChannel.owner_id == user.id)
                         .order_by(AlertLog.sent_at.desc()).limit(20).all())
    return templates.TemplateResponse(request=request, name="fragments/settings.html", context={
        "sources": _source_statuses(), "channels": channels, "recent_alert_logs": recent_alert_logs,
        "smtp_ready": bool(settings.SMTP_HOST and settings.SMTP_FROM),
    })

def _source_statuses():
    return [
        {
            "key": "hudson_rock",
            "name": "Hudson Rock",
            "description": "域名、邮箱和用户名 Infostealer 泄漏情报",
            "enabled": settings.HUDSON_ROCK_ENABLED,
            "credential": "Community OSINT",
        },
        {
            "key": "hibp",
            "name": "Have I Been Pwned",
            "description": "免费查询域名泄漏事件；配置 API Key 后增加邮箱精确查询",
            "enabled": True,
            "credential": "完整模式 · API Key" if settings.HIBP_API_KEY else "基础免费模式 · 无需 API Key",
        },
        {
            "key": "pwned_passwords",
            "name": "HIBP Pwned Passwords",
            "description": "通过 k-anonymity 检查密码是否出现在泄漏库",
            "enabled": True,
            "credential": "免费，无需 API Key",
        },
        {
            "key": "xposedornot", "name": "XposedOrNot",
            "description": "免费免密查询邮箱泄漏详情",
            "enabled": settings.XPOSEDORNOT_ENABLED, "credential": "免费，无需 API Key",
        },
        {
            "key": "leakcheck", "name": "LeakCheck",
            "description": "邮箱、用户名泄漏来源与字段；配置 Key 后返回完整记录",
            "enabled": settings.LEAKCHECK_ENABLED,
            "credential": "Pro API Key" if settings.LEAKCHECK_API_KEY else "Public API 免费模式",
        },
    ]

@router.get("/views/nav_user")
async def view_nav_user(request: Request, user = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    return templates.TemplateResponse(request=request, name="fragments/nav_user.html", context={"current_user": user})
