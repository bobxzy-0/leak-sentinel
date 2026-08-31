from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
from sqlalchemy import func
from app.core.database import get_db
from app.models.models import MonitoredAsset, User, AssetTypeEnum
from app.schemas.schemas import AssetCreate, AssetResponse
from app.api.deps import get_current_user
from app.core.crypto import crypto_service
import hashlib
import re
from urllib.parse import urlsplit

router = APIRouter()

class AssetReorder(BaseModel):
    asset_ids: list[int]

class AssetScopeUpdate(BaseModel):
    site_filter_mode: str
    watched_sites: list[str] = []

def normalize_watched_sites(values: list[str]) -> list[str]:
    normalized = []
    for raw in values:
        value = raw.strip().lower().rstrip(".")
        if not value:
            continue
        wildcard = value.startswith("*.")
        candidate = value[2:] if wildcard else value
        parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
        host = (parsed.hostname or "").encode("idna").decode("ascii")
        if not host or len(host) > 253 or not re.fullmatch(r"[a-z0-9.-]+", host):
            raise HTTPException(status_code=422, detail=f"Invalid watched site: {raw}")
        result = f"*.{host}" if wildcard else host
        if result not in normalized:
            normalized.append(result)
    return normalized

@router.get("/", response_model=List[AssetResponse])
def get_assets(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401)
    assets = db.query(MonitoredAsset).filter(MonitoredAsset.owner_id == current_user.id).order_by(
        MonitoredAsset.sort_order.asc(), MonitoredAsset.id.asc()
    ).all()
    # Decrypt values for response
    for asset in assets:
        if asset.value_ciphertext:
            value = crypto_service.decrypt(asset.value_ciphertext)
            asset.value = "••••••••" if asset.asset_type.value in ("password", "api_key", "token") else value
        else:
            asset.value = ""
        asset.watched_sites = asset.watched_sites_json or []
    return assets

@router.post("/", response_model=AssetResponse)
def create_asset(asset_in: AssetCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401)
    
    value_hash = hashlib.sha256(asset_in.value.encode()).hexdigest()
    # check duplicates
    existing = db.query(MonitoredAsset).filter(
        MonitoredAsset.owner_id == current_user.id,
        MonitoredAsset.asset_type == asset_in.asset_type,
        MonitoredAsset.value_hash == value_hash
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Asset already exists")
    
    max_order = db.query(func.max(MonitoredAsset.sort_order)).filter(
        MonitoredAsset.owner_id == current_user.id
    ).scalar()
    watched_sites = normalize_watched_sites(asset_in.watched_sites)
    if asset_in.asset_type in (AssetTypeEnum.password, AssetTypeEnum.api_key, AssetTypeEnum.token) and asset_in.site_filter_mode == "only":
        raise HTTPException(status_code=422, detail="This asset type does not support watched-site filtering")
    if asset_in.site_filter_mode == "only" and not watched_sites:
        raise HTTPException(status_code=422, detail="At least one watched site is required")
    new_asset = MonitoredAsset(
        owner_id=current_user.id,
        asset_type=asset_in.asset_type,
        label=asset_in.label,
        value_ciphertext=crypto_service.encrypt(asset_in.value),
        value_hash=value_hash,
        is_domain_verified=False if asset_in.asset_type == AssetTypeEnum.domain else True,
        sort_order=(max_order if max_order is not None else -1) + 1,
        site_filter_mode=asset_in.site_filter_mode,
        watched_sites_json=watched_sites,
    )
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)
    
    new_asset.value = "••••••••" if asset_in.asset_type.value in ("password", "api_key", "token") else asset_in.value
    new_asset.watched_sites = watched_sites
    return new_asset

@router.put("/reorder")
def reorder_assets(body: AssetReorder, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401)
    owned = db.query(MonitoredAsset).filter(MonitoredAsset.owner_id == current_user.id).all()
    owned_by_id = {asset.id: asset for asset in owned}
    if len(body.asset_ids) != len(set(body.asset_ids)):
        raise HTTPException(status_code=422, detail="Duplicate asset IDs")
    if set(body.asset_ids) != set(owned_by_id):
        raise HTTPException(status_code=422, detail="Asset list must contain all owned assets")
    for position, asset_id in enumerate(body.asset_ids):
        owned_by_id[asset_id].sort_order = position
    db.commit()
    return {"msg": "Reordered", "asset_ids": body.asset_ids}

@router.put("/{asset_id}/scope")
def update_asset_scope(asset_id: int, body: AssetScopeUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401)
    if body.site_filter_mode not in ("all", "only"):
        raise HTTPException(status_code=422, detail="Invalid site_filter_mode")
    watched_sites = normalize_watched_sites(body.watched_sites)
    if body.site_filter_mode == "only" and not watched_sites:
        raise HTTPException(status_code=422, detail="At least one watched site is required")
    asset = db.query(MonitoredAsset).filter_by(id=asset_id, owner_id=current_user.id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if asset.asset_type in (AssetTypeEnum.password, AssetTypeEnum.api_key, AssetTypeEnum.token) and body.site_filter_mode == "only":
        raise HTTPException(status_code=422, detail="This asset type does not support watched-site filtering")
    asset.site_filter_mode = body.site_filter_mode
    asset.watched_sites_json = watched_sites
    db.commit()
    return {"msg": "Scope updated", "site_filter_mode": body.site_filter_mode, "watched_sites": watched_sites}

@router.delete("/{asset_id}")
def delete_asset(asset_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401)
    asset = db.query(MonitoredAsset).filter(MonitoredAsset.id == asset_id, MonitoredAsset.owner_id == current_user.id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(asset)
    db.commit()
    return {"msg": "Deleted"}

@router.put("/{asset_id}/verify")
def verify_domain_asset(asset_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401)
    asset = db.query(MonitoredAsset).filter(MonitoredAsset.id == asset_id, MonitoredAsset.owner_id == current_user.id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if asset.asset_type != AssetTypeEnum.domain:
        raise HTTPException(status_code=400, detail="Only domains can be verified")
    
    asset.is_domain_verified = True
    db.commit()
    return {"msg": "Marked as verified"}
