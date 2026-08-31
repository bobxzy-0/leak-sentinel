from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.database import get_db
from app.models.models import MonitoredAsset, User, AssetTypeEnum
from app.schemas.schemas import AssetCreate, AssetResponse
from app.api.deps import get_current_user
from app.core.crypto import crypto_service
import hashlib

router = APIRouter()

@router.get("/", response_model=List[AssetResponse])
def get_assets(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401)
    assets = db.query(MonitoredAsset).filter(MonitoredAsset.owner_id == current_user.id).all()
    # Decrypt values for response
    for asset in assets:
        if asset.value_ciphertext:
            asset.value = crypto_service.decrypt(asset.value_ciphertext)
        else:
            asset.value = ""
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
    
    new_asset = MonitoredAsset(
        owner_id=current_user.id,
        asset_type=asset_in.asset_type,
        label=asset_in.label,
        value_ciphertext=crypto_service.encrypt(asset_in.value),
        value_hash=value_hash,
        is_domain_verified=False if asset_in.asset_type == AssetTypeEnum.domain else True
    )
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)
    
    new_asset.value = asset_in.value
    return new_asset

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
