from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.templating import Jinja2Templates
import os
from app.api.deps import get_current_user
from sqlalchemy.orm import Session
from app.models.models import MonitoredAsset
from app.core.crypto import crypto_service
from app.core.database import get_db

router = APIRouter()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))

APP_NAME = os.getenv("APP_NAME", "HIBP 数据泄露监控平台")

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
    return templates.TemplateResponse(request=request, name="fragments/dashboard.html", context={"assets_count": assets_count, "new_findings_count": 0})

    
@router.get("/views/assets")
async def view_assets(request: Request, user = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        raise HTTPException(status_code=401)
    assets = db.query(MonitoredAsset).filter(MonitoredAsset.owner_id == user.id).all()
    for asset in assets:
        if asset.value_ciphertext:
            asset.value = crypto_service.decrypt(asset.value_ciphertext)
        else:
            asset.value = ""
    return templates.TemplateResponse(request=request, name="fragments/assets.html", context={"assets": assets})

@router.get("/views/assets/new")
async def view_assets_new(request: Request, user = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    return templates.TemplateResponse(request=request, name="fragments/asset_new.html", context={})


@router.get("/views/settings")
async def view_settings(request: Request, user = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    return templates.TemplateResponse(request=request, name="fragments/settings.html", context={})

@router.get("/views/nav_user")
async def view_nav_user(request: Request, user = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401)
    return templates.TemplateResponse(request=request, name="fragments/nav_user.html", context={"current_user": user})
