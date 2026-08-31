from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.assets import router as assets_router
from app.api.monitoring import router as monitoring_router

api_router = APIRouter()
api_router.include_router(auth_router, prefix="/auth", tags=["auth"])
api_router.include_router(assets_router, prefix="/assets", tags=["assets"])
api_router.include_router(monitoring_router, tags=["monitoring"])
