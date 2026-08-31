from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import api_router
from app.api.web import router as web_router

from app.core.database import engine
from app.models.base import Base
from app.services.scheduler import init_scheduler, shutdown_scheduler
from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import get_password_hash
from app.models.models import User, RoleEnum
from sqlalchemy import inspect, text

def ensure_schema_compatibility():
    """Apply small additive upgrades for installations created before migrations existed."""
    inspector = inspect(engine)
    if engine.dialect.name == "postgresql":
        with engine.begin() as connection:
            connection.execute(text("ALTER TYPE assettypeenum ADD VALUE IF NOT EXISTS 'token'"))
            connection.execute(text("ALTER TYPE findingsourceenum ADD VALUE IF NOT EXISTS 'xposedornot'"))
            connection.execute(text("ALTER TYPE findingsourceenum ADD VALUE IF NOT EXISTS 'leakcheck'"))
            connection.execute(text("ALTER TYPE findingsourceenum ADD VALUE IF NOT EXISTS 'whiteintel'"))
            connection.execute(text("ALTER TYPE findingsourceenum ADD VALUE IF NOT EXISTS 'intelligence_x'"))
    if "monitored_assets" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("monitored_assets")}
    if "sort_order" not in columns:
        with engine.begin() as connection:
            connection.execute(text(
                "ALTER TABLE monitored_assets ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0"
            ))
    if "provider_status_json" not in columns:
        with engine.begin() as connection:
            connection.execute(text(
                "ALTER TABLE monitored_assets ADD COLUMN provider_status_json JSON"
            ))
    if "site_filter_mode" not in columns:
        with engine.begin() as connection:
            connection.execute(text(
                "ALTER TABLE monitored_assets ADD COLUMN site_filter_mode VARCHAR NOT NULL DEFAULT 'all'"
            ))
    if "watched_sites_json" not in columns:
        with engine.begin() as connection:
            connection.execute(text(
                "ALTER TABLE monitored_assets ADD COLUMN watched_sites_json JSON"
            ))
    inspector = inspect(engine)
    if "provider_call_logs" in inspector.get_table_names():
        call_columns = {column["name"] for column in inspector.get_columns("provider_call_logs")}
        if "returned_count" not in call_columns:
            with engine.begin() as connection:
                connection.execute(text(
                    "ALTER TABLE provider_call_logs ADD COLUMN returned_count INTEGER NOT NULL DEFAULT 0"
                ))
        if "filtered_count" not in call_columns:
            with engine.begin() as connection:
                connection.execute(text(
                    "ALTER TABLE provider_call_logs ADD COLUMN filtered_count INTEGER NOT NULL DEFAULT 0"
                ))

def ensure_admin():
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.email == settings.ADMIN_EMAIL).first():
            db.add(User(email=settings.ADMIN_EMAIL, display_name="Administrator", role=RoleEnum.admin,
                        password_hash=get_password_hash(settings.ADMIN_PASSWORD)))
            db.commit()
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_schema_compatibility()
    ensure_admin()
    init_scheduler()
    yield
    shutdown_scheduler()

app = FastAPI(title=settings.APP_NAME, version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(web_router)
app.include_router(api_router, prefix="/api")

@app.get("/health")
async def health_check():
    return {"status": "ok"}
