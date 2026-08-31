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
    ensure_admin()
    init_scheduler()
    yield
    shutdown_scheduler()

app = FastAPI(title="Leak Sentinel", version="1.0.0", lifespan=lifespan)

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
