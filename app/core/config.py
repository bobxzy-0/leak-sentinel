from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    APP_NAME: str = "万联泄漏情报监控"
    APP_HOST: str = "127.0.0.1"
    APP_PORT: int = 8000
    DATABASE_URL: str = "sqlite:///./leak_sentinel.db"
    MASTER_KEY: str
    JWT_SECRET_KEY: str
    JWT_EXPIRE_MINUTES: int = 60 * 24 * 7
    HIBP_API_KEY: Optional[str] = None
    HIBP_RATE_LIMIT_RPM: int = 10
    HUDSON_ROCK_ENABLED: bool = True
    HUDSON_ROCK_BASE_URL: str = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
    SCAN_INTERVAL_MINUTES: int = 60
    HTTP_TIMEOUT_SECONDS: int = 20
    BREACH_CATALOG_SYNC_CRON: str = "0 0 * * *"
    
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: Optional[int] = None
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_FROM: Optional[str] = None
    SMTP_USE_TLS: bool = True
    ADMIN_EMAIL: str = "admin@example.com"
    ADMIN_PASSWORD: str

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
