from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from app.core.config import settings


def local_datetime(value: datetime) -> datetime:
    """Treat database-naive timestamps as UTC and convert for presentation."""
    aware = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    return aware.astimezone(ZoneInfo(settings.APP_TIMEZONE))


def format_localtime(value: datetime | str | None, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    if not value:
        return ""
    if isinstance(value, str):
        return value
    return local_datetime(value).strftime(fmt)
