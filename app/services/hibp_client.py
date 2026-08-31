import httpx
import hashlib
from tenacity import retry, stop_after_attempt, wait_exponential
from app.core.crypto import crypto_service
from app.models.models import HibpConfig
from sqlalchemy.orm import Session
import logging

logger = logging.getLogger(__name__)

class PaidFeatureDisabledError(Exception):
    pass

class HibpConfigService:
    @staticmethod
    def get_active_api_key(db: Session) -> str | None:
        config = db.query(HibpConfig).first()
        if config and config.api_key_ciphertext:
            return crypto_service.decrypt(config.api_key_ciphertext)
        from app.core.config import settings
        return settings.HIBP_API_KEY

class HibpClient:
    BASE_URL = "https://haveibeenpwned.com/api/v3"
    PWNED_PASSWORDS_URL = "https://api.pwnedpasswords.com/range"
    
    def __init__(self, db: Session):
        self.db = db
        self.api_key = HibpConfigService.get_active_api_key(db)

    async def is_paid_enabled(self) -> bool:
        return bool(self.api_key)
        
    def _get_headers(self, auth=True):
        headers = {"user-agent": "leak-monitor-platform"}
        if auth and self.api_key:
            headers["hibp-api-key"] = self.api_key
        return headers

    async def check_password(self, password: str, add_padding=True) -> tuple[bool, int]:
        sha1_full = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_full[:5], sha1_full[5:]
        headers = {}
        if add_padding:
            headers["Add-Padding"] = "true"
            
        async with httpx.AsyncClient() as client:
            res = await client.get(f"{self.PWNED_PASSWORDS_URL}/{prefix}", headers=headers)
            if res.status_code == 200:
                for line in res.text.splitlines():
                    parts = line.split(':')
                    if len(parts) == 2:
                        hash_suffix, count = parts
                        if hash_suffix == suffix:
                            return True, int(count)
            return False, 0
            
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    async def search_breached_account(self, email: str):
        if not await self.is_paid_enabled():
            raise PaidFeatureDisabledError("HIBP API Key required. Please configure in settings.")
        async with httpx.AsyncClient() as client:
            res = await client.get(f"{self.BASE_URL}/breachedaccount/{email}", headers=self._get_headers())
            if res.status_code == 404:
                return []
            res.raise_for_status()
            return res.json()
