import asyncio
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import settings
from app.models.models import AssetTypeEnum


@dataclass(frozen=True)
class ProviderResult:
    source: str
    external_ref: str
    severity: int
    data: dict[str, Any]


class HudsonRockProvider:
    """Community OSINT provider for domain, email and username statistics."""

    endpoints = {
        AssetTypeEnum.domain: ("search-by-domain", "domain"),
        AssetTypeEnum.email: ("search-by-email", "email"),
        AssetTypeEnum.username: ("search-by-username", "username"),
    }

    async def search(self, asset_type: AssetTypeEnum, value: str) -> list[ProviderResult]:
        if not settings.HUDSON_ROCK_ENABLED or asset_type not in self.endpoints:
            return []
        endpoint, param = self.endpoints[asset_type]
        url = f"{settings.HUDSON_ROCK_BASE_URL}/{endpoint}?{param}={quote(value)}"
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
            response = await client.get(url, headers={"user-agent": "leak-sentinel/1.0"})
            if response.status_code == 404:
                return []
            response.raise_for_status()
            payload = response.json()
        total = self._total(payload)
        if total <= 0:
            return []
        return [ProviderResult("hudson_rock", f"hudson-rock:{asset_type.value}:{value}", self._severity(total), payload)]

    @staticmethod
    def _total(payload: Any) -> int:
        if not isinstance(payload, dict):
            return 0
        for key in ("total", "totalEmployees", "total_corporate_services", "total_user_services"):
            value = payload.get(key)
            if isinstance(value, int):
                return value
        return sum(len(value) for value in payload.values() if isinstance(value, list))

    @staticmethod
    def _severity(total: int) -> int:
        return 4 if total >= 100 else 3 if total >= 10 else 2


class HIBPProvider:
    """HIBP v3 account lookup. HIBP only supports email assets here."""

    async def search(self, asset_type: AssetTypeEnum, value: str) -> list[ProviderResult]:
        if asset_type != AssetTypeEnum.email or not settings.HIBP_API_KEY:
            return []
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(value)}?truncateResponse=false"
        headers = {"hibp-api-key": settings.HIBP_API_KEY, "user-agent": "leak-sentinel/1.0"}
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 404:
                return []
            response.raise_for_status()
            breaches = response.json()
        results = []
        for breach in breaches:
            name = breach.get("Name", "unknown")
            data_classes = breach.get("DataClasses", [])
            severity = 4 if any(x in data_classes for x in ("Passwords", "Credit cards", "Bank account numbers")) else 3
            results.append(ProviderResult("hibp_breach", f"hibp:{name}", severity, breach))
        return results


class ProviderRegistry:
    def __init__(self):
        self.providers = [HudsonRockProvider(), HIBPProvider()]

    async def search(self, asset_type: AssetTypeEnum, value: str) -> list[ProviderResult]:
        outcomes = await asyncio.gather(
            *(provider.search(asset_type, value) for provider in self.providers), return_exceptions=True
        )
        results: list[ProviderResult] = []
        for outcome in outcomes:
            if isinstance(outcome, list):
                results.extend(outcome)
        return results
