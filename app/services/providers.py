import asyncio
import hashlib
import time
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

@dataclass(frozen=True)
class ProviderOutcome:
    provider: str
    status: str
    results: list[ProviderResult]
    match_count: int = 0
    error: str | None = None
    duration_ms: int = 0
    returned_count: int = 0
    filtered_count: int = 0


class HudsonRockProvider:
    """Community OSINT provider for domain, email and username statistics."""

    endpoints = {
        AssetTypeEnum.domain: ("search-by-domain", "domain"),
        AssetTypeEnum.email: ("search-by-email", "email"),
        AssetTypeEnum.username: ("search-by-username", "username"),
    }
    name = "hudson_rock"

    def is_enabled_for(self, asset_type: AssetTypeEnum) -> bool:
        return settings.HUDSON_ROCK_ENABLED and asset_type in self.endpoints

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
    """HIBP v3 free breach catalog for domains and paid account lookup for emails."""

    name = "hibp"

    def is_enabled_for(self, asset_type: AssetTypeEnum) -> bool:
        return asset_type == AssetTypeEnum.domain or (
            asset_type == AssetTypeEnum.email and bool(settings.HIBP_API_KEY)
        )

    async def search(self, asset_type: AssetTypeEnum, value: str) -> list[ProviderResult]:
        if asset_type == AssetTypeEnum.domain:
            url = f"https://haveibeenpwned.com/api/v3/breaches?domain={quote(value)}"
            headers = {"user-agent": "leak-sentinel/1.0"}
        elif asset_type == AssetTypeEnum.email and settings.HIBP_API_KEY:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(value)}?truncateResponse=false"
            headers = {"hibp-api-key": settings.HIBP_API_KEY, "user-agent": "leak-sentinel/1.0"}
        else:
            return []
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


class PwnedPasswordsProvider:
    """HIBP Pwned Passwords k-anonymity range lookup."""

    name = "pwned_passwords"

    def is_enabled_for(self, asset_type: AssetTypeEnum) -> bool:
        return asset_type == AssetTypeEnum.password

    async def search(self, asset_type: AssetTypeEnum, value: str) -> list[ProviderResult]:
        if asset_type != AssetTypeEnum.password:
            return []
        digest = hashlib.sha1(value.encode()).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
            response = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={"Add-Padding": "true", "user-agent": "leak-sentinel/1.0"},
            )
            response.raise_for_status()
        for line in response.text.splitlines():
            candidate, count = line.split(":", 1)
            if candidate == suffix and int(count) > 0:
                return [ProviderResult("pwned_password", f"pwned-password:{prefix}", 4, {"count": int(count)})]
        return []


class XposedOrNotProvider:
    """Free, keyless XposedOrNot email breach analytics."""

    name = "xposedornot"

    def is_enabled_for(self, asset_type: AssetTypeEnum) -> bool:
        return settings.XPOSEDORNOT_ENABLED and asset_type == AssetTypeEnum.email

    async def _request_json(self, client: httpx.AsyncClient, url: str) -> dict[str, Any] | None:
        last_error = None
        for attempt in range(3):
            try:
                response = await client.get(
                    url, headers={
                        "user-agent": "leak-sentinel/1.0 (+https://github.com/bobxzy-0/leak-sentinel)",
                        "accept": "application/json",
                    },
                    follow_redirects=True,
                )
                if response.status_code == 404:
                    return None
                if response.status_code in (403, 429) or response.status_code >= 500:
                    last_error = RuntimeError(
                        f"XposedOrNot HTTP {response.status_code}: {response.text[:180]}"
                    )
                    if attempt < 2:
                        await asyncio.sleep(1 << attempt)
                        continue
                response.raise_for_status()
                return response.json()
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                last_error = exc
                if attempt < 2:
                    await asyncio.sleep(1 << attempt)
                    continue
        raise RuntimeError(f"XposedOrNot request failed after 3 attempts: {last_error}")

    async def search(self, asset_type: AssetTypeEnum, value: str) -> list[ProviderResult]:
        if not self.is_enabled_for(asset_type):
            return []
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
            if asset_type == AssetTypeEnum.email:
                check_url = f"{settings.XPOSEDORNOT_BASE_URL}/v1/check-email/{quote(value)}?details=true"
                try:
                    payload = await self._request_json(client, check_url)
                except (RuntimeError, httpx.HTTPStatusError):
                    payload = await self._request_json(
                        client,
                        f"{settings.XPOSEDORNOT_BASE_URL}/v1/breach-analytics?email={quote(value)}",
                    )
            else:
                return []
        if not payload or payload.get("Error") or payload.get("status") == "Not Found":
            return []
        if asset_type == AssetTypeEnum.email:
            details = ((payload.get("ExposedBreaches") or {}).get("breaches_details") or [])
            if not details:
                details = payload.get("breaches") or []
                if len(details) == 1 and isinstance(details[0], list):
                    details = details[0]
        results = []
        for index, item in enumerate(details):
            if not isinstance(item, dict):
                item = {"breach": str(item)}
            ref = item.get("breach") or item.get("breachID") or f"result-{index + 1}"
            results.append(ProviderResult("xposedornot", f"xon:{ref}", 3, item))
        return results


class LeakCheckProvider:
    """LeakCheck public email/username lookup, upgraded to Pro v2 when a key is configured."""

    name = "leakcheck"

    def is_enabled_for(self, asset_type: AssetTypeEnum) -> bool:
        if not settings.LEAKCHECK_ENABLED:
            return False
        if asset_type in (AssetTypeEnum.email, AssetTypeEnum.username):
            return True
        return bool(settings.LEAKCHECK_API_KEY) and asset_type == AssetTypeEnum.domain

    async def search(self, asset_type: AssetTypeEnum, value: str) -> list[ProviderResult]:
        if not self.is_enabled_for(asset_type):
            return []
        headers = {"Accept": "application/json", "user-agent": "leak-sentinel/1.0"}
        if settings.LEAKCHECK_API_KEY:
            url = f"{settings.LEAKCHECK_PRO_URL}/query/{quote(value)}"
            headers["X-API-Key"] = settings.LEAKCHECK_API_KEY
        else:
            url = f"{settings.LEAKCHECK_PUBLIC_URL}?check={quote(value)}"
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
            response = await client.get(url, headers=headers)
            if response.status_code == 404:
                return []
            response.raise_for_status()
            payload = response.json()
        if not payload.get("success", True) or not payload.get("found", bool(payload.get("result") or payload.get("sources"))):
            return []
        items = payload.get("result") or payload.get("sources") or [payload]
        if not isinstance(items, list):
            items = [items]
        results = []
        for index, item in enumerate(items):
            data = dict(item) if isinstance(item, dict) else {"source": item}
            if not settings.LEAKCHECK_API_KEY:
                data["fields"] = payload.get("fields", [])
                data["found"] = payload.get("found", len(items))
                data.setdefault("website", data.get("name"))
            ref = data.get("name") or data.get("source") or f"result-{index + 1}"
            date = data.get("date", "unknown")
            results.append(ProviderResult("leakcheck", f"leakcheck:{ref}:{date}", 3, data))
        return results


class ProviderRegistry:
    def __init__(self):
        self.providers = [
            HudsonRockProvider(), HIBPProvider(), PwnedPasswordsProvider(),
            XposedOrNotProvider(), LeakCheckProvider(),
        ]

    async def search(self, asset_type: AssetTypeEnum, value: str) -> list[ProviderResult]:
        outcomes = await asyncio.gather(
            *(provider.search(asset_type, value) for provider in self.providers), return_exceptions=True
        )
        results: list[ProviderResult] = []
        for outcome in outcomes:
            if isinstance(outcome, list):
                results.extend(outcome)
        return results

    async def search_with_status(
        self, asset_type: AssetTypeEnum, value: str, provider_name: str | None = None,
    ) -> list[ProviderOutcome]:
        selected = [
            provider for provider in self.providers
            if provider_name is None or provider.name == provider_name
        ]
        if provider_name is not None and not selected:
            raise ValueError(f"Unknown provider: {provider_name}")
        enabled = [provider for provider in selected if provider.is_enabled_for(asset_type)]
        disabled = [provider for provider in selected if not provider.is_enabled_for(asset_type)]
        async def execute(provider):
            started = time.perf_counter()
            try:
                response = await provider.search(asset_type, value)
                return provider, response, None, int((time.perf_counter() - started) * 1000)
            except Exception as exc:
                return provider, [], exc, int((time.perf_counter() - started) * 1000)

        responses = await asyncio.gather(*(execute(provider) for provider in enabled))
        outcomes: list[ProviderOutcome] = []
        for provider, response, error, duration_ms in responses:
            if error:
                outcomes.append(ProviderOutcome(provider.name, "error", [], error=str(error)[:300], duration_ms=duration_ms))
                continue
            count = len(response)
            if provider.name == "hudson_rock" and response:
                count = provider._total(response[0].data)
            if provider.name == "pwned_passwords" and response:
                count = response[0].data.get("count", 0)
            outcomes.append(ProviderOutcome(
                provider.name, "found" if count else "clean", response, count,
                duration_ms=duration_ms, returned_count=count,
            ))
        outcomes.extend(ProviderOutcome(provider.name, "disabled", []) for provider in disabled)
        return outcomes
