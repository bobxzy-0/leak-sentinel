import hashlib
import json
from datetime import datetime
from dataclasses import replace
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.core.crypto import crypto_service
from app.models.models import Finding, FindingSourceEnum, MonitoredAsset, ProviderCallLog
from app.services.alert_dispatcher import AlertDispatcher
from app.services.finding_normalizer import normalize_finding
from app.services.providers import ProviderRegistry, ProviderResult

SITE_KEYS = ("url", "domain", "website", "host", "service")

def normalize_host(value: str) -> str | None:
    candidate = value.strip().lower()
    if not candidate or " " in candidate:
        return None
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    host = (parsed.hostname or "").rstrip(".")
    return host or None

def extract_related_sites(data, parent_key: str = "") -> set[str]:
    sites: set[str] = set()
    if isinstance(data, dict):
        for key, value in data.items():
            sites.update(extract_related_sites(value, str(key).lower()))
    elif isinstance(data, list):
        for value in data:
            sites.update(extract_related_sites(value, parent_key))
    elif isinstance(data, str) and any(key in parent_key for key in SITE_KEYS):
        host = normalize_host(data)
        if host:
            sites.add(host)
    return sites

def host_matches_pattern(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host.endswith(f".{suffix}") and host != suffix
    return host == pattern or host.endswith(f".{pattern}")

def filter_outcomes_by_sites(outcomes, patterns: list[str]):
    filtered = []
    for outcome in outcomes:
        if outcome.status in ("disabled", "error"):
            filtered.append(outcome)
            continue
        matched_results = []
        matched_sites: set[str] = set()
        for result in outcome.results:
            sites = extract_related_sites(result.data)
            current = {site for site in sites if any(host_matches_pattern(site, pattern) for pattern in patterns)}
            if current:
                matched_results.append(result)
                matched_sites.update(current)
        effective_count = len(matched_results)
        if outcome.provider == "hudson_rock" and matched_sites:
            effective_count = len(matched_sites)
        filtered.append(replace(
            outcome,
            results=matched_results,
            status="found" if effective_count else "clean",
            match_count=effective_count,
            filtered_count=max(outcome.returned_count - effective_count, 0),
        ))
    return filtered


def finding_signature(source: str, external_ref: str, severity: int, data: dict) -> str:
    normalized = normalize_finding(source, data)
    meaningful = {
        "external_ref": external_ref,
        "severity": severity,
        "title": normalized.get("title") or "",
        "websites": sorted(set(normalized.get("websites") or [])),
        "breach_time": normalized.get("breach_time") or "",
        "data_classes": sorted(set(normalized.get("data_classes") or [])),
        "description": normalized.get("description") or "",
        "reference": normalized.get("reference") or "",
        "record_count": normalized.get("record_count"),
    }
    return json.dumps(meaningful, sort_keys=True, separators=(",", ":"), default=str)


def fingerprint(asset_id: int, result: ProviderResult) -> str:
    stable = finding_signature(result.source, result.external_ref, result.severity, result.data)
    return hashlib.sha256(f"{asset_id}:{result.source}:{result.external_ref}:{stable}".encode()).hexdigest()


async def scan_asset(
    db: Session, asset: MonitoredAsset, trigger: str = "manual", provider_name: str | None = None,
) -> dict:
    value = crypto_service.decrypt(asset.value_ciphertext)
    outcomes = await ProviderRegistry().search_with_status(
        asset.asset_type, value, provider_name=provider_name,
    )
    if asset.site_filter_mode == "only" and asset.watched_sites_json:
        outcomes = filter_outcomes_by_sites(outcomes, asset.watched_sites_json)
    # Some providers return a statistics envelope even when its authoritative
    # match count is zero. Keep it in the call log, but never persist it as a leak.
    results = [
        result for outcome in outcomes if outcome.status == "found"
        for result in outcome.results
    ]
    created = 0
    new_findings = []
    for result in results:
        digest = fingerprint(asset.id, result)
        if db.query(Finding.id).filter(Finding.fingerprint == digest).first():
            continue
        # Compatibility with findings saved before semantic fingerprints were introduced.
        previous_versions = db.query(Finding).filter(
            Finding.asset_id == asset.id,
            Finding.source == FindingSourceEnum(result.source),
            Finding.external_ref == result.external_ref,
        ).all()
        current_signature = finding_signature(
            result.source, result.external_ref, result.severity, result.data,
        )
        if any(
            finding_signature(
                item.source.value, item.external_ref, item.severity, item.raw_data_json or {},
            ) == current_signature
            for item in previous_versions
        ):
            continue
        finding = Finding(
            asset_id=asset.id,
            source=FindingSourceEnum(result.source),
            external_ref=result.external_ref,
            raw_data_json=result.data,
            severity=result.severity,
            fingerprint=digest,
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)
        new_findings.append(finding)
        created += 1
    if new_findings:
        await AlertDispatcher(db).dispatch_batch(new_findings)
    checked_at = datetime.utcnow()
    if provider_name is None:
        asset.last_checked_at = checked_at
        if trigger == "automatic":
            asset.last_automatic_checked_at = checked_at
    provider_states = dict(asset.provider_status_json or {}) if provider_name else {}
    provider_states.update({
        outcome.provider: {
            "status": outcome.status,
            "count": outcome.match_count,
            "error": outcome.error,
            "returned_count": outcome.returned_count,
            "filtered_count": outcome.filtered_count,
            "checked_at": checked_at.isoformat(),
        }
        for outcome in outcomes
    })
    asset.provider_status_json = provider_states
    for outcome in outcomes:
        if outcome.status == "disabled":
            continue
        db.add(ProviderCallLog(
            asset_id=asset.id,
            provider=outcome.provider,
            target_type=asset.asset_type.value,
            trigger=trigger,
            status=outcome.status,
            match_count=outcome.match_count,
            returned_count=outcome.returned_count,
            filtered_count=outcome.filtered_count,
            duration_ms=outcome.duration_ms,
            error_message=outcome.error,
            called_at=checked_at,
        ))
    db.commit()
    return {
        "asset_id": asset.id, "provider": provider_name, "results": len(results),
        "new_findings": created,
        "outcomes": [{"provider": item.provider, "status": item.status, "error": item.error,
                      "count": item.match_count} for item in outcomes],
    }
