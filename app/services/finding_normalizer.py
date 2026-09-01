from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


SOURCE_LABELS = {
    "hudson_rock": "Hudson Rock",
    "hibp_breach": "Have I Been Pwned",
    "hibp_paste": "Have I Been Pwned",
    "hibp_stealer_log": "Have I Been Pwned",
    "pwned_password": "HIBP Pwned Passwords",
    "xposedornot": "XposedOrNot",
    "leakcheck": "LeakCheck",
    "whiteintel": "WhiteIntel",
    "intelligence_x": "Intelligence X",
}

SITE_KEYS = {
    "domain", "website", "url", "host", "hostname", "service", "service_url",
    "client_url", "origin", "site", "target_url",
}
DATE_KEYS = {
    "breachdate", "breach_date", "xposed_date", "date", "created_at", "added",
    "addeddate", "added_date", "timestamp", "time", "discovered_at", "last_seen",
    "lastseen", "first_seen", "indexed", "systemdate",
}
FIELD_KEYS = {
    "dataclasses", "data_classes", "xposed_data", "credentials", "fields", "data_fields",
    "exposed_data", "compromised_data", "record_types", "types",
}


def _walk(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _values_for_keys(data: dict[str, Any], keys: set[str]) -> list[Any]:
    values = []
    for key, value in _walk(data):
        if key.lower().replace("-", "_") in keys and value not in (None, "", [], {}):
            values.append(value)
    return values


def _strings(values: list[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates:
            if isinstance(candidate, str):
                parts = candidate.split(";") if ";" in candidate else [candidate]
                result.extend(part.strip() for part in parts if part.strip())
            elif isinstance(candidate, (int, float)):
                result.append(str(candidate))
    return list(dict.fromkeys(result))


def _site(value: str) -> str:
    parsed = urlsplit(value if "://" in value else f"//{value}")
    return parsed.hostname or value


def normalize_finding(source: str, data: dict[str, Any] | None) -> dict[str, Any]:
    """Convert provider-specific response fields into one stable detail schema."""
    data = data or {}
    sites = [_site(value) for value in _strings(_values_for_keys(data, SITE_KEYS))]
    dates = _strings(_values_for_keys(data, DATE_KEYS))
    fields = _strings(_values_for_keys(data, FIELD_KEYS))

    title = next(iter(_strings([
        data.get("Name") or data.get("breach") or data.get("name") or
        data.get("source") or data.get("title") or data.get("bucket") or ""
    ])), "")
    description = next(iter(_strings([
        data.get("Description") or data.get("details") or data.get("description") or
        data.get("message") or ""
    ])), "")
    reference = next(iter(_strings([
        data.get("references") or data.get("reference") or data.get("source_url") or ""
    ])), "")
    record_count = (
        data.get("PwnCount") or data.get("xposed_records") or data.get("count") or
        data.get("records") or data.get("total")
    )

    if source == "pwned_password":
        fields = ["密码"]
    elif source == "intelligence_x" and not fields:
        fields = _strings([data.get("bucket"), data.get("media")])
    elif source == "whiteintel" and not fields:
        fields = _strings([data.get("type"), data.get("category")])

    return {
        "source_label": SOURCE_LABELS.get(source, source),
        "title": title,
        "websites": list(dict.fromkeys(filter(None, sites))),
        "breach_time": dates[0] if dates else "",
        "data_classes": fields,
        "description": description,
        "reference": reference,
        "record_count": record_count,
    }
