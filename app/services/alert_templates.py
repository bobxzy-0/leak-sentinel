from typing import Any

from app.core.crypto import crypto_service


DEFAULT_TEMPLATE = """### 🚨 数据泄漏告警
- **监控资产**：{asset}
- **资产类型**：{asset_type}
- **情报来源**：{source}
- **关联网站**：{website}
- **泄漏时间**：{breach_date}
- **泄漏字段**：{data_classes}
- **事件标识**：{external_ref}
- **发现时间**：{detected_at}"""


class SafeValues(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def finding_values(finding: Any) -> dict[str, str]:
    data = getattr(finding, "raw_data_json", None) or {}
    website = data.get("Domain") or data.get("domain") or data.get("website") or data.get("url") or "数据源未提供"
    breach_date = data.get("BreachDate") or data.get("breach_date") or data.get("date") or "数据源未提供"
    classes = data.get("DataClasses") or data.get("data_classes") or data.get("credentials") or "数据源未提供"
    if isinstance(classes, (list, tuple, set)):
        classes = "、".join(map(str, classes))
    asset = getattr(finding, "asset", None)
    return {
        "asset": getattr(asset, "label", None) or "未知资产",
        "asset_type": getattr(getattr(asset, "asset_type", None), "value", "未知"),
        "source": getattr(getattr(finding, "source", None), "value", "未知"),
        "website": str(website), "breach_date": str(breach_date), "data_classes": str(classes),
        "external_ref": str(getattr(finding, "external_ref", "未知")),
        "severity": str(getattr(finding, "severity", 0)),
        "detected_at": str(getattr(finding, "first_seen_at", "未知")),
    }


def render_body(finding: Any, config: dict[str, Any]) -> str:
    encrypted = config.get("body_template_ciphertext")
    template = crypto_service.decrypt(encrypted) if encrypted else DEFAULT_TEMPLATE
    return template.format_map(SafeValues(finding_values(finding)))


def payload_preview(template: str) -> str:
    return template.format_map(SafeValues({
        "asset": "示例资产", "asset_type": "email", "source": "hibp_breach",
        "website": "example.com", "breach_date": "2026-08-31",
        "data_classes": "邮箱、密码", "external_ref": "example-breach",
        "severity": "3", "detected_at": "2026-08-31 12:00:00",
    }))
