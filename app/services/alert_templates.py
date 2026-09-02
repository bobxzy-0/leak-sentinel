from typing import Any

from app.core.crypto import crypto_service
from app.core.time import format_localtime
from app.services.finding_normalizer import normalize_finding


DEFAULT_TEMPLATE = """### 🚨 数据泄漏告警
- **涉及网站**：
{website_list}

- **情报来源**：{source}
- **监控对象**：{asset}
- **对象类型**：{asset_type}
- **对象内容**：{asset_value}
- **最早泄漏事件**：{earliest_breach}
- **泄漏字段**：{data_classes}
- **影响记录**：{record_count}
- **风险等级**：{severity}
- **新增事件**：{finding_count} 个
- **系统发现时间**：{detected_at}

**处置建议**：
{recommendations}"""


class SafeValues(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def severity_label(value: Any) -> str:
    try:
        level = int(value)
    except (TypeError, ValueError):
        level = 0
    return {4: "严重风险", 3: "高风险", 2: "中风险", 1: "低风险"}.get(level, "提示")


def _mask_value(value: str, asset_type: str) -> str:
    if not value:
        return "未提供"
    if asset_type == "email" and "@" in value:
        local, domain = value.split("@", 1)
        return f"{local[:2]}***@{domain}"
    if asset_type == "domain":
        parts = value.split(".")
        parts[0] = f"{parts[0][:2]}***"
        return ".".join(parts)
    if asset_type in ("password", "api_key", "token"):
        edge = 2 if asset_type == "password" else 4
    else:
        edge = 2
    if len(value) <= edge * 2:
        return "••••••"
    return f"{value[:edge]}***{value[-edge:]}"


def _recommendations(asset_type: str) -> str:
    items = {
        "email": ["确认受影响账号并立即修改相关网站密码", "排查密码复用并撤销现有登录会话", "启用多因素认证并检查异常登录"],
        "username": ["确认该用户名是否属于本企业人员", "修改相关网站密码并排查密码复用", "启用多因素认证并检查异常登录"],
        "password": ["立即废弃该密码", "排查所有可能复用该密码的系统并逐一修改", "撤销现有会话并检查异常登录"],
        "api_key": ["立即吊销并轮换该 API 密钥", "检查密钥调用日志和异常来源", "缩小新密钥权限并设置有效期"],
        "token": ["立即吊销并重新签发令牌", "检查令牌使用日志和异常访问", "缩短令牌有效期并限制授权范围"],
        "domain": ["确认涉及网站和受影响的企业账号", "通知相关人员修改密码并排查密码复用", "检查异常登录、会话和潜在入侵范围"],
    }.get(asset_type, ["确认泄漏真实性和影响范围", "轮换相关凭据并检查异常访问", "持续跟踪后续泄漏和攻击活动"])
    return "\n".join(f"{index}. {item}" for index, item in enumerate(items, 1))


def finding_values(finding: Any) -> dict[str, str]:
    findings = getattr(finding, "batch_findings", None) or [finding]
    normalized_items = []
    for item in findings:
        data = getattr(item, "raw_data_json", None) or {}
        source_value = getattr(getattr(item, "source", None), "value", "未知")
        normalized_items.append(normalize_finding(source_value, data))
    asset = getattr(finding, "asset", None)
    asset_type = getattr(getattr(asset, "asset_type", None), "value", "未知")
    asset_type_label = {
        "domain": "域名", "email": "电子邮箱", "username": "用户名",
        "password": "密码", "api_key": "API 密钥", "token": "令牌",
    }.get(asset_type, asset_type)
    ciphertext = getattr(asset, "value_ciphertext", "") if asset else ""
    try:
        raw_value = crypto_service.decrypt(ciphertext) if ciphertext else getattr(asset, "value", "")
    except Exception:
        raw_value = ""
    websites = list(dict.fromkeys(
        site for normalized in normalized_items for site in normalized["websites"]
    ))
    website = "、".join(websites) if websites else "数据源未提供"
    website_list = "\n".join(f"  - {site}" for site in websites) if websites else "  - 数据源未提供"
    dated_events = [
        (normalized["breach_time"], normalized["title"])
        for normalized in normalized_items if normalized["breach_time"]
    ]
    breach_date, title = min(dated_events, default=("数据源未提供", "未知事件"))
    sources = list(dict.fromkeys(normalized["source_label"] for normalized in normalized_items))
    classes = list(dict.fromkeys(
        field for normalized in normalized_items for field in normalized["data_classes"]
    ))
    counts = [normalized["record_count"] for normalized in normalized_items]
    numeric_counts = [count for count in counts if isinstance(count, (int, float))]
    record_count = sum(numeric_counts) if numeric_counts else next((count for count in counts if count), "数据源未提供")
    return {
        "asset": getattr(asset, "label", None) or "未命名对象",
        "asset_type": asset_type_label,
        "asset_value": _mask_value(str(raw_value), asset_type),
        "source": "、".join(sources),
        "website": website, "website_list": website_list,
        "breach_date": str(breach_date), "earliest_breach": f"{breach_date} · {title}",
        "data_classes": "、".join(classes) or "数据源未提供",
        "record_count": str(record_count),
        "finding_count": str(len(findings)),
        "external_ref": str(getattr(finding, "external_ref", "未知")),
        "severity": severity_label(getattr(finding, "severity", 0)),
        "detected_at": format_localtime(getattr(finding, "first_seen_at", None)) or "未知",
        "recommendations": _recommendations(asset_type),
    }


def render_body(finding: Any, config: dict[str, Any]) -> str:
    encrypted = config.get("body_template_ciphertext")
    template = crypto_service.decrypt(encrypted) if encrypted else DEFAULT_TEMPLATE
    return template.format_map(SafeValues(finding_values(finding)))


def payload_preview(template: str) -> str:
    return template.format_map(SafeValues({
        "asset": "企业邮箱", "asset_type": "邮箱", "asset_value": "se***@example.com",
        "source": "Have I Been Pwned", "website": "example.com", "website_list": "  - example.com",
        "breach_date": "2026-08-31", "earliest_breach": "2026-08-31 · Example Breach",
        "data_classes": "邮箱、密码", "finding_count": "1", "external_ref": "example-breach",
        "record_count": "1,234", "severity": "高风险", "detected_at": "2026-08-31 12:00:00",
        "recommendations": "1. 修改密码\n2. 启用多因素认证",
    }))
