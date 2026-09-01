from types import SimpleNamespace

from app.core.crypto import crypto_service
from app.services.alert_templates import finding_values, render_body


def test_custom_webhook_template_uses_safe_placeholders():
    finding = SimpleNamespace(
        asset=SimpleNamespace(
            label="企业邮箱", asset_type=SimpleNamespace(value="email"),
            value_ciphertext=crypto_service.encrypt("security@example.com"),
        ),
        source=SimpleNamespace(value="hibp_breach"), external_ref="event-1", severity=3,
        first_seen_at="2026-08-31", raw_data_json={
            "Domain": "example.com", "BreachDate": "2026-08-01", "DataClasses": ["Email", "Password"]
        },
    )
    config = {"body_template_ciphertext": crypto_service.encrypt("{asset}|{website}|{data_classes}|{unknown}")}
    assert render_body(finding, config) == "企业邮箱|example.com|Email、Password|{unknown}"


def test_default_alert_masks_object_and_lists_sites_before_source():
    finding = SimpleNamespace(
        asset=SimpleNamespace(
            label="企业邮箱", asset_type=SimpleNamespace(value="email"),
            value_ciphertext=crypto_service.encrypt("security@example.com"),
        ),
        source=SimpleNamespace(value="xposedornot"), external_ref="xon:example", severity=4,
        first_seen_at="2026-09-01 10:00:00", raw_data_json={
            "domain": "portal.example.com", "xposed_date": "2024",
            "xposed_data": "Email addresses;Passwords", "breach": "Example Leak",
            "xposed_records": 1000,
        },
    )
    values = finding_values(finding)
    body = render_body(finding, {})
    assert values["asset_value"] == "se***@example.com"
    assert values["source"] == "XposedOrNot"
    assert values["earliest_breach"] == "2024 · Example Leak"
    assert values["severity"] == "严重风险"
    assert body.index("涉及网站") < body.index("情报来源") < body.index("监控对象")
    assert "portal.example.com" in body
    assert "处置建议" in body


def test_batch_alert_merges_new_findings():
    asset = SimpleNamespace(
        label="企业邮箱", asset_type=SimpleNamespace(value="email"),
        value_ciphertext=crypto_service.encrypt("security@example.com"),
    )
    first = SimpleNamespace(
        asset=asset, source=SimpleNamespace(value="xposedornot"), external_ref="one",
        severity=3, first_seen_at="2026-09-01", raw_data_json={
            "domain": "one.example", "xposed_date": "2025", "breach": "Newer",
            "xposed_data": "Emails", "xposed_records": 10,
        },
    )
    second = SimpleNamespace(
        asset=asset, source=SimpleNamespace(value="hibp_breach"), external_ref="two",
        severity=4, first_seen_at="2026-09-01", raw_data_json={
            "Domain": "two.example", "BreachDate": "2020-01-01", "Name": "Older",
            "DataClasses": ["Passwords"], "PwnCount": 20,
        },
    )
    summary_data = vars(first).copy()
    summary_data.update(batch_findings=[first, second], severity=4)
    summary = SimpleNamespace(**summary_data)
    values = finding_values(summary)
    assert values["finding_count"] == "2"
    assert values["website"] == "one.example、two.example"
    assert values["source"] == "XposedOrNot、Have I Been Pwned"
    assert values["earliest_breach"] == "2020-01-01 · Older"
    assert values["record_count"] == "30"
