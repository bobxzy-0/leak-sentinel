from types import SimpleNamespace

from app.core.crypto import crypto_service
from app.services.alert_templates import render_body


def test_custom_webhook_template_uses_safe_placeholders():
    finding = SimpleNamespace(
        asset=SimpleNamespace(label="企业邮箱", asset_type=SimpleNamespace(value="email")),
        source=SimpleNamespace(value="hibp_breach"), external_ref="event-1", severity=3,
        first_seen_at="2026-08-31", raw_data_json={
            "Domain": "example.com", "BreachDate": "2026-08-01", "DataClasses": ["Email", "Password"]
        },
    )
    config = {"body_template_ciphertext": crypto_service.encrypt("{asset}|{website}|{data_classes}|{unknown}")}
    assert render_body(finding, config) == "企业邮箱|example.com|Email、Password|{unknown}"
