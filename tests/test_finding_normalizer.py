from app.services.finding_normalizer import normalize_finding


def test_xposedornot_fields_are_normalized():
    result = normalize_finding("xposedornot", {
        "breach": "ExampleBreach",
        "domain": "accounts.example.com",
        "xposed_date": "2025",
        "xposed_data": "Email addresses;Passwords;Usernames;",
        "xposed_records": 1234,
        "details": "Example incident",
    })
    assert result["websites"] == ["accounts.example.com"]
    assert result["breach_time"] == "2025"
    assert result["data_classes"] == ["Email addresses", "Passwords", "Usernames"]
    assert result["record_count"] == 1234
    assert result["title"] == "ExampleBreach"


def test_nested_hudson_fields_are_normalized():
    result = normalize_finding("hudson_rock", {
        "employees": [{"client_url": "https://portal.example.com/login", "last_seen": "2026-08-01"}],
        "credentials": ["email", "password"],
    })
    assert result["websites"] == ["portal.example.com"]
    assert result["breach_time"] == "2026-08-01"
    assert result["data_classes"] == ["email", "password"]


def test_provider_specific_fallbacks_are_not_reported_as_missing():
    assert normalize_finding("pwned_password", {"count": 42})["data_classes"] == ["密码"]
    assert normalize_finding("intelligence_x", {"bucket": "leaks.public"})["data_classes"] == ["leaks.public"]
