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
        "total": 12, "employees": 2, "users": 10, "third_parties": 3,
        "last_employee_compromised": "2026-08-01T10:00:00Z",
        "last_user_compromised": "2026-07-01T10:00:00Z",
        "data": {"all_urls": [
            {"url": "https://portal.example.com/login", "occurrence": 8, "type": "employee"},
            {"url": "https://portal.example.com/sso", "occurrence": 4, "type": "client"},
        ]},
    })
    assert result["websites"] == ["portal.example.com"]
    assert result["breach_time"] == "2026-07-01T10:00:00Z"
    assert result["record_count"] == 12
    assert "员工 2" in result["description"]


def test_hudson_email_counts_both_service_groups():
    result = normalize_finding("hudson_rock", {
        "total_corporate_services": 0, "total_user_services": 5,
        "stealers": [{"url": "https://accounts.example.net", "date_compromised": "2024-01-01"}],
    })
    assert result["record_count"] == 5
    assert result["websites"] == ["accounts.example.net"]
    assert result["breach_time"] == "2024-01-01"


def test_provider_specific_fallbacks_are_not_reported_as_missing():
    assert normalize_finding("pwned_password", {"count": 42})["data_classes"] == ["密码"]
    assert normalize_finding("intelligence_x", {"bucket": "leaks.public"})["data_classes"] == ["leaks.public"]
