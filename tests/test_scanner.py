from app.models.models import FindingSourceEnum
from app.services.providers import ProviderOutcome, ProviderResult
from app.services.scanner import (
    extract_related_sites, filter_outcomes_by_sites, finding_signature, host_matches_pattern,
)


def test_provider_sources_are_mappable():
    assert FindingSourceEnum("hudson_rock") is FindingSourceEnum.hudson_rock
    assert FindingSourceEnum("hibp_breach") is FindingSourceEnum.hibp_breach


def test_site_matching_is_domain_aware():
    assert host_matches_pattern("login.example.com", "example.com")
    assert host_matches_pattern("login.example.com", "*.example.com")
    assert not host_matches_pattern("example.com", "*.example.com")
    assert not host_matches_pattern("notexample.com", "example.com")


def test_extract_and_filter_related_sites():
    result = ProviderResult(
        source="hibp_breach", external_ref="Example", severity=3,
        data={"Domain": "accounts.example.com", "DataClasses": ["Email addresses", "Passwords"]},
    )
    assert "accounts.example.com" in extract_related_sites(result.data)
    outcome = ProviderOutcome(provider="hibp", status="found", results=[result], match_count=1, returned_count=1)
    kept = filter_outcomes_by_sites([outcome], ["example.com"])[0]
    assert kept.status == "found" and kept.match_count == 1
    removed = filter_outcomes_by_sites([outcome], ["other.example"])[0]
    assert removed.status == "clean" and removed.match_count == 0 and removed.filtered_count == 1


def test_finding_signature_ignores_non_meaningful_provider_changes():
    first = finding_signature(
        "hudson_rock", "event", 3,
        {"total": 2, "totalStealers": 36000000, "data": {"all_urls": ["https://a.example"]}},
    )
    same = finding_signature(
        "hudson_rock", "event", 3,
        {"logo": "changed", "totalStealers": 37000000, "total": 2,
         "data": {"all_urls": ["https://a.example"]}},
    )
    changed = finding_signature(
        "hudson_rock", "event", 3,
        {"total": 3, "totalStealers": 37000000, "data": {"all_urls": ["https://a.example"]}},
    )
    assert first == same
    assert first != changed
