from app.models.models import FindingSourceEnum


def test_provider_sources_are_mappable():
    assert FindingSourceEnum("hudson_rock") is FindingSourceEnum.hudson_rock
    assert FindingSourceEnum("hibp_breach") is FindingSourceEnum.hibp_breach
