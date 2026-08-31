from app.models.models import AssetTypeEnum
from app.services.providers import (
    HIBPProvider, HudsonRockProvider, LeakCheckProvider, WhiteIntelProvider, XposedOrNotProvider,
)


def test_hudson_total_and_severity():
    provider = HudsonRockProvider()
    assert provider._total({"total": 12}) == 12
    assert provider._total({"stealers": [{}, {}]}) == 2
    assert provider._severity(1) == 2
    assert provider._severity(10) == 3
    assert provider._severity(100) == 4


def test_hibp_free_domain_catalog_is_enabled_without_key():
    assert HIBPProvider().is_enabled_for(AssetTypeEnum.domain)


def test_free_providers_support_expected_asset_types():
    assert XposedOrNotProvider().is_enabled_for(AssetTypeEnum.email)
    assert XposedOrNotProvider().is_enabled_for(AssetTypeEnum.domain)
    assert LeakCheckProvider().is_enabled_for(AssetTypeEnum.email)
    assert LeakCheckProvider().is_enabled_for(AssetTypeEnum.username)
    assert not LeakCheckProvider().is_enabled_for(AssetTypeEnum.password)
    assert not WhiteIntelProvider().is_enabled_for(AssetTypeEnum.domain)
