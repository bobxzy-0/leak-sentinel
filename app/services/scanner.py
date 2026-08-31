import hashlib
import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.crypto import crypto_service
from app.models.models import Finding, FindingSourceEnum, MonitoredAsset
from app.services.alert_dispatcher import AlertDispatcher
from app.services.providers import ProviderRegistry, ProviderResult


def fingerprint(asset_id: int, result: ProviderResult) -> str:
    stable = json.dumps(result.data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{asset_id}:{result.source}:{result.external_ref}:{stable}".encode()).hexdigest()


async def scan_asset(db: Session, asset: MonitoredAsset) -> dict:
    value = crypto_service.decrypt(asset.value_ciphertext)
    results = await ProviderRegistry().search(asset.asset_type, value)
    created = 0
    for result in results:
        digest = fingerprint(asset.id, result)
        if db.query(Finding.id).filter(Finding.fingerprint == digest).first():
            continue
        finding = Finding(
            asset_id=asset.id,
            source=FindingSourceEnum(result.source),
            external_ref=result.external_ref,
            raw_data_json=result.data,
            severity=result.severity,
            fingerprint=digest,
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)
        await AlertDispatcher(db).dispatch(finding)
        created += 1
    asset.last_checked_at = datetime.utcnow()
    db.commit()
    return {"asset_id": asset.id, "results": len(results), "new_findings": created}
