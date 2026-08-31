from app.services.alert_channels.base import AlertChannelBase
from app.models.models import Finding
from typing import Dict, Any
import httpx
from app.core.crypto import crypto_service
import logging

logger = logging.getLogger(__name__)

class WecomChannel(AlertChannelBase):
    async def send(self, finding: Finding, config: Dict[str, Any]) -> bool:
        webhook_url = crypto_service.decrypt(config.get("webhook_url_ciphertext", ""))
        
        if not webhook_url:
            logger.error("Wecom configuration missing")
            return False

        payload = {
            "msgtype": "markdown",
            "markdown": {
                "content": f"## ⚠️ Data Breach Alert\n> **Asset**: <font color=\"warning\">{finding.asset.label if finding.asset else 'Global'}</font>\n> **Source**: {finding.external_ref}\n> **Severity**: {finding.severity}\n> **Time**: {finding.first_seen_at}"
            }
        }
        
        async with httpx.AsyncClient() as client:
            try:
                res = await client.post(webhook_url, json=payload)
                res.raise_for_status()
                data = res.json()
                if data.get("errcode") != 0:
                    logger.error(f"Wecom API error: {data}")
                    return False
                return True
            except Exception as e:
                logger.error(f"Failed to send Wecom alert: {str(e)}")
                return False
