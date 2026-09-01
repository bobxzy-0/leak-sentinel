import logging
from typing import Any, Dict

import httpx

from app.core.crypto import crypto_service
from app.models.models import Finding
from app.services.alert_channels.base import AlertChannelBase
from app.services.alert_templates import render_body

logger = logging.getLogger(__name__)


class WebhookChannel(AlertChannelBase):
    """Webhook payload compatible with DingTalk and WeCom markdown robots."""

    async def send(self, finding: Finding, config: Dict[str, Any]) -> bool:
        webhook_url = crypto_service.decrypt(config.get("webhook_url_ciphertext", ""))
        if not webhook_url:
            logger.error("Webhook configuration missing or invalid")
            return False
        content = render_body(finding, config)
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "title": f"[S{finding.severity}] 数据泄漏告警",
                "text": content,
                "content": content,
            },
        }
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                response = await client.post(webhook_url, json=payload)
                response.raise_for_status()
                try:
                    result = response.json()
                except ValueError:
                    result = {}
                if result.get("errcode", 0) != 0:
                    logger.error("Webhook API error: %s", result)
                    return False
                return True
        except Exception:
            logger.exception("Failed to send webhook alert")
            return False
