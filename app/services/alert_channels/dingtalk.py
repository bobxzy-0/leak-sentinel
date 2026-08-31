from app.services.alert_channels.base import AlertChannelBase
from app.models.models import Finding
from typing import Dict, Any
import httpx
import time
import hmac
import hashlib
import base64
import urllib.parse
from app.core.crypto import crypto_service
import logging

logger = logging.getLogger(__name__)

class DingTalkChannel(AlertChannelBase):
    async def send(self, finding: Finding, config: Dict[str, Any]) -> bool:
        webhook_url = crypto_service.decrypt(config.get("webhook_url_ciphertext", ""))
        secret = crypto_service.decrypt(config.get("secret_ciphertext", ""))
        
        if not webhook_url:
            logger.error("DingTalk configuration missing or invalid")
            return False

        url = webhook_url
        if secret:
            timestamp = str(round(time.time() * 1000))
            hmac_code = hmac.new(secret.encode(), f'{timestamp}\n{secret}'.encode(), digestmod=hashlib.sha256).digest()
            sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
            separator = "&" if "?" in webhook_url else "?"
            url = f"{webhook_url}{separator}timestamp={timestamp}&sign={sign}"
        
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "title": f"[S{finding.severity}] 数据泄漏告警",
                "text": f"### 🚨 [S{finding.severity}] 数据泄漏告警\n- **监控对象**：{finding.asset.label if finding.asset else 'Global'}\n- **数据源**：{finding.source.value}\n- **事件标识**：{finding.external_ref}\n- **发现时间**：{finding.first_seen_at}"
            }
        }
        
        async with httpx.AsyncClient() as client:
            try:
                res = await client.post(url, json=payload)
                res.raise_for_status()
                data = res.json()
                if data.get("errcode") != 0:
                    logger.error(f"DingTalk API error: {data}")
                    return False
                return True
            except Exception as e:
                logger.error(f"Failed to send DingTalk alert: {str(e)}")
                return False
