from app.services.alert_channels.base import AlertChannelBase
from app.models.models import Finding
from typing import Dict, Any
import logging
import asyncio
import json
import smtplib
from email.message import EmailMessage
from app.core.config import settings
from app.core.crypto import crypto_service
from app.services.alert_templates import render_body, severity_label

logger = logging.getLogger(__name__)

class EmailChannel(AlertChannelBase):
    async def send(self, finding: Finding, config: Dict[str, Any]) -> bool:
        try:
            recipients = json.loads(crypto_service.decrypt(config.get("recipients_ciphertext", "")))
            if not settings.SMTP_HOST or not settings.SMTP_FROM or not recipients:
                return False
            message = EmailMessage()
            message["Subject"] = f"[万联泄漏情报监控][{severity_label(finding.severity)}] 发现新的数据泄漏"
            message["From"] = settings.SMTP_FROM
            message["To"] = ", ".join(recipients)
            message.set_content(render_body(finding, config))
            await asyncio.to_thread(self._send, message)
            return True
        except Exception:
            logger.exception("Failed to send email alert")
            return False

    @staticmethod
    def _send(message: EmailMessage) -> None:
        port = settings.SMTP_PORT or (587 if settings.SMTP_USE_TLS else 25)
        with smtplib.SMTP(settings.SMTP_HOST, port, timeout=20) as smtp:
            if settings.SMTP_USE_TLS:
                smtp.starttls()
            if settings.SMTP_USERNAME:
                smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD or "")
            smtp.send_message(message)
