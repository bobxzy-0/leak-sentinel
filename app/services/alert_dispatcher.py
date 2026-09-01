from app.models.models import Finding, AlertChannel, AlertLog, ChannelTypeEnum
from app.services.alert_channels.dingtalk import DingTalkChannel
from app.services.alert_channels.wecom import WecomChannel
from app.services.alert_channels.email import EmailChannel
from app.services.alert_channels.webhook import WebhookChannel
from sqlalchemy.orm import Session
import logging
import json

logger = logging.getLogger(__name__)

class AlertDispatcher:
    def __init__(self, db: Session):
        self.db = db
        self.channels = {
            ChannelTypeEnum.webhook: WebhookChannel(),
            ChannelTypeEnum.dingtalk: DingTalkChannel(),
            ChannelTypeEnum.wecom: WecomChannel(),
            ChannelTypeEnum.email: EmailChannel()
        }

    async def dispatch(self, finding: Finding):
        if not finding.is_new:
            return
            
        user_id = finding.asset.owner_id if finding.asset else None
        
        if user_id:
            active_channels = self.db.query(AlertChannel).filter(
                AlertChannel.owner_id == user_id, 
                AlertChannel.is_enabled
            ).all()
        else:
            # Global alerts (e.g. breach catalog sync)
            active_channels = self.db.query(AlertChannel).filter(
                AlertChannel.owner_id.is_(None),
                AlertChannel.is_enabled
            ).all()

        for channel in active_channels:
            if channel.channel_type in self.channels:
                try:
                    config = json.loads(channel.config_ciphertext) if channel.config_ciphertext else {}
                    await self._send_and_log(channel, finding, config)
                except Exception as e:
                    logger.error(f"Failed to parse config for channel {channel.id}: {e}")

        finding.is_new = False
        self.db.commit()

    async def _send_and_log(self, channel: AlertChannel, finding: Finding, config: dict):
        handler = self.channels[channel.channel_type]
        success = await handler.send(finding, config)
        
        log_entry = AlertLog(
            finding_id=finding.id,
            channel_id=channel.id,
            status="success" if success else "failed",
            error_message=None if success else "Failed to send alert (see logs)"
        )
        self.db.add(log_entry)
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
