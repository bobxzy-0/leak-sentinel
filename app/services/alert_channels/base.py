from abc import ABC, abstractmethod
from app.models.models import Finding
from typing import Dict, Any

class AlertChannelBase(ABC):
    @abstractmethod
    async def send(self, finding: Finding, config: Dict[str, Any]) -> bool:
        pass
