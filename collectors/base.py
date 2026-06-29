from abc import ABC, abstractmethod
from models.asset import Asset
from models.evidence import Evidence

class BaseCollector(ABC):
    name: str = "base"
    
    @abstractmethod
    async def collect(self, target: str) -> list[Asset | Evidence]:
        """
        Collectors must return a list of newly discovered Assets or Evidence.
        They NEVER calculate risk or make security judgments.
        """
        pass
