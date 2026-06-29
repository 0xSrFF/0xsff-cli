import asyncio
from models.asset import Asset
from models.enums import AssetType

class AssetInventory:
    def __init__(self):
        self._assets: dict[str, Asset] = {}
        self._lock = asyncio.Lock()

    def _get_key(self, asset_type: AssetType, value: str) -> str:
        return f"{asset_type.value}:{value}"

    async def add_asset(self, asset: Asset) -> bool:
        key = self._get_key(asset.type, asset.value)
        async with self._lock:
            if key in self._assets:
                # Merge evidence if the asset already exists
                self._assets[key].evidence.extend(asset.evidence)
                return False
            self._assets[key] = asset
            return True

    def get_all(self) -> list[Asset]:
        return list(self._assets.values())
