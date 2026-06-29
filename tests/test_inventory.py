import pytest
from core.inventory import AssetInventory
from models.asset import Asset
from models.enums import AssetType

@pytest.mark.asyncio
async def test_add_asset_and_merge():
    inventory = AssetInventory()
    asset1 = Asset(type=AssetType.DOMAIN, value="example.com")
    asset2 = Asset(type=AssetType.DOMAIN, value="example.com")
    
    # First add should be new
    is_new = await inventory.add_asset(asset1)
    assert is_new is True
    
    # Second add of the same asset should merge, not duplicate
    is_new_again = await inventory.add_asset(asset2)
    assert is_new_again is False
    
    # Inventory should only have 1 asset
    assert len(inventory.get_all()) == 1
