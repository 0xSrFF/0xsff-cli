import json
from pathlib import Path
from models.asset import Asset

# Create a hidden directory in the project root to store scan history
STATE_DIR = Path(".0xsff_state")
STATE_DIR.mkdir(exist_ok=True)

def save_state(target: str, assets: list[Asset]):
    """Serializes the Pydantic models to JSON and saves them to disk."""
    # mode="json" ensures datetimes and enums are properly formatted
    data = [asset.model_dump(mode="json") for asset in assets]
    
    file_path = STATE_DIR / f"{target}.json"
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

def load_state(target: str) -> list[Asset]:
    """Loads the previous scan state from disk and reconstructs the Pydantic models."""
    file_path = STATE_DIR / f"{target}.json"
    
    if not file_path.exists():
        return []
        
    with open(file_path, "r") as f:
        data = json.load(f)
        
    # Reconstruct the strict Pydantic Asset objects
    return [Asset.model_validate(asset_data) for asset_data in data]
