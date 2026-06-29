def classify_surface(asset: str, tags: list):
    asset_lower = asset.lower()

    # AUTH surfaces
    if any(x in asset_lower for x in ["admin", "login", "auth", "panel"]):
        return "AUTH_SURFACE"

    # API surfaces
    if "api" in asset_lower:
        return "API_SURFACE"

    # DEV / TEST environments
    if any(x in asset_lower for x in ["dev", "test", "staging"]):
        return "DEV_SURFACE"

    # ROOT / INFRASTRUCTURE
    if asset_lower.count(".") == 1:
        return "INFRASTRUCTURE"

    # DEFAULT
    return "EXTERNAL_SURFACE"
