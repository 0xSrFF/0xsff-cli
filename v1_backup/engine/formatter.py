def format_asset(asset_type, value, risk="LOW", status="ACTIVE"):
    return {
        "type": asset_type,
        "asset": value,
        "risk": risk,
        "status": status
    }
