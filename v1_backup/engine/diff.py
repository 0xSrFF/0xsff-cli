def extract_assets(findings):
    """
    Normalize findings into comparable asset set
    Works even if history format changes
    """
    assets = set()

    if not findings:
        return assets

    for f in findings:
        if isinstance(f, dict) and "asset" in f:
            assets.add(f["asset"])

    return assets


def diff_scans(old_findings, new_findings):
    old_assets = extract_assets(old_findings)
    new_assets = extract_assets(new_findings)

    added = list(new_assets - old_assets)
    removed = list(old_assets - new_assets)

    return {
        "added": added,
        "removed": removed
    }
