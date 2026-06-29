from models.asset import Asset

class DiffEngine:
    def compare(self, old_assets: list[Asset], new_assets: list[Asset]) -> dict:
        """
        Compares two inventories and identifies:
        - Added assets (New attack surface)
        - Removed assets (Decommissioned surface)
        - Changed assets (Existing assets with new evidence/ports/headers)
        """
        old_map = {asset.value: asset for asset in old_assets}
        new_map = {asset.value: asset for asset in new_assets}

        added = [new_map[k] for k in new_map if k not in old_map]
        removed = [old_map[k] for k in old_map if k not in new_map]
        
        # Check for changes in existing assets (e.g., we found new evidence today)
        changed = []
        for k in new_map:
            if k in old_map:
                old_ev_count = len(old_map[k].evidence)
                new_ev_count = len(new_map[k].evidence)
                if new_ev_count > old_ev_count:
                    changed.append(new_map[k])

        return {
            "added": added,
            "removed": removed,
            "changed": changed
        }
