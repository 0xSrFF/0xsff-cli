import asyncio
from core.inventory import AssetInventory
from collectors.base import BaseCollector
from models.asset import Asset
from models.evidence import Evidence
from models.enums import AssetType
from core.logger import log

class Pipeline:
    def __init__(self, collectors: list[BaseCollector]):
        self.collectors = collectors
        self.inventory = AssetInventory()

    async def run(self, target: str):
        log(f"[+] Starting pipeline for {target}")
        
        root_asset = Asset(type=AssetType.DOMAIN, value=target)
        await self.inventory.add_asset(root_asset)

        await self._run_collector_batch([target])
        
        return self.inventory

    async def enrich(self, targets: list[str]):
        log(f"[+] Enriching {len(targets)} targets...")
        await self._run_collector_batch(targets)

    async def _run_collector_batch(self, targets: list[str]):
        tasks = []
        for target in targets:
            for collector in self.collectors:
                tasks.append(self._run_collector(collector, target))
        
        try:
            # FIX: Reduced timeout to 30 seconds so it doesn't feel stuck
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=30.0)
        except asyncio.TimeoutError:
            log("[!] Enrichment batch timed out after 30 seconds. Continuing...")

    async def _run_collector(self, collector: BaseCollector, target: str):
        try:
            # Hard timeout on individual collector
            results = await asyncio.wait_for(collector.collect(target), timeout=15.0)
            for item in results:
                if isinstance(item, Asset):
                    is_new = await self.inventory.add_asset(item)
                    if is_new:
                        log(f"  [{collector.name}] Found new asset: {item.type.value} -> {item.value}")
                elif isinstance(item, Evidence):
                    for asset in self.inventory.get_all():
                        if asset.value == target:
                            asset.evidence.append(item)
                            break
        except asyncio.TimeoutError:
            log(f"[!] Collector {collector.name} timed out on {target}")
        except Exception as e:
            log(f"[!] Collector {collector.name} failed on {target}: {e}")
