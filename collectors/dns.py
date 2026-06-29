import asyncio
import socket
from collectors.base import BaseCollector
from models.asset import Asset
from models.evidence import Evidence
from models.enums import AssetType

class DNSCollector(BaseCollector):
    name = "dns"

    async def collect(self, target: str) -> list[Asset]:
        assets = []
        try:
            # Async DNS resolution using the event loop
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(target, None, family=socket.AF_INET)
            
            # Deduplicate IPs
            ips = list({info[4][0] for info in infos})
            for ip in ips:
                asset = Asset(
                    type=AssetType.IP,
                    value=ip,
                    parent=target,
                    evidence=[
                        Evidence(
                            source="dns_resolution",
                            confidence=100,
                            raw_data={"hostname": target, "ip": ip}
                        )
                    ]
                )
                assets.append(asset)
        except socket.gaierror:
            pass
            
        return assets
