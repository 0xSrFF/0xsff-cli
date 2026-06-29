import httpx
from collectors.base import BaseCollector
from models.asset import Asset
from models.enums import AssetType
from models.evidence import Evidence
from core.logger import log

class CertspotterCollector(BaseCollector):
    name = "certspotter"

    async def collect(self, target: str) -> list[Asset]:
        assets = []
        seen_subdomains = set()
        
        # Certspotter's highly stable API
        url = f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names"
        headers = {"User-Agent": "0xsff/2.0"}
        
        try:
            async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
                resp = await client.get(url)
                
                if resp.status_code != 200:
                    log(f"[!] CertspotterCollector: Received HTTP {resp.status_code}")
                    return assets
                    
                data = resp.json()
                
                for entry in data:
                    # dns_names contains the SANs (Subject Alternative Names)
                    for sub in entry.get("dns_names", []):
                        sub = sub.strip().lower()
                        
                        # Clean up wildcards
                        if sub.startswith("*."):
                            sub = sub[2:]
                            
                        if not sub or sub in seen_subdomains:
                            continue
                            
                        # Only keep valid subdomains
                        if sub.endswith(f".{target}") or sub == target:
                            seen_subdomains.add(sub)
                            assets.append(
                                Asset(
                                    type=AssetType.DOMAIN,
                                    value=sub,
                                    parent=target,
                                    evidence=[
                                        Evidence(
                                            source="certificate_transparency",
                                            confidence=95,
                                            raw_data={"issuer": entry.get("issuer"), "cert_id": entry.get("id")}
                                        )
                                    ]
                                )
                            )
        except Exception as e:
            log(f"[!] CertspotterCollector failed: {type(e).__name__} -> {e}")
            
        return assets
