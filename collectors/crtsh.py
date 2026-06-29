import httpx
from collectors.base import BaseCollector
from models.asset import Asset
from models.enums import AssetType
from models.evidence import Evidence
from core.logger import log

class CrtShCollector(BaseCollector):
    name = "crtsh"

    async def collect(self, target: str) -> list[Asset]:
        assets = []
        seen_subdomains = set()
        
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        headers = {"User-Agent": "0xsff/2.0"}
        
        try:
            # Increased timeout to 30s and enabled follow_redirects
            async with httpx.AsyncClient(timeout=30.0, headers=headers, follow_redirects=True) as client:
                resp = await client.get(url)
                
                # crt.sh frequently returns 500 or 503 for large queries
                if resp.status_code != 200:
                    log(f"[!] CrtShCollector: Received HTTP {resp.status_code} from crt.sh (Server might be overloaded)")
                    return assets
                    
                # crt.sh sometimes returns an HTML block page instead of JSON
                try:
                    data = resp.json()
                except Exception as json_err:
                    log(f"[!] CrtShCollector: Failed to parse JSON. Response is likely HTML. Error: {json_err}")
                    return assets
                
                for entry in data:
                    # name_value can contain multiple domains separated by newlines (SANs)
                    name_values = entry.get("name_value", "").split("\n")
                    
                    for sub in name_values:
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
                                            raw_data={"issuer": entry.get("issuer_name"), "cert_id": entry.get("id")}
                                        )
                                    ]
                                )
                            )
        except Exception as e:
            # Log the exact exception type so we know what's happening
            log(f"[!] CrtShCollector failed: {type(e).__name__} -> {e}")
            
        return assets
