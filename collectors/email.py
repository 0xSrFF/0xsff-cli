import asyncio
import dns.resolver
from collectors.base import BaseCollector
from models.evidence import Evidence
from core.logger import log

def _sync_dns_query(target: str, record_type: str):
    """Synchronous DNS query running in a background thread."""
    try:
        # Set a strict timeout for the DNS resolver to prevent kernel hangs
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2.0
        resolver.lifetime = 2.0
        answers = resolver.resolve(target, record_type)
        return [r.to_text() for r in answers]
    except Exception:
        return []

class EmailCollector(BaseCollector):
    name = "email"

    async def collect(self, target: str) -> list[Evidence]:
        results = []
        
        # FIX: Wrap DNS queries in hard timeouts
        async def query_with_timeout(target: str, rtype: str):
            try:
                return await asyncio.wait_for(
                    asyncio.to_thread(_sync_dns_query, target, rtype),
                    timeout=3.0
                )
            except asyncio.TimeoutError:
                return []

        # 1. MX Records
        mx_records = await query_with_timeout(target, "MX")
        if mx_records:
            results.append(Evidence(source="mx_records", confidence=100, raw_data={"records": mx_records}))
            
        # 2. SPF Records
        txt_records = await query_with_timeout(target, "TXT")
        spf_record = next((r for r in txt_records if "v=spf1" in r), None)
        if spf_record:
            results.append(Evidence(source="spf_record", confidence=100, raw_data={"record": spf_record}))
            
        # 3. DMARC Records
        dmarc_target = f"_dmarc.{target}"
        dmarc_records = await query_with_timeout(dmarc_target, "TXT")
        dmarc_record = next((r for r in dmarc_records if "v=DMARC1" in r), None)
        if dmarc_record:
            results.append(Evidence(source="dmarc_record", confidence=100, raw_data={"record": dmarc_record}))
            
        return results
