import httpx
import asyncio
from collectors.base import BaseCollector
from models.evidence import Evidence
from core.logger import log

def _sync_check_bucket(url: str):
    """Synchronous HTTP GET running in a background thread."""
    try:
        # Strict timeout to prevent OS-level hangs
        with httpx.Client(timeout=3.0, follow_redirects=True) as client:
            resp = client.get(url)
            return resp.status_code, resp.text
    except Exception:
        return None, ""

class CloudCollector(BaseCollector):
    name = "cloud"

    async def collect(self, target: str) -> list[Evidence]:
        results = []
        
        buckets_to_check = [
            f"{target}.s3.amazonaws.com",
            f"www.{target}.s3.amazonaws.com",
            f"assets.{target}.s3.amazonaws.com",
            f"{target}.blob.core.windows.net",
            f"www.{target}.blob.core.windows.net"
        ]
        
        urls = [f"https://{b}" for b in buckets_to_check]
        
        # FIX: Wrap each thread in asyncio.wait_for to prevent WSL kernel hangs
        async def check_with_timeout(url: str):
            try:
                return await asyncio.wait_for(
                    asyncio.to_thread(_sync_check_bucket, url),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                return None, ""

        tasks = [check_with_timeout(u) for u in urls]
        exists_results = await asyncio.gather(*tasks)
        
        for bucket, (status, text) in zip(buckets_to_check, exists_results):
            if status is None:
                continue
                
            is_s3 = "amazonaws" in bucket
            is_azure = "windows" in bucket
            exists = False
            
            if is_s3:
                if status == 403 or status == 200:
                    exists = True
                elif status == 404 and "NoSuchBucket" not in text:
                    exists = True
            elif is_azure:
                if status != 404 or "BlobNotFound" not in text:
                    exists = True
                    
            if exists:
                provider = "AWS S3" if is_s3 else "Azure Blob"
                results.append(Evidence(
                    source="cloud_bucket", 
                    confidence=95, 
                    raw_data={"bucket": bucket, "provider": provider, "http_status": status}
                ))
                
        return results
