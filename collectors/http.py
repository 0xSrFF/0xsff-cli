import httpx
import asyncio
import re
from collectors.base import BaseCollector
from models.evidence import Evidence
from core.logger import log

class HTTPCollector(BaseCollector):
    name = "http"

    async def collect(self, target: str) -> list[Evidence]:
        results = []
        urls = [f"https://{target}", f"http://{target}"]
        
        # Strict timeout: 3 seconds to connect, 5 seconds total
        timeout_config = httpx.Timeout(5.0, connect=3.0)
        
        async with httpx.AsyncClient(timeout=timeout_config, verify=False, follow_redirects=True) as client:
            for url in urls:
                try:
                    # Hard timeout on the request itself to prevent WSL/Network hangs
                    resp = await asyncio.wait_for(client.get(url), timeout=6.0)
                    
                    server = resp.headers.get("server", "Unknown")
                    status = resp.status_code
                    
                    title = "No Title"
                    if "text/html" in resp.headers.get("content-type", ""):
                        match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
                        if match:
                            title = match.group(1).strip()
                            
                    results.append(
                        Evidence(
                            source=f"http_{status}",
                            confidence=100,
                            raw_data={
                                "url": str(resp.url),
                                "status": status,
                                "server": server,
                                "title": title
                            }
                        )
                    )
                    
                    # If HTTPS worked, we don't need to check HTTP
                    if url.startswith("https"):
                        break
                        
                except asyncio.TimeoutError:
                    log(f"[!] HTTPCollector: {url} timed out (Hard timeout)")
                except httpx.RequestError as e:
                    log(f"[!] HTTPCollector: {url} failed -> {type(e).__name__}")
                    
        return results
