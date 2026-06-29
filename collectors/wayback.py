import httpx
from collectors.base import BaseCollector
from models.evidence import Evidence
from core.logger import log

class WaybackCollector(BaseCollector):
    name = "wayback"

    async def collect(self, target: str) -> list[Evidence]:
        results = []
        
        # Keywords that indicate high-value historical endpoints
        interesting_keywords = [
            "admin", "login", "api", "config", "backup", ".env", "wp-admin", 
            "phpinfo", "test", "dev", "staging", "old", "debug", "sql", "git"
        ]
        
        # Query the CDX API for all historical URLs matching *.target.com/*
        url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&collapse=urlkey&fl=original,timestamp,statuscode"
        
        # Add a User-Agent so we don't get blocked as a generic bot
        headers = {"User-Agent": "0xsff/2.0 (Exposure Intelligence Framework)"}
        
        try:
            # Increased timeout to 45 seconds for large targets
            async with httpx.AsyncClient(timeout=45.0, headers=headers) as client:
                resp = await client.get(url)
                
                # Explicitly handle HTTP errors (like 403 Forbidden or 429 Too Many Requests)
                if resp.status_code != 200:
                    log(f"[!] WaybackCollector: Received HTTP {resp.status_code} for {target}")
                    return results
                    
                # Wayback sometimes returns HTML instead of JSON when overloaded
                try:
                    data = resp.json()
                except Exception:
                    log(f"[!] WaybackCollector: Received invalid JSON (likely HTML) for {target}")
                    return results
                
                # data[0] is the header row, the rest are the records
                if len(data) > 1:
                    urls = data[1:]
                    interesting_urls = []
                    
                    for row in urls:
                        if len(row) >= 3:
                            original_url = row[0]
                            timestamp = row[1]
                            status = row[2]
                            
                            # Filter for interesting keywords and valid HTTP status codes (2xx or 3xx)
                            if any(kw in original_url.lower() for kw in interesting_keywords):
                                if status.startswith("2") or status.startswith("3"):
                                    interesting_urls.append({
                                        "url": original_url,
                                        "timestamp": timestamp,
                                        "status": status
                                    })
                                    
                    if interesting_urls:
                        results.append(
                            Evidence(
                                source="wayback_machine",
                                confidence=90,
                                raw_data={
                                    "total_snapshots": len(urls),
                                    "interesting_urls": interesting_urls[:20] # Limit to top 20 for the terminal report
                                }
                            )
                        )
        except Exception as e:
            # Log the EXACT exception type so we know what's happening
            log(f"[!] WaybackCollector failed for {target}: {type(e).__name__} -> {e}")
            
        return results
