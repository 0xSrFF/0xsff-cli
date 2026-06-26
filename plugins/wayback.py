import requests
from core.logger import log

def run(target: str, config: dict):
    findings = []
    log(f"[*] Mining Wayback Machine for {target}...")
    
    # Added limit, timestamp filter (2020+), and status code filter to prevent timeouts
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&collapse=urlkey&fl=original&limit=1000&filter=statuscode:200&from=20200101"
    
    try:
        resp = requests.get(url, timeout=120) # Increased timeout
        if resp.status_code == 200:
            data = resp.json()
            
            # Skip header row
            urls = [item[0] for item in data[1:] if len(item) > 0]
            
            # Look for interesting endpoints and files
            interesting = [
                "/admin", "/login", "/api/", "/backup", "/config", 
                "/.env", "/wp-admin", "/phpmyadmin", "/.git", 
                "/server-status", "/debug", "/test", "/dev",
                ".zip", ".tar.gz", ".sql", ".bak"
            ]
            
            for url in urls:
                for pattern in interesting:
                    if pattern in url.lower():
                        findings.append({
                            "asset": url,
                            "type": "wayback_url",
                            "risk": "MEDIUM",
                            "reasons": [f"Found archived endpoint: {pattern}"],
                            "tags": ["wayback", "endpoint", "archived"],
                            "surface": "EXTERNAL_SURFACE"
                        })
                        break
                        
            log(f"[+] Found {len(findings)} interesting archived URLs")
            
    except requests.exceptions.Timeout:
        log(f"[!] Wayback Machine timed out. Target might be too large.")
    except Exception as e:
        log(f"[!] Wayback Machine error: {e}")
    
    return findings
