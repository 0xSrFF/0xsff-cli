import requests
from core.logger import log

def run(target: str, config: dict):
    findings = []
    log(f"[*] 🔎 Checking breach history for {target}...")
    
    # Check Have I Been Pwned API (free, no key needed for domain search)
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}"
    headers = {
        "hibp-api-key": config.get("hibp_api_key", ""),  # Optional
        "user-agent": "0xsff"
    }
    
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            for breach in data:
                findings.append({
                    "asset": target,
                    "type": "breach_history",
                    "risk": "HIGH",
                    "reasons": [f"Found in {breach.get('Name')} breach ({breach.get('BreachDate')})"],
                    "tags": ["breach", "pwned", "leaked"],
                    "surface": "EXTERNAL_SURFACE"
                })
            log(f"[+] Found {len(data)} historical breaches")
        elif resp.status_code == 404:
            log("[+] No known breaches found")
        elif resp.status_code == 403:
            log("[!] HIBP API requires an API key for this search")
            
    except Exception as e:
        log(f"[!] Breach check error: {e}")
    
    return findings
