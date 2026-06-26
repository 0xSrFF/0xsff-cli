import requests
from core.logger import log

def run(target: str, config: dict):
    findings = []
    token = config.get("github_token", "")
    log(f"[*] 🕵️ Smart Leak Hunt for {target}...")

    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    # We don't just want "mentions"; we want SECRETS.
    # These queries look for sensitive keywords + the target domain.
    queries = [
        f'"{target}" password',
        f'"{target}" api_key',
        f'"{target}" secret',
        f'"{target}" token',
        f'"{target}" extension:env'  # Looks for .env files
    ]

    for q in queries:
        url = f"https://api.github.com/search/code?q={q}&per_page=2" # Keep it small to save quota
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('items', []):
                    html_url = item.get('html_url')
                    
                    # Prevent duplicates
                    if any(f['asset'] == html_url for f in findings):
                        continue
                        
                    findings.append({
                        "asset": html_url,
                        "type": "smart_leak",
                        "risk": "HIGH", # Leaks are critical
                        "reasons": [f"Sensitive pattern: {q}"],
                        "tags": ["leak", "sensitive_data", "github"],
                        "surface": "EXTERNAL_SURFACE"
                    })
            elif resp.status_code == 403:
                log("[!] Rate limit hit. Stopping search.")
                break
        except Exception as e:
            log(f"[!] Search error: {e}")

    return findings
