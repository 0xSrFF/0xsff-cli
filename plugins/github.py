import requests
from core.logger import log

def run(target: str, config: dict):
    findings = []
    token = config.get("github_token", "")
    log(f"[*] Searching GitHub for exposure related to {target}...")

    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    query = target
    url = f"https://api.github.com/search/code?q={query}&per_page=5"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get('items', []):
                repo_name = item['repository']['full_name']
                path = item['path']
                findings.append({
                    "asset": item.get('html_url', 'N/A'),
                    "type": "github_exposure",
                    "risk": "MEDIUM",
                    "reasons": [f"Found in public repo: {repo_name} (File: {path})"],
                    "tags": ["public_exposure", "code_reference"],
                    "surface": "EXTERNAL_SURFACE"
                })
        elif resp.status_code == 403:
            log("[!] GitHub API rate limit exceeded.")
    except Exception as e:
        log(f"[!] GitHub search failed: {e}")

    return findings
