import httpx
import asyncio
import os
from collectors.base import BaseCollector
from models.evidence import Evidence
from core.logger import log

def _sync_github_search(url: str, headers: dict):
    try:
        with httpx.Client(timeout=5.0) as client:
            return client.get(url, headers=headers)
    except Exception:
        return None

class GitHubCollector(BaseCollector):
    name = "github"

    # FIX: Expanded noise filter to catch cheat sheets and methodology repos
    NOISE_KEYWORDS = [
        "bug-bounty", "writeup", "reference", "bountyplz", "poc", 
        "exploit", "vulnerability", "disclosure", "hackerone", "awesome",
        "ssrf", "cheatsheet", "methodology", "top10", "webseclist", 
        "webhunt", "aws-customer", "security-incidents", "allthings"
    ]

    async def collect(self, target: str) -> list[Evidence]:
        results = []
        token = os.environ.get("GITHUB_TOKEN")
        
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"
            
        # Simple query to avoid 422 errors
        query = f'"{target}"'
        url = f"https://api.github.com/search/code?q={query}&per_page=5"
        
        try:
            resp = await asyncio.wait_for(
                asyncio.to_thread(_sync_github_search, url, headers),
                timeout=10.0
            )
            
            if resp is None:
                return results
                
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                
                if items:
                    valid_leaks = []
                    for item in items:
                        repo_name = item["repository"]["full_name"].lower()
                        file_name = item["path"].lower()
                        
                        # Filter out the noise (cheat sheets, writeups, methodology)
                        if any(noise in repo_name for noise in self.NOISE_KEYWORDS):
                            continue
                        if any(noise in file_name for noise in self.NOISE_KEYWORDS):
                            continue
                            
                        valid_leaks.append({
                            "repo": item["repository"]["full_name"], 
                            "file": item["path"],
                            "url": item.get("html_url", f"https://github.com/{item['repository']['full_name']}")
                        })
                        
                    if valid_leaks:
                        results.append(Evidence(
                            source="github_secrets",
                            confidence=90,
                            raw_data={
                                "total_count": len(valid_leaks),
                                "leaked_files": valid_leaks[:5]
                            }
                        ))
            elif resp.status_code == 403:
                log("[!] GitHubCollector: API rate limit exceeded.")
            else:
                log(f"[!] GitHubCollector: Received HTTP {resp.status_code}")
                
        except asyncio.TimeoutError:
            log("[!] GitHubCollector: Request timed out")
        except Exception as e:
            log(f"[!] GitHubCollector failed: {type(e).__name__}")
            
        return results
