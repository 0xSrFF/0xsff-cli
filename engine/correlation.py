from engine.scoring import score_asset
from engine.surface_classifier import classify_surface

def correlate(target, data):
    findings = []
    
    # Extract core data
    subdomains = data.get("subdomains", [])
    http = data.get("http", {})
    ports = data.get("ports", [])
    headers = data.get("headers", [])
    tech = data.get("tech", [])
    
    # 1. Process Core Modules (Subdomains & Root)
    for s in subdomains:
        risk, reasons, tags = score_asset("subdomain", s, http, ports, headers, tech)
        findings.append({
            "asset": s, "type": "subdomain", "risk": risk,
            "reasons": reasons, "tags": tags, "surface": classify_surface(s, tags)
        })

    risk, reasons, tags = score_asset("root", target, http, ports, headers, tech)
    findings.append({
        "asset": target, "type": "root", "risk": risk,
        "reasons": reasons, "tags": tags, "surface": classify_surface(target, tags)
    })

    # 2. Collect Plugin Data (DO NOT run them again, just collect)
    # The dispatcher already ran them. We just grab the results.
    plugin_keys = ["github", "leaks", "shodan", "censys"] 
    for key in plugin_keys:
        plugin_findings = data.get(key, [])
        if plugin_findings:
            findings.extend(plugin_findings)

    return findings
