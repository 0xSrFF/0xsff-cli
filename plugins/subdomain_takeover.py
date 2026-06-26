import dns.resolver
import requests
from core.logger import log

def run(target: str, config: dict):
    findings = []
    log(f"[*] 🔍 Checking for subdomain takeover vulnerabilities...")
    
    # Common CNAME patterns that indicate takeover risk
    takeover_indicators = {
        "github.io": "GitHub Pages",
        "herokuapp.com": "Heroku",
        "s3.amazonaws.com": "AWS S3",
        "azurewebsites.net": "Azure",
        "cloudfront.net": "CloudFront",
        "firebaseapp.com": "Firebase",
        "bitbucket.io": "Bitbucket",
        "shopify.com": "Shopify"
    }
    
    # Get subdomains from DNS module or scan common ones
    common_subs = ["www", "dev", "test", "staging", "api", "admin", "blog"]
    
    for sub in common_subs:
        full_domain = f"{sub}.{target}"
        try:
            answers = dns.resolver.resolve(full_domain, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).rstrip('.')
                for service, name in takeover_indicators.items():
                    if service in cname:
                        findings.append({
                            "asset": full_domain,
                            "type": "subdomain_takeover",
                            "risk": "HIGH",
                            "reasons": [f"CNAME points to {name} ({cname}) - potential takeover"],
                            "tags": ["takeover", "dns", cname.split('.')[0]],
                            "surface": "EXTERNAL_SURFACE"
                        })
        except:
            pass  # Domain doesn't exist or no CNAME
    
    return findings
