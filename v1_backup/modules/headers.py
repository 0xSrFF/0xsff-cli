import requests
from core.logger import log

def run_headers(target: str):
    findings = []
    # Try both http and https, but prioritize https for security headers
    urls = [f"https://{target}", f"http://{target}"]
    
    for url in urls:
        try:
            # allow_redirects=True is key here to catch headers on the final page
            resp = requests.get(url, timeout=10, allow_redirects=True)
            headers = resp.headers
            
            security_headers = {
                "Strict-Transport-Security": "missing_hsts",
                "Content-Security-Policy": "missing_csp",
                "X-Frame-Options": "missing_xfo",
                "X-Content-Type-Options": "missing_xcto"
            }

            missing = []
            for header, tag in security_headers.items():
                if header not in headers:
                    missing.append(tag)
            
            # Only report if we actually found the site and headers are missing
            if missing and resp.status_code < 400:
                findings.append({
                    "asset": target,
                    "type": "header_check",
                    "risk": "MEDIUM",
                    "reasons": missing,
                    "tags": ["misconfiguration"],
                    "surface": "EXTERNAL_SURFACE"
                })
            break # Stop after the first successful connection
        except Exception as e:
            continue

    return findings
