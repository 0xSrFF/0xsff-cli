import requests
from core.logger import log
import socket

def run(target: str, config: dict):
    findings = []
    log(f"[*]  Querying InternetDB for {target}...")
    
    # Resolve domain to IP
    try:
        ip = socket.gethostbyname(target)
        url = f"https://internetdb.shodan.io/{ip}"
        
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            
            # Check for vulnerabilities
            if data.get('cpe'):
                for cpe in data['cpe']:
                    findings.append({
                        "asset": f"{target} ({ip})",
                        "type": "internetdb_cpe",
                        "risk": "MEDIUM",
                        "reasons": [f"Software identified: {cpe}"],
                        "tags": ["software", "cpe", "version"],
                        "surface": "INFRASTRUCTURE"
                    })
            
            # Check for open ports
            if data.get('ports'):
                for port in data['ports']:
                    findings.append({
                        "asset": f"{target}:{port}",
                        "type": "internetdb_port",
                        "risk": "LOW",
                        "reasons": [f"Open port detected via Shodan"],
                        "tags": ["port", "shodan", f"port_{port}"],
                        "surface": "INFRASTRUCTURE"
                    })
            
            # Check for vulnerabilities
            if data.get('vulns'):
                for vuln in data['vulns']:
                    findings.append({
                        "asset": f"{target} ({ip})",
                        "type": "internetdb_vuln",
                        "risk": "HIGH",
                        "reasons": [f"Known vulnerability: {vuln}"],
                        "tags": ["vulnerability", "cve", "shodan"],
                        "surface": "INFRASTRUCTURE"
                    })
                    
            log(f"[+] InternetDB: {len(data.get('ports', []))} ports, {len(data.get('vulns', []))} vulns")
            
    except socket.gaierror:
        log(f"[!] Could not resolve {target}")
    except Exception as e:
        log(f"[!] InternetDB error: {e}")
    
    return findings
