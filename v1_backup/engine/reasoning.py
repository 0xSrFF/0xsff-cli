from core.logger import log

def analyze_attack_paths(findings):
    paths = []
    
    # Create a map of all missing headers across all assets for broader context
    global_missing_headers = []
    for f in findings:
        if isinstance(f, dict):
            global_missing_headers.extend(f.get("reasons", []))

    for finding in findings:
        if not isinstance(finding, dict):
            continue
            
        asset = finding['asset']
        tags = finding.get('tags', [])
        reasons = finding.get('reasons', [])
        surface = finding.get('surface', '')
        
        # 1. Outdated Tech + Open Port
        if 'outdated' in tags and ('port_80_open' in reasons or 'port_443_open' in reasons):
            paths.append({
                "asset": asset,
                "path_type": "EXPLOITABLE_SERVICE",
                "severity": "HIGH",
                "description": f"{asset} is running outdated software on an open port."
            })
            
        # 2. Auth Surface + Any Security Misconfiguration (Broader check)
        if 'AUTH_SURFACE' in surface and ('misconfigured_security' in tags or 'missing_hsts' in global_missing_headers):
             paths.append({
                "asset": asset,
                "path_type": "SESSION_HIJACKING",
                "severity": "MEDIUM",
                "description": f"{asset} is a high-value auth surface with potential security misconfigurations."
            })

    return paths
