def score_asset(asset_type, asset, http, ports, headers, tech=None):
    risk = "LOW"
    reasons = []
    tags = []

    # 1. Check HTTP Status
    if isinstance(http, dict) and asset in http:
        status = http[asset].get("status", 0)
        if status == 200:
            reasons.append("http_accessible")
            tags.append("live_host")
        elif status == 403:
            reasons.append("access_forbidden")
            tags.append("protected_surface")

    # 2. Check Ports
    if isinstance(ports, list):
        for p in ports:
            port_num = None
            if isinstance(p, dict):
                if p.get("asset") == asset:
                    port_num = p.get("port")
            elif isinstance(p, int):
                port_num = p
            
            if port_num:
                reasons.append(f"port_{port_num}_open")
                if port_num in [80, 443, 8080, 8443]:
                    if "web_service" not in tags:
                        tags.append("web_service")

    # 3. Check Headers
    if isinstance(headers, list):
        for h in headers:
            if isinstance(h, dict) and h.get("asset") == asset:
                missing_headers = h.get("reasons", [])
                reasons.extend(missing_headers)
                if "missing_hsts" in missing_headers or "missing_csp" in missing_headers:
                    if "misconfigured_security" not in tags:
                        tags.append("misconfigured_security")

    # 4. Check Tech Stack
    if tech and isinstance(tech, list):
        for t in tech:
            if isinstance(t, dict) and t.get("asset") == asset:
                tech_tags = t.get("tags", [])
                for tag in tech_tags:
                    if tag not in tags:
                        tags.append(tag)
                if "outdated" in tech_tags:
                    reasons.append("outdated_software")
                    if "vulnerable" not in tags:
                        tags.append("vulnerable")

    # 5. Determine Risk
    if "authentication_surface" in tags or "admin" in asset:
        risk = "HIGH"
        if "high_value_surface" not in tags:
            tags.append("high_value_surface")
    elif len(reasons) > 3:
        risk = "MEDIUM"
    
    return risk, reasons, tags
