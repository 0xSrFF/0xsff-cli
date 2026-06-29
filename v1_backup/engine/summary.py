from collections import Counter

def generate_summary(findings):
    return {
        "total": len(findings),
        "risk": Counter(f["risk"] for f in findings if isinstance(f, dict) and "risk" in f),
        "surface": Counter(f.get("surface", "UNKNOWN") for f in findings if isinstance(f, dict))
    }

def generate_narrative(findings):
    narrative = []
    for f in findings:
        if not isinstance(f, dict):
            continue
            
        asset = f.get('asset', 'Unknown')
        risk = f.get('risk', 'LOW')
        surface = f.get('surface', 'UNKNOWN')
        reasons = f.get('reasons', [])
        
        if risk in ["HIGH", "CRITICAL"]:
            reason_str = ", ".join(reasons) if reasons else "multiple security concerns"
            narrative.append(f"[{risk}] {asset} is a {surface} with {reason_str}.")
            
    return narrative if narrative else ["No critical narratives generated."]
