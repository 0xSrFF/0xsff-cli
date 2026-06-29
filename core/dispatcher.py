from core.logger import log, Colors
from core.config import load_config
from core.plugin_loader import load_plugins

from modules.dns import run_dns
from modules.subdomains import run_subdomains
from modules.http import run_http
from modules.ports import run_ports
from modules.headers import run_headers
from modules.tech import run_tech

from engine.correlation import correlate
from engine.diff import diff_scans
from engine.summary import generate_summary, generate_narrative
from engine.reasoning import analyze_attack_paths
from storage.db import load_history, save_history
from output.report import generate_report


def get_priority(risk, tags):
    if risk == "HIGH" and ("authentication_surface" in tags or "high_value_surface" in tags):
        return "CRITICAL"
    if risk == "HIGH":
        return "HIGH"
    if risk == "MEDIUM":
        return "MEDIUM"
    return "LOW"


def dispatch_scan(target: str, intel_mode: bool = False, report_mode: str = None):
    config = load_config()
    log(f"[+] TARGET: {target}\n")

    # 1. Run Core Modules
    dns = run_dns(target)
    subdomains = run_subdomains(target)
    http = run_http(target)
    ports = run_ports(target)
    headers = run_headers(target)
    tech = run_tech(target)
    
    all_data = {
        "dns": dns, "subdomains": subdomains, "http": http,
        "ports": ports, "headers": headers, "tech": tech
    }

    # 2. Run Dynamic Plugins
    plugins = load_plugins()
    for plugin in plugins:
        try:
            plugin_results = plugin.run(target, config)
            if isinstance(plugin_results, list):
                all_data[plugin.__name__] = plugin_results
        except Exception as e:
            log(f"[!] Plugin {plugin.__name__} failed: {e}")

    # 3. Correlate Data
    findings = correlate(target, all_data)
    attack_paths = analyze_attack_paths(findings)

    # 4. History & Diff
    history = load_history()
    old_findings = history.get(target, [])
    changes = diff_scans(old_findings, findings)

    if intel_mode:
        findings = [f for f in findings if f["risk"] in ["HIGH", "CRITICAL"]]

    summary = generate_summary(findings)
    narrative = generate_narrative(findings)

    # --- TERMINAL OUTPUT ---
    log("\n[SUMMARY]")
    log(str(summary))
    
    log("\n[NARRATIVE]")
    for line in narrative:
        log(line)

    if attack_paths:
        log("\n[ATTACK PATHS IDENTIFIED]")
        for path in attack_paths:
            log(f"[{path['severity']}] {path['path_type']}: {path['description']}")
    else:
        log("\n[ATTACK PATHS] No specific high-risk paths identified.")

    log("\n[NEW ASSETS]")
    log(str(changes["added"]) if changes["added"] else "None")

    log("\n[REMOVED ASSETS]")
    log(str(changes["removed"]) if changes["removed"] else "None")

    # --- CLEAN INTELLIGENCE RESULTS UI ---
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*25} INTELLIGENCE RESULTS {'='*25}{Colors.ENDC}\n")

    for f in findings:
        priority = get_priority(f["risk"], f.get("tags", []))
        
        # Determine colors and text icons based on risk
        if f['risk'] == "HIGH" or priority == "CRITICAL":
            risk_color = Colors.FAIL
            icon = f"{Colors.FAIL}[!]{Colors.ENDC}"
        elif f['risk'] == "MEDIUM":
            risk_color = Colors.WARNING
            icon = f"{Colors.WARNING}[~]{Colors.ENDC}"
        else:
            risk_color = Colors.BLUE
            icon = f"{Colors.BLUE}[+]{Colors.ENDC}"
            
        asset_str = f"{Colors.BOLD}{Colors.CYAN}{f['asset']}{Colors.ENDC}"
        risk_str = f"{risk_color}{Colors.BOLD}[{f['risk']} | {priority}]{Colors.ENDC}"
        surface_str = f"{Colors.UNDERLINE}{f.get('surface', 'UNKNOWN')}{Colors.ENDC}"
        tags_str = f"{Colors.GREEN}{', '.join(f.get('tags', [])) or 'no_tags'}{Colors.ENDC}"
        reasons_str = f"{Colors.WARNING}{', '.join(f.get('reasons', []))}{Colors.ENDC}"
        
        print(f" {icon} {risk_str} {asset_str}")
        print(f"    {Colors.BOLD}├─ Surface:{Colors.ENDC} {surface_str}")
        print(f"    {Colors.BOLD}├─ Tags:   {Colors.ENDC} {tags_str}")
        print(f"    {Colors.BOLD}└─ Reasons:{Colors.ENDC} {reasons_str}\n")

    history[target] = findings
    save_history(history)

    if report_mode:
        generate_report(target, findings, report_mode)

    log(f"\n{Colors.BOLD}{Colors.GREEN}[+] Phase 12 complete. Scan finished successfully.{Colors.ENDC}")
