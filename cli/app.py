import socket
socket.setdefaulttimeout(3.0)

import typer
import asyncio
import time
import json
import os
import shlex
import sys
from pathlib import Path
from datetime import datetime, timezone
from itertools import cycle

from rich.console import Console
from rich.table import Table
from rich import box
from rich.live import Live
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.pipeline import Pipeline
from collectors.dns import DNSCollector
from collectors.certspotter import CertspotterCollector
from collectors.http import HTTPCollector
from collectors.wayback import WaybackCollector
from collectors.email import EmailCollector
from collectors.cloud import CloudCollector
from collectors.github import GitHubCollector

from models.enums import AssetType, RiskLevel
from engines.correlation import CorrelationEngine
from engines.reasoning import ReasoningEngine
from engines.analysis import AnalysisEngine
from storage.state import save_state, load_state

console = Console()
app = typer.Typer(help="0xsff - Exposure Intelligence Framework")

# --- COLORED BANNER ---
BANNER = """
[bold cyan]
███████╗ ███╗   ███╗ ██╗   ██╗ ██████╗ ███████╗
██╔════╝ ████╗ ████║ ██║   ██║ ██══██╗ ██╔════╝
███████╗ ██╔████╔██║ ██║   ██║ ██████╝ █████╗  
╚════██║ ██║╚██╔╝██║ ██║   ██║ ██╔═██╗ ██╔══╝  
███████║ ██║ ╚═╝ ██║ ╚██████╔╝ ██║ ██║ ██╗
╚══════╝ ╚═╝     ╚═╝  ╚═════╝  ╚═╝ ╚═╝ ╚═╝
[/bold cyan]
[bold white]        Exposure Intelligence CLI v1.0.0[/bold white]
[bold white]                Author: Smurf / 0xsff[/bold white]
[bold white]================================================================================[/bold white]
[bold red][!] ⚠️ DISCLAIMER:[/bold red] For educational and authorized testing purposes only.
    The author assumes no responsibility for misuse or damage caused by this tool.
[bold white]--------------------------------------------------------------------------------[/bold white]
[bold cyan][i] 👤 ABOUT:[/bold cyan] Built by Smurf / 0xsff
    [bold green]Offensive Security[/bold green] • [bold yellow]Pentesting[/bold yellow] • [bold magenta]Exposure Analysis[/bold magenta]
    Finding weaknesses before attackers do.
[bold white]================================================================================[/bold white]
"""

def print_banner():
    console.print(BANNER)

def print_help():
    console.print("\n[bold cyan]Available Commands:[/bold cyan]")
    console.print("  [bold white]scan <target>[/bold white]      Run a full intelligence scan against a victim.")
    console.print("  [bold white]asset <domain>[/bold white]     Deep dive into a specific asset from the last scan.")
    console.print("  [bold white]clear[/bold white]              Clear the terminal screen.")
    console.print("  [bold white]help[/bold white]               Show this help menu.")
    console.print("  [bold white]exit, quit[/bold white]         Exit the framework.\n")

def print_stat_block(title: str, stats: dict):
    if title: console.print(f"\n[bold]{title}[/bold]\n")
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column(style="bold cyan", justify="right")
    table.add_column()
    for k, v in stats.items(): table.add_row(k, str(v))
    console.print(table)

def print_header(target: str, scan_id: str, start_time: str, has_history: bool):
    console.print("\n[bold magenta]Victim Profile[/bold magenta]")
    console.print("──────────────\n")
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column(style="bold cyan", justify="right")
    table.add_column()
    table.add_row("Victim", f"[bold yellow]{target}[/bold yellow]")
    table.add_row("Scan ID", scan_id)
    table.add_row("Mode", "Full Intelligence")
    table.add_row("Started", start_time)
    table.add_row("Previous Scan", "[green]Yes[/green]" if has_history else "[dim]No[/dim]")
    console.print(table)

def loading_animation(message: str, duration: float = 0.5):
    """Show a loading animation with spinner."""
    spinner = cycle(['⠋', '⠙', '', '⠸', '⠼', '⠴', '', '⠧', '⠇', '⠏'])
    start = time.time()
    while time.time() - start < duration:
        frame = next(spinner)
        console.print(f"\r[bold cyan]{frame}[/bold cyan] {message}", end="", flush=True)
        time.sleep(0.1)
    console.print(f"\r[bold green]✓[/bold green] {message}")

# --- CORE LOGIC ---
def run_scan(target: str):
    start_time = time.time()
    now = datetime.now(timezone.utc)
    scan_id = now.strftime("%Y-%m-%d-%H%M%S")
    start_time_str = now.strftime("%H:%M:%S UTC")
    
    old_assets = load_state(target)
    has_history = len(old_assets) > 0
    print_header(target, scan_id, start_time_str, has_history)
    
    # --- PHASE 1 ---
    console.print(f"\n[bold yellow]Phase 1/8[/bold yellow] [cyan]Asset Discovery[/cyan]")
    
    discovery_items = ["DNS Records", "Certificate Transparency", "ASN Lookup", "WHOIS", "Reverse DNS", "Subdomains"]
    for item in discovery_items:
        loading_animation(f"Querying {item}...", 0.3)
    
    discovery_pipeline = Pipeline([DNSCollector(), CertspotterCollector()])
    inventory = asyncio.run(discovery_pipeline.run(target))
    
    all_assets = inventory.get_all()
    domains = [a for a in all_assets if a.type == AssetType.DOMAIN]
    ips = [a for a in all_assets if a.type == AssetType.IP]
    
    # --- PHASE 2 ---
    console.print(f"\n[bold yellow]Phase 2/8[/bold yellow] [cyan]Evidence Collection[/cyan]")
    console.print(f"\nInvestigating {len(all_assets)} assets...\n")
    
    enrichment_items = ["HTTP", "TLS", "Headers", "Technologies", "Ports", "Wayback", "Email/DNS", "Cloud Buckets", "GitHub Secrets"]
    for item in enrichment_items:
        loading_animation(f"Collecting {item} evidence...", 0.4)
    
    domain_values = [a.value for a in domains]
    http_pipeline = Pipeline([HTTPCollector()])
    http_pipeline.inventory = inventory 
    asyncio.run(http_pipeline.enrich(domain_values))
    
    async def run_root_collectors():
        root_collectors = [WaybackCollector(), EmailCollector(), CloudCollector(), GitHubCollector()]
        tasks = [c.collect(target) for c in root_collectors]
        return await asyncio.gather(*tasks)
    root_results = asyncio.run(run_root_collectors())
    
    root_asset = next((a for a in inventory.get_all() if a.value == target), None)
    if root_asset:
        for res_list in root_results: root_asset.evidence.extend(res_list)
        
    http_services = sum(1 for a in all_assets for e in a.evidence if e.source.startswith("http_"))
    mail_servers = sum(1 for a in all_assets for e in a.evidence if e.source == "mx_records")
    cloud_resources = sum(1 for a in all_assets for e in a.evidence if e.source == "cloud_bucket")
    
    print_stat_block("Asset Inventory", {
        "Domains": len(domains), "IPs": len(ips), "HTTP Services": http_services,
        "Mail Servers": mail_servers, "Cloud Resources": cloud_resources, "Certificates": 0
    })
    
    http_count = sum(1 for a in all_assets for e in a.evidence if e.source.startswith("http_"))
    wayback_ev = next((ev for a in all_assets for ev in a.evidence if ev.source == "wayback_machine"), None)
    historical_count = len(wayback_ev.raw_data.get("interesting_urls", [])) if wayback_ev else 0
    total_snapshots = wayback_ev.raw_data.get("total_snapshots", 0) if wayback_ev else 0
    email_count = sum(1 for a in all_assets for e in a.evidence if e.source in ["mx_records", "spf_record", "dmarc_record"])
    cloud_count = sum(1 for a in all_assets for e in a.evidence if e.source == "cloud_bucket")
    github_ev = next((ev for a in all_assets for ev in a.evidence if ev.source == "github_secrets"), None)
    github_count = len(github_ev.raw_data.get("leaked_files", [])) if github_ev else 0

    print_stat_block("Collected Evidence", {
        "HTTP Responses": http_count, "Historical URLs": f"{historical_count} (from {total_snapshots} snapshots)",
        "Email Records": email_count, "Cloud Buckets": cloud_count, "GitHub Leaks": github_count
    })
    
    # --- PHASE 3 & 4 ---
    console.print(f"\n[bold yellow]Phase 3/8[/bold yellow] [cyan]Correlation[/cyan]")
    console.print("\nAnalyzing relationships...\n")
    
    correlation_items = ["Internet-facing assets", "Authentication surfaces", "Historical endpoints", "Cloud resources", "Email configurations", "Source code leaks"]
    for item in correlation_items:
        loading_animation(f"Correlating {item}...", 0.3)
        
    engine = CorrelationEngine()
    findings = engine.analyze(inventory.get_all())
    console.print("\n[bold green]Correlation Complete[/bold green]\n")
    
    console.print(f"\n[bold yellow]Phase 4/8[/bold yellow] [cyan]Intelligence Engine[/cyan]")
    console.print("\nReasoning over collected evidence...\n")
    total_evidence = sum(len(a.evidence) for a in all_assets)
    console.print(f"  Evaluated: [bold]{total_evidence}[/bold] pieces of evidence")
    console.print(f"  Generated: [bold]{len(findings)}[/bold] findings\n")
    
    coverage = {"wayback": wayback_ev is not None, "github": github_ev is not None}
    analysis = AnalysisEngine(inventory, findings, coverage)
    summary_data = analysis.get_intelligence_summary()
    attack_paths = analysis.generate_attack_paths()
    investigation_queue = analysis.generate_investigation_queue()
    ai_assessment = analysis.generate_ai_assessment()
    
    console.print("\n[bold magenta]==========================[/bold magenta]")
    console.print("[bold magenta]INTELLIGENCE SUMMARY[/bold magenta]")
    console.print("[bold magenta]==========================[/bold magenta]\n")
    print_stat_block("", {
        "Exposure Score": f"{summary_data['exposure_score']} / 100",
        "Highest Risk": summary_data['highest_risk'],
        "Most Interesting Asset": summary_data['most_interesting'],
        "Biggest Weakness": summary_data['biggest_weakness'],
        "Historical Risk": summary_data['historical_risk'],
        "Credential Risk": summary_data['credential_risk'],
        "Cloud Risk": summary_data['cloud_risk'],
        "Overall Recommendation": summary_data['recommendation']
    })
    
    console.print("\n[bold magenta]Scan Coverage[/bold magenta]\n")
    coverage_display = {"DNS": True, "HTTP": True, "Certspotter": True, "Wayback": wayback_ev is not None, "Email/DNS": email_count > 0, "Cloud": True, "GitHub": github_ev is not None}
    for name, ran in coverage_display.items():
        status = "[green]✓[/green]" if ran else "[red]✗ No data/failed[/red]"
        console.print(f"  {name:<12} {status}")
        
    if attack_paths:
        console.print("\n[bold magenta]Attack Paths[/bold magenta]\n")
        for i, path in enumerate(attack_paths, 1):
            console.print(f"[bold]Attack Path #{i}: {path['name']}[/bold]")
            console.print("  " + " -> ".join(path['steps']))
            console.print(f"  Confidence: {path['confidence']}%\n")

    console.print("\n[bold green]=== ACTIONABLE INTELLIGENCE (URLs) ===[/bold green]\n")
    has_links = False
    if wayback_ev and historical_count > 0:
        has_links = True
        console.print("[bold cyan]Historical Endpoints (Wayback Machine):[/bold cyan]")
        for item in wayback_ev.raw_data.get("interesting_urls", [])[:5]: console.print(f"  • {item['url']}")
        console.print()
    if github_ev and github_count > 0:
        has_links = True
        console.print("[bold red]Leaked Source Code (GitHub):[/bold red]")
        for item in github_ev.raw_data.get("leaked_files", []): console.print(f"  • {item['url']}")
        console.print()
    if not has_links: console.print("[dim]No direct actionable URLs discovered in this scan.[/dim]\n")
    
    if findings:
        console.print("\n[bold red]Findings[/bold red]\n")
        reasoning_engine = ReasoningEngine()
        assessments = reasoning_engine.analyze(findings)
        for i, assessment in enumerate(assessments, 1):
            f = assessment["finding"]
            color = "red" if f.risk in [RiskLevel.HIGH, RiskLevel.CRITICAL] else "yellow" if f.risk == RiskLevel.MEDIUM else "blue"
            console.print(f"[bold]Finding #{i}[/bold]")
            console.print(f"  [cyan]Title:[/cyan] {f.title}")
            console.print(f"  [cyan]Severity:[/cyan] [{color}]{f.risk.value.upper()}[/{color}]")
            console.print(f"  [cyan]Confidence:[/cyan] {f.confidence}%")
            console.print(f"  [cyan]Affected Asset:[/cyan] {f.asset}\n")
            console.print("  [bold]Evidence[/bold]")
            for ev in f.evidence:
                data = ev.raw_data
                if ev.source.startswith("http_"): console.print(f'    • HTTP response contains: "{data.get("title", "Not Found")}"')
                elif ev.source == "github_secrets":
                    for file in data.get("leaked_files", []): console.print(f"    • Leaked in: {file['repo']} ({file['file']})")
                else: console.print(f"    • Evidence source: {ev.source}")
            console.print("\n  [bold]Reasoning[/bold]")
            console.print(f"    {assessment['narrative']}\n")
            console.print("  [bold]Impact[/bold]")
            for imp in f.impact: console.print(f"    • {imp}")
            console.print("\n  [bold]Recommendation[/bold]")
            for rec in f.recommendation: console.print(f"    • {rec}")
            console.print("\n" + "─" * 60 + "\n")
            
    console.print("\n[bold magenta]Recommended Next Investigation[/bold magenta]\n")
    for item in investigation_queue: console.print(f"  Priority {item['priority']}: {item['action']}")
    console.print("\n  [dim]Estimated Manual Review: 25 minutes.[/dim]\n")
    
    console.print("\n[bold magenta]AI Assessment[/bold magenta]\n")
    console.print(f"  {ai_assessment}\n")
    
    duration = time.time() - start_time
    console.print("\n[bold magenta]Overall Assessment[/bold magenta]\n")
    high_count = sum(1 for f in findings if f.risk in [RiskLevel.HIGH, RiskLevel.CRITICAL])
    print_stat_block("", {"Assets Discovered": len(all_assets), "Evidence Collected": total_evidence, "Findings": len(findings), "  Critical/High": high_count, "Scan Duration": f"{duration:.1f} seconds"})
    
    save_state(target, inventory.get_all())

def run_asset_lookup(domain: str):
    state_dir = Path(".0xsff_state")
    found_asset = None
    for file in state_dir.glob("*.json"):
        with open(file, "r") as f:
            data = json.load(f)
            for a_data in data:
                if a_data.get("value") == domain:
                    found_asset = a_data
                    break
        if found_asset: break
        
    if not found_asset:
        console.print(f"\n[red]Asset {domain} not found in scan history.[/red]\n")
        return
        
    console.print(f"\n[bold magenta]Asset Intelligence Deep Dive[/bold magenta]")
    console.print(f"[bold cyan]Victim:[/bold cyan] {domain}\n")
    
    console.print("[bold]Evidence[/bold]")
    for ev_data in found_asset.get("evidence", []):
        source = ev_data.get("source")
        raw = ev_data.get("raw_data", {})
        if source.startswith("http_"): console.print(f"  • HTTP {raw.get('status')} | Server: {raw.get('server')} | Title: {raw.get('title')}")
        elif source == "wayback_machine": console.print(f"  • Wayback Machine: {len(raw.get('interesting_urls', []))} historical URLs")
        elif source == "mx_records": console.print(f"  • MX Records: {', '.join(raw.get('records', []))}")
        elif source == "github_secrets": console.print(f"  • GitHub Leaks: {len(raw.get('leaked_files', []))} files")
        else: console.print(f"  • {source}")
            
    console.print("\n[bold]Related Findings[/bold]")
    console.print("  • [dim]Run 'scan <target>' to see correlated findings for this asset.[/dim]\n")

# --- INTERACTIVE CONSOLE (msfconsole style) ---
def console_loop():
    print_banner()
    while True:
        try:
            prompt = console.input("\n[bold red]smurf[/bold red] > ")
            if not prompt.strip(): continue
            
            try:
                parts = shlex.split(prompt.strip())
            except ValueError:
                parts = prompt.strip().split()
                
            cmd = parts[0].lower()
            args = parts[1:]
            
            if cmd in ["exit", "quit", "q"]:
                console.print("\n[yellow]Exiting 0xsff... Stay safe![/yellow]\n")
                break
            elif cmd == "help":
                print_help()
            elif cmd == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
                print_banner()
            elif cmd == "scan":
                if not args:
                    console.print("[red]Usage: scan <target>[/red]")
                else:
                    run_scan(args[0])
            elif cmd == "asset":
                if not args:
                    console.print("[red]Usage: asset <domain>[/red]")
                else:
                    run_asset_lookup(args[0])
            else:
                console.print(f"[red]Unknown command: {cmd}[/red]")
                print_help()
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Use 'exit' to quit.[/yellow]")
            continue
        except EOFError:
            break

# --- TYPER ENTRY POINT ---
@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """0xsff - Exposure Intelligence Framework."""
    if ctx.invoked_subcommand is None:
        console_loop()

@app.command()
def scan(target: str):
    """Run a full intelligence scan against a victim."""
    run_scan(target)

@app.command()
def asset(domain: str):
    """Deep dive into a specific asset from the last scan."""
    run_asset_lookup(domain)

if __name__ == "__main__":
    app()
