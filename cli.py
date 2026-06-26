import argparse
from core.dispatcher import dispatch_scan
from core.logger import log

BANNER = """
███████╗███╗   ███╗██╗   ██╗██████╗ ███████╗
██╔════╝████╗ ████║██║   ██║██╔══██╗██╔════╝
███████╗██╔████╔██║██║   ██║██████╔╝█████╗  
╚════██║██║╚██╔╝██║██║   ██║██╔══██╗██╔══╝  
███████║██║ ╚═╝ ██║╚██████╔╝██║  ██║███████╗
╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝

        Exposure Intelligence CLI v1.0.0
                Author: Smurf / 0xsff
"""

DISCLAIMER = """
================================================================================
[!] DISCLAIMER: Educational, research, and authorized security testing only.
    Unauthorized use against systems you do not own is strictly prohibited.
--------------------------------------------------------------------------------
[i] ABOUT Author: Offensive Security • Pentesting • Exposure Analysis
    Finding weaknesses before attackers do.
================================================================================
"""

def print_banner():
    log(BANNER)
    log(DISCLAIMER)

def main():
    parser = argparse.ArgumentParser(
        description="0xsff - Exposure Intelligence CLI",
        epilog="Example: 0xsff scan example.com --intel --report html"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    scan_parser = subparsers.add_parser("scan", help="Run full intelligence scan")
    scan_parser.add_argument("target", help="Target domain or IP")
    scan_parser.add_argument("--intel", action="store_true", help="Only show high-value findings")
    scan_parser.add_argument("--report", choices=["md", "json", "html"], help="Generate report")
    
    for cmd in ["dns", "subdomains", "http", "ports", "tech", "headers", "github", "leaks", "history", "diff"]:
        p = subparsers.add_parser(cmd, help=f"Run {cmd} module")
        p.add_argument("target", help="Target domain")

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        return

    print_banner()

    if args.command == "scan":
        dispatch_scan(
            target=args.target,
            intel_mode=args.intel,
            report_mode=args.report
        )
    else:
        log(f"[+] Running module: {args.command} on {args.target}")
        log("[!] Module-specific execution is coming in the next update.")

if __name__ == "__main__":
    main()
