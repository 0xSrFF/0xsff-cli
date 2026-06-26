# 0xsff - Exposure Intelligence CLI

**0xsff** is a terminal-based Exposure Intelligence and Attack Surface Reconnaissance framework. 

Unlike traditional scanners that dump thousands of raw ports and subdomains, 0xsff focuses on **actionable intelligence**. It correlates external security data (DNS, HTTP, GitHub leaks, Wayback Machine, Shodan) to identify high-risk attack paths, misconfigurations, and exposed secrets.

> "Show what matters, not everything found."

##  Features

- **Intelligence Correlation:** Connects the dots between open ports, missing headers, and tech stacks to identify real risk.
- **Smart Leak Hunting:** Scans GitHub for exposed `.env` files, API keys, and passwords related to the target.
- **Historical Analysis:** Mines the Wayback Machine for forgotten endpoints, backups, and old admin panels.
- **Infrastructure Mapping:** Integrates with InternetDB (Shodan) for free CVE and port discovery.
- **Vulnerability Detection:** Checks for Subdomain Takeover (NSTO) and missing security headers (CSP, HSTS).
- **Attack Path Reasoning:** Automatically identifies logical attack vectors (e.g., Auth surfaces missing HSTS).
- **Beautiful Terminal UI:** Clean, color-coded, tree-structured output.
- **Reporting:** Export findings to HTML, JSON, or Markdown.

##  Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/0xsff.git
   cd 0xsff
