# 0xsff - Exposure Intelligence Framework

<div align="center">

# --- COLORED BANNER ---
BANNER = """
███████╗ ███╗   ███╗ ██╗   ██╗ ██████╗ ███████╗
██╔════╝ ████╗ ████║ ██║   ██║ ██══██╗ ██╔════╝
███████╗ ██╔████╔██║ ██║   ██║ ██████╝ █████╗  
╚════██║ ██║╚██╔╝██║ ██║   ██║ ██╔═██╗ ██╔══╝  
███████║ ██║ ╚═╝ ██║ ╚██████╔╝ ██║ ██║ ██╗
╚══════╝ ╚═╝     ╚═╝  ╚═════╝  ╚═╝ ╚═╝ ╚═╝


**Exposure Intelligence CLI v1.0.0**  
*Finding weaknesses before attackers do.*

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production-green.svg)]()

**Author:** Smurf / 0xsff  
**Category:** Offensive Security • Pentesting • Exposure Analysis

---

> ⚠️ **DISCLAIMER:** For educational and authorized testing purposes only.  
> The author assumes no responsibility for misuse or damage caused by this tool.

</div>

---

## 📖 Table of Contents

- [About](#-about)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
- [Architecture](#-architecture)
- [Modules](#-modules)
- [Examples](#-examples)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 About

**0xsff** is a professional-grade Exposure Intelligence Framework designed for offensive security professionals, penetration testers, and bug bounty hunters. Unlike traditional recon tools that simply dump data, 0xsff collects evidence, correlates findings, applies reasoning, and generates actionable intelligence—just like a senior security analyst.

The framework operates in **four intelligent phases**:
1. **Asset Discovery** - DNS, Certificate Transparency, Subdomains
2. **Evidence Collection** - HTTP, TLS, Wayback Machine, GitHub Secrets, Cloud Buckets
3. **Correlation** - Analyzing relationships between assets
4. **Intelligence Engine** - Generating findings with confidence scores, attack paths, and AI assessments

---

## ✨ Features

### Core Capabilities
- **🎭 Interactive CLI** - Metasploit-style console with `smurf >` prompt
- **🔄 Multi-Phase Workflow** - Structured 4-phase intelligence gathering
- **🧠 AI-Powered Analysis** - Automated reasoning and narrative generation
- **📊 Exposure Scoring** - Quantified risk scoring (0-100)
- **🎯 Attack Paths** - Visual attack chain mapping
- **📈 Asset Inventory** - Comprehensive asset tracking
- **⏱️ Time-Travel Diff** - Compare scans over time
- **🔍 Deep Asset Dive** - Investigate individual assets

### Intelligence Modules
- ✅ DNS Records & Subdomain Enumeration
- ✅ Certificate Transparency Logs (Certspotter)
- ✅ HTTP/HTTPS Service Detection
- ✅ Historical Intelligence (Wayback Machine)
- ✅ Email Security Analysis (MX, SPF, DMARC)
- ✅ Cloud Storage Detection (AWS S3, Azure Blob)
- ✅ GitHub Secrets & Leak Detection
- ✅ Subdomain Takeover Detection
- ✅ Technology Fingerprinting

### Output Features
- **Evidence vs Findings** - Clear separation of raw data and intelligence
- **Confidence Scores** - Every finding includes confidence percentage
- **Impact Assessment** - Detailed impact analysis
- **Recommendations** - Actionable remediation steps
- **Investigation Queue** - Prioritized next steps
- **Scan Coverage** - Visual indicator of what was tested

---

## 📥 Installation

### Prerequisites
- Python 3.11 or higher
- pip (Python package manager)
- Git

### Step-by-Step Setup


# 1. Clone the repository
```
git clone https://github.com/0xSrFF/0xsff-cli.git
cd 0xsff-cli
```

# 2. Create virtual environment
```
python3 -m venv venv
```

# 3. Activate virtual environment
# On Linux/Mac:
```
source venv/bin/activate
```
# On Windows:
```
venv\Scripts\activate
```
# 4. Install dependencies
```
pip install -e .
```
# 5. (Optional) Set GitHub token for enhanced secret detection
```
export GITHUB_TOKEN=your_github_token_here
```
# 6. Run the framework
```
smurf
```

# Dependencies
The framework automatically installs:
typer - CLI framework
rich - Terminal formatting
httpx - Async HTTP client
pydantic - Data validation
dnspython - DNS queries
anyio - Async networking
