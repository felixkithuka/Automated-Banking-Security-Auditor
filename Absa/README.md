Automated Banking Security Auditor (ABSA)
A Zero-Day-Aware Python Testing Framework

ABSA is an enterprise-grade, fully automated offensive security testing framework built in Python. It is designed specifically for assessing online banking systems. A user supplies a target URL and a valid authorization token, and the framework executes a complete end-to-end pipeline—from reconnaissance and active exploitation to zero-day simulation—ultimately outputting a highly detailed, professional PDF report.

WARNING: This tool performs real offensive security tests against live systems. Running it without explicit, written authorization from the target institution is strictly illegal. See the Legal & Ethics section.

Table of Contents
Key Features
Architecture (6 Phases)
Project Structure
Installation
How to Run
Generating an Authorization Token
Basic Execution
Stealth & Proxy Evasion
Reporting Output
Legal & Ethics
Key Features
Fully Automated Pipeline: Single command execution takes a target from URL to a finished PDF report.
Real-World Payloads: Active scanner uses real SQLi, XSS, SSRF, SSTI, LFI, and Command Injection vectors. Non-destructive by default (benign SELECTs, marker strings, read-only file reads).
Zero-Day Simulation Engine:
Intelligent Fuzzer: Coverage-guided parameter fuzzing with statistical anomaly detection (Z-score on response length/timing).
Payload Crafter: Mutation engine generating WAF-bypassing payloads (encoding variations, comment injection, Unicode fullwidth, null-byte insertion).
Business Logic Fuzzer: State-aware testing for amount tampering, step-skipping in multi-step transfers, race conditions on financial endpoints, and IDOR detection.
Safe Exploit Orchestrator: Read-only verification of zero-days (e.g., SQLi extracts SELECT 1, LFI reads /etc/hostname).
Operational Security (Stealth):
Proxy Rotation: Routes traffic through SOCKS5/HTTP proxies, rotating after N requests.
Identity Masking: Rotates User-Agent strings and companion headers mimicking search engine bots (Googlebot, Bingbot) or real browsers (Chrome, Firefox).
TLS Fingerprint Mimicry: Applies browser-like cipher ordering to defeat JA3/JA4 fingerprint-based WAF detection.
Timing Jitter: Log-normal distribution of inter-request delays with "burst-then-pause" patterns to mimic human behavior.
Comprehensive CVE Correlation: Maps detected technologies to real CVEs (NVD, local mirror), cross-references Exploit-DB for public exploits, and generates CWE-mapped remediations with copy-paste code fixes.
Professional PDF Reporting: Includes vector-drawn charts, color-coded severity badges, monospace code blocks, evidence panels, compliance mapping (PCI DSS 4.0, GDPR, OWASP ASVS), and a zero-day appendix.
Architecture (6 Phases)
[User Input: URL + Token]
│
▼
┌──────────────────────────────────────────────────────────────────┐
│ AUTHORIZATION GATE │
│ Validates HMAC-SHA256 signature, scope, expiry. Blocks if invalid│
└──────────────────────────┬───────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────────┐
│ PHASE 1: RECONNAISSANCE │
│ 1A. Subdomain Enum (crt.sh + DNS brute-force) │
│ 1B. Fingerprinting (Headers, Body, JS libs, Cookie flags) │
│ 1C. Spidering (BFS crawl, form extraction, JS API parse) │
└──────────────────────────┬───────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────────┐
│ PHASE 2: VULNERABILITY SCANNING │
│ 2A. Passive CVE Lookup (CPE → NVD/OSV/Exploit-DB) │
│ 2B. Active OWASP Top 10 (SQLi, XSS, CSRF, SSRF, SSTI, etc.) │
│ 2C. TLS Configuration (Protocols, Ciphers, Certs, HSTS) │
│ 2D. Security Headers (HSTS, CSP, X-Frame-Options, Cookies) │
└──────────────────────────┬───────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────────┐
│ PHASE 3: ZERO-DAY SIMULATION │
│ 3A. Intelligent Fuzzing (Mutations + Anomaly Detection) │
│ 3B. Business Logic (Amount tamper, race conditions, IDOR) │
│ 3C. Safe Exploit Orchestrator (Read-only PoC verification) │
└──────────────────────────┬───────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────────┐
│ PHASE 4: CORRELATION & FIXES │
│ CWE → CVE mapping, Exploit-DB cross-ref, Code fix generation │
└──────────────────────────┬───────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────────────────────────┐
│ PHASE 5: PDF REPORT GENERATION │
│ Cover, TOC, Charts, Findings, Zero-Days, Compliance, Disclaim │
└──────────────────────────────────────────────────────────────────┘

text


---

## Project Structure

```text
Absa/
├── absa.py                   # Entry point with ASCII banner & CLI
├── config.py                 # All framework constants and tunables
├── requirements.txt          # Python dependencies
│
├── core/
│   ├── __init__.py
│   ├── models.py             # Data models (Finding, Endpoint, ScanContext, etc.)
│   ├── auth.py               # HMAC-SHA256 authorization gate
│   └── orchestrator.py       # Main pipeline driver (wires stealth client)
│
├── recon/
│   ├── __init__.py
│   ├── subdomain.py          # Certificate Transparency + DNS brute-force
│   ├── fingerprint.py        # Header/Body/JS technology detection + CPE mapping
│   └── spider.py             # BFS crawler, form/JS-API endpoint extraction
│
├── scanner/
│   ├── __init__.py
│   ├── passive.py            # Version-to-CVE matching (local NVD mirror)
│   ├── active.py             # OWASP Top 10 payloads + race condition testing
│   ├── tls.py                # TLS protocol/cipher/cert analysis (sslyze)
│   └── headers.py            # Security header presence and compliance check
│
├── zeroday/
│   ├── __init__.py
│   ├── payload_crafter.py    # WAF-bypass payload mutations (encoding, unicode, etc.)
│   ├── fuzzer.py             # Coverage-guided fuzzing with Z-score anomaly detection
│   ├── logic_fuzzer.py       # Business logic: amount tamper, IDOR, step-skip, races
│   └── exploit.py            # Safe read-only zero-day verification engine
│
├── correlation/
│   ├── __init__.py
│   ├── cve_lookup.py         # CWE→CVE mapping (local + NVD API fallback)
│   ├── exploit_db.py         # CVE→Exploit-DB ID cross-reference
│   └── fix_suggester.py      # CWE→Remediation code/text mapping
│
├── reporting/
│   ├── __init__.py
│   ├── templates.py          # All text templates for PDF sections
│   ├── report_builder.py     # Assembles scan data into structured dict
│   └── pdf_generator.py      # ReportLab PDF generation with vector charts
│
├── stealth/
│   ├── __init__.py
│   ├── proxy_manager.py      # SOCKS5/HTTP proxy pool with auto-rotation
│   ├── user_agent_rotator.py # Bot/Browser/Mixed UA + header profile rotation
│   ├── fingerprint_mimic.py  # JA3/JA4 TLS cipher ordering mimicry
│   └── timing.py             # Log-normal jitter + burst-then-pause patterns
│
└── utils/
    ├── __init__.py
    ├── logger.py             # Color-coded async logger (colorama)
    ├── http_client.py         # Shared stealth-enabled async HTTP client
    └── helpers.py             # URL parsing, form/JS extraction, scoring
Installation
1. Prerequisites
Python 3.9 or newer
pip (usually included with Python)
2. Create a Virtual Environment (Recommended)
bash

python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
3. Install Dependencies
bash

pip install -r requirements.txt
Note on sslyze: If installation fails on macOS/Linux, you may need system-level OpenSSL dev headers (libssl-dev on Ubuntu, openssl@1.1 via Homebrew on macOS). If sslyze fails to install, ABSA gracefully falls back to Python's built-in ssl module for basic TLS checks.

How to Run
Generating an Authorization Token
ABSA will not run without a valid authorization token. The token is a base64-encoded JSON object signed with HMAC-SHA256. You must generate one using the script below (or modify core/auth.py to use your organization's PGP keys).

python

import base64, json, hmac, hashlib
from datetime import datetime, timezone

# ⚠️ CHANGE THIS KEY to match what's in your config.py (or set env var ABSA_AUTH_KEY)
HMAC_KEY = "absa-demo-authorization-key-replace-in-production-do-not-use-default"

payload = {
    "engagement_id": "ENG-2024-0847",
    "target_domain": "demo-bank.example.com",
    "scope": ["*.demo-bank.example.com"],
    "operations": ["recon", "scan", "fuzz", "report", "zeroday"],
    "issued_at": datetime.now(timezone.utc).isoformat(),
    "expires_at": "2025-12-31T23:59:59Z",
    "authorized_by": "Jane Doe, CISO, Example Bank"
}

# Sign the payload
msg = json.dumps({k: v for k, v in sorted(payload.items())}, sort_keys=True, separators=(",", ":"))
sig = hmac.new(HMAC_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
payload["signature"] = sig

# Encode
token = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
print(f"Your ABSA Token:\n{token}")
Basic Execution
bash

python absa.py \
  --url https://demo-bank.example.com \
  --token "eyJlbmdhZ2VtZW50X2lkIjoiRU5HLTIwMjQtMDg0NyIsInRhcmdldF9kb21haW4iOi..." \
  --threads 10 \
  --delay 0.1
Stealth & Proxy Evasion
To mask your origin IP and mimic search engine crawlers (so the bank's WAF/IDS sees Googlebot traffic instead of penetration testing tools):

bash

# Mimic search engine bots (default)
python absa.py \
  --url https://demo-bank.example.com \
  --token "YOUR_TOKEN" \
  --stealth bot

# Mimic real browser users
python absa.py \
  --url https://demo-bank.example.com \
  --token "YOUR_TOKEN" \
  --stealth browser

# Route through a SOCKS5 proxy
python absa.py \
  --url https://demo-bank.example.com \
  --token "YOUR_TOKEN" \
  --stealth bot \
  --proxy socks5://127.0.0.1:9050

# Rotate through a list of proxies
python absa.py \
  --url https://demo-bank.example.com \
  --token "YOUR_TOKEN" \
  --stealth mixed \
  --proxy-file proxies.txt \
  --max-requests-per-proxy 50 \
  --jitter 0.7
Proxy file format (proxies.txt):

text

socks5://user:pass@10.0.0.1:9050
socks5://10.0.0.2:9050
http://user:pass@10.0.0.3:8080
socks5://10.0.0.4:1080
Skipping Phases
bash

# Skip zero-day simulation (faster scan)
python absa.py --url https://demo-bank.example.com --token "YOUR_TOKEN" --skip-zeroday

# Skip TLS scanning
python absa.py --url https://demo-bank.example.com --token "YOUR_TOKEN" --skip-tls

# Disable stealth entirely
python absa.py --url https://demo-bank.example.com --token "YOUR_TOKEN" --no-stealth

# Debug mode (verbose logging)
python absa.py --url https://demo-bank.example.com --token "YOUR_TOKEN" --debug
Output
Terminal: Real-time color-coded log output showing each phase's progress and findings.
PDF Report: Generated in Absa/output/reports/ with a filename like ABSA_Report_demo-bank.example.com_20240815_143022.pdf.
Reporting Output
The generated PDF includes the following sections:

Cover Page: Green branded header with target URL, session ID, date, and CONFIDENTIAL classification.
Executive Summary: Risk rating (CRITICAL/HIGH/MEDIUM/LOW), overall finding counts, top critical items, zero-day summary.
Vector Charts: Bar chart of severity distribution and horizontal bar chart of vulnerability categories (drawn with ReportLab primitives — no external charting library required).
Phase Results: Table showing status, duration, and statistics for all 12 sub-phases.
Detailed Findings: Every vulnerability with color-coded severity badge, CVSS score, CWE ID, full description, evidence panel (monospace), step-by-step reproduction, remediation description, and copy-paste code fix in multiple languages (Python, Java, PHP, Nginx/Apache config).
Zero-Day Appendix: Isolated section for zero-day findings with proposed patch and responsible disclosure guidance.
Compliance Mapping: Tables mapping findings to PCI DSS 4.0, GDPR, and OWASP ASVS 4.0 clause IDs.
Stealth Methodology: Documentation of what OPSEC measures were applied.
Disclaimer: Legal text regarding confidentiality and responsible disclosure.
Legal & Ethics
This is a weaponized security tool. It sends real attack payloads to live systems.
You MUST have:
A signed penetration testing engagement letter from the bank's legal department.
A signed scope document explicitly listing permitted targets.
A valid authorization token from the bank's CISO.
The authorization gate in core/auth.py is a technical safeguard, not a legal one. It prevents accidental runs but does not grant legal permission.
Zero-day findings must be reported directly to the target bank under the embargo terms specified in the engagement letter. Public disclosure without consent is unethical and potentially illegal.
Destructive payloads (DROP TABLE, DELETE FROM, rm -rf, etc.) are hard-blocked in the code and cannot be enabled without modifying the source. The zero-day engine operates in strict read-only mode.
The developers of this framework assume no liability for misuse. You are solely responsible for ensuring your actions comply with all applicable laws in your jurisdiction.