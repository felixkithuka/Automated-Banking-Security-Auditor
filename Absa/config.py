"""
ABSA — Central Configuration
All tunables, defaults, and constants including stealth parameters.
"""

import os

APP_NAME = "Automated Banking Security Auditor"
APP_TAGLINE = "A Zero-Day-Aware Python Testing Framework"
APP_VERSION = "1.0.0"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
REPORT_DIR = os.path.join(OUTPUT_DIR, "reports")
LOG_DIR = os.path.join(OUTPUT_DIR, "logs")
EVIDENCE_DIR = os.path.join(OUTPUT_DIR, "evidence")
STEALTH_DIR = os.path.join(BASE_DIR, "data")

for _d in (OUTPUT_DIR, REPORT_DIR, LOG_DIR, EVIDENCE_DIR, STEALTH_DIR):
    os.makedirs(_d, exist_ok=True)

DEFAULT_TIMEOUT = 15
DEFAULT_CONCURRENCY = 10
DEFAULT_DELAY = 0.1
MAX_REDIRECTS = 5

RECON_DNS_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"]
RECON_CRAWL_MAX_DEPTH = 4
RECON_CRAWL_MAX_PAGES = 500
RECON_CRAWL_RESPECT_ROBOTS = True
RECON_JS_PARSE = True
RECON_EXCLUDE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".zip", ".gz", ".tar", ".pdf",
    ".doc", ".docx", ".xls", ".xlsx", ".pptx",
}

BANKING_SUBDOMAIN_WORDLIST = [
    "www", "api", "app", "mobile", "m", "banking", "online", "portal",
    "admin", "dashboard", "secure", "auth", "login", "sso", "oauth",
    "pay", "payment", "transfer", "cards", "loans", "accounts",
    "staging", "dev", "test", "uat", "qa", "demo", "sandbox",
    "cdn", "static", "assets", "img", "images", "media",
    "mail", "remote", "vpn", "gateway", "proxy", "lb", "ns1", "ns2",
    "crm", "erp", "internal", "intranet", "hr", "docs", "wiki",
    "web", "webmail", "ftp", "sftp", "backup", "db", "database",
    "notifications", "webhooks", "scheduler", "jobs", "workers",
    "graphql", "rest", "soap", "ws", "wss", "socket",
]

FINGERPRINT_JS_LIBRARIES = {
    "jquery": r"jquery[.\-]\d",
    "react": r"react[.\-_]\d",
    "angular": r"angular[.\-_]\d",
    "vue": r"vue[.\-_]\d",
}

TLS_MIN_VERSION = "TLSv1.2"
TLS_WEAK_CIPHERS_BLOCKLIST = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"]

REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "directive": "max-age",
        "fix": "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "directive": None,
        "fix": 'Define a strict CSP e.g. "default-src \'self\'; script-src \'self\'"',
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "directive": "nosniff",
        "fix": "Set 'X-Content-Type-Options: nosniff'",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "directive": "DENY",
        "fix": "Set 'X-Frame-Options: DENY'",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "directive": "strict-origin-when-cross-origin",
        "fix": "Set 'Referrer-Policy: strict-origin-when-cross-origin'",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "directive": None,
        "fix": "Set 'Permissions-Policy: camera=(), microphone=(), geolocation=()'",
    },
}

FUZZER_MAX_MUTATIONS = 5000
FUZZER_ANOMALY_THRESHOLD = 3.0
FUZZER_TIMEOUT_PER_REQUEST = 20
FUZZER_READ_ONLY = True
FUZZER_BLOCKLIST_PAYLOADS = [
    "DROP TABLE", "DELETE FROM", "TRUNCATE", "ALTER TABLE",
    "DROP DATABASE", "SHUTDOWN", "rm -rf", "mkfs", "FORMAT ",
    ":(){ :|:& };:", "DEL /F /S /Q", "ERASE",
]

LOGIC_FUZZER_MAX_EPISODES = 200
LOGIC_FUZZER_INVARIANTS = [
    "balance_non_negative",
    "auth_required_for_transfer",
    "step_sequence_enforced",
    "amount_matches_confirmation",
]

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_URL = "https://api.osv.dev/v1/query"

REPORT_TITLE = "Automated Banking Security Auditor - A Zero-Day-Aware Testing Framework"
REPORT_FONT = "Helvetica"
REPORT_FONT_MONO = "Courier"
REPORT_COLORS = {
    "primary": (0, 102, 51),
    "critical": (204, 0, 0),
    "high": (230, 126, 34),
    "medium": (241, 196, 15),
    "low": (52, 152, 219),
    "info": (149, 165, 166),
    "text": (44, 62, 80),
    "text_light": (127, 140, 141),
    "bg_light": (245, 247, 250),
    "white": (255, 255, 255),
    "black": (0, 0, 0),
    "border": (189, 195, 199),
}
REPORT_INCLUDE_EXECUTIVE_SUMMARY = True
REPORT_INCLUDE_EVIDENCE = True
REPORT_INCLUDE_COMPLIANCE = True
REPORT_COMPLIANCE_FRAMEWORKS = ["PCI DSS 4.0", "GDPR", "OWASP ASVS 4.0"]

CVSS_BANKING_WEIGHTS = {
    "financial_impact": 1.5,
    "data_exposure": 1.3,
    "authentication_bypass": 1.4,
    "default": 1.0,
}
SEVERITY_THRESHOLDS = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1, "info": 0.0}

LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s │ %(levelname)-8s │ %(name)-28s │ %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ─── Stealth Configuration ────────────────────────────────────────
STEALTH_ENABLED = True
STEALTH_PROFILE = "bot"
STEALTH_JITTER = 0.5
STEALTH_MAX_REQUESTS_PER_PROXY = 100
STEALTH_DNS_RESOLVER_SHUFFLE = True
STEALTH_STRIP_TOOL_HEADERS = True
STEALTH_RANDOMIZE_TCP_WINDOW = False
STEALTH_ACCEPT_LANGUAGE_ROTATE = True
PROXY_FILE_PATH = os.path.join(STEALTH_DIR, "proxies.txt")