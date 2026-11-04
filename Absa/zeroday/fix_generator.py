"""
ABSA Aggressive Zero-Day Fix Generator
Generates specific, actionable remediation code and configuration fixes
for verified zero-day vulnerabilities, including WAF rules.
"""

import re
from typing import Dict, List, Optional, Any
from datetime import datetime

from core.models import Finding, Severity
from utils.logger import get_logger

logger = get_logger("zeroday.fixes")

FIX_TEMPLATES = {
    "CWE-22": {
        "title": "Path Traversal Prevention",
        "description": "Validate and sanitize all file path inputs.",
        "code": '''import os

def safe_get_file(user_path: str, base_dir: str) -> str:
    """Prevent path traversal by resolving and checking prefix."""
    base = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base_dir, user_path))
    if not target.startswith(base):
        raise ValueError("Invalid path: traversal detected")
    if not os.path.isfile(target):
        raise FileNotFoundError("File not found")
    return target

# Usage:
# file_path = safe_get_file(request.args.get("file"), "/var/www/docs/")
''',
        "waf_rule": '''
SecRule ARGS "@contains ../" "id:1001,phase:2,deny,status:403,msg:'Path Traversal Detected'"
SecRule ARGS "@contains ..%2f" "id:1002,phase:2,deny,status:403,msg:'Encoded Path Traversal'"
''',
        "nginx": '''
# Block path traversal in Nginx
location ~* \\.\\./ {
    return 403;
}
if ($uri ~* "\\.\\./") {
    return 403;
}
''',
    },
    "CWE-89": {
        "title": "SQL Injection Prevention",
        "description": "Use parameterized queries instead of string concatenation.",
        "code": '''import sqlite3

def get_user(user_id: int):
    """SAFE: Parameterized query prevents SQL injection."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # NEVER do: f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
''',
        "waf_rule": '''
SecRule ARGS "@detectSQLi" "id:2001,phase:2,deny,status:403,msg:'SQL Injection Detected'"
''',
    },
    "CWE-639": {
        "title": "IDOR / Bypass Authorization Fix",
        "description": "Implement row-level authorization checks.",
        "code": '''from functools import wraps

def check_ownership(resource_model):
    """Decorator ensuring user owns the requested resource."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, request=None, resource_id=None, **kwargs):
            resource = resource_model.query.get(resource_id)
            if not resource:
                return {"error": "Not found"}, 404
            if resource.owner_id != request.user.id:
                return {"error": "Forbidden"}, 403
            return f(*args, resource=resource, **kwargs)
        return wrapper
    return decorator
''',
    },
    "CWE-119": {
        "title": "Buffer Overflow Mitigation",
        "description": "Upgrade software to patched version immediately.",
        "code": '''#!/bin/bash
# Upgrade Apache to latest safe version
sudo apt update
sudo apt install --only-upgrade apache2

# Verify version
apache2 -v | grep "Server version"
''',
    },
    "CWE-200": {
        "title": "Information Disclosure Prevention",
        "description": "Strip version headers and block sensitive files.",
        "code": '''# Apache: Hide version in httpd.conf or apache2.conf
ServerTokens Prod
ServerSignature Off

# Block sensitive files
<DirectoryMatch "^\\.\\.|\\.env|\\.git|\\.svn|\\.map$">
    Require all denied
</DirectoryMatch>

# Nginx: Hide version in nginx.conf
server_tokens off;

# Block sensitive files
location ~ /\\.(env|git|svn|map)$ {
    deny all;
    return 404;
}
''',
    },
    "CWE-502": {
        "title": "Insecure Deserialization Prevention",
        "description": "Never deserialize untrusted data. Use safe formats.",
        "code": '''import json

# UNSAFE: pickle.loads(untrusted_data) - Remote Code Execution!
# SAFE: Use JSON for data interchange

def safe_deserialize(data: bytes) -> dict:
    """Only deserialize JSON, never pickle/yaml/raw."""
    try:
        return json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("Invalid data format: only JSON accepted")
''',
    },
    "CWE-327": {
        "title": "Weak Cryptographic Algorithm",
        "description": "Upgrade to TLS 1.3 and disable weak ciphers.",
        "code": '''# OpenSSL upgrade
sudo apt update && sudo apt install openssl libssl-dev

# Generate strong TLS 1.3 only config
cat > /etc/ssl/strong.conf << 'EOF'
openssl_conf = openssl_init

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.3
CipherString = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
EOF
''',
    },
    "CWE-400": {
        "title": "Resource Exhaustion Prevention",
        "description": "Implement rate limiting and payload size limits.",
        "code": '''from flask import Flask, request, jsonify
from functools import wraps
import time

app = Flask(__name__)

# Simple rate limiter
request_counts = {}

def rate_limit(max_requests=100, window_seconds=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            if ip not in request_counts:
                request_counts[ip] = []
            # Clean old entries
            request_counts[ip] = [t for t in request_counts[ip] if now - t < window_seconds]
            if len(request_counts[ip]) >= max_requests:
                return jsonify({"error": "Rate limit exceeded"}), 429
            request_counts[ip].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Limit request body size
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1MB
''',
    },
    "CWE-918": {
        "title": "SSRF Prevention",
        "description": "Validate and restrict outbound requests.",
        "code": '''import ipaddress
import socket
from urllib.parse import urlparse

def is_safe_url(url: str) -> bool:
    """Block private IPs and non-HTTP schemes."""
    parsed = urlparse(url)
    if parsed.scheme not in ["http", "https"]: return False

    try:
        ip = socket.gethostbyname(parsed.hostname)
        if ipaddress.ip_address(ip).is_private: return False
        if ipaddress.ip_address(ip).is_loopback: return False
    except socket.gaierror:
        return False

    return True
''',
        "waf_rule": '''
SecRule ARGS:url "@ipMatch 127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.169.254" "id:3001,phase:2,deny,status:403,msg:'SSRF Blocked'"
''',
    },
    "CWE-78": {
        "title": "OS Command Injection Prevention",
        "description": "Never pass user input to shell commands.",
        "code": '''import subprocess

# UNSAFE: os.system(f"ping {user_input}")
# UNSAFE: subprocess.call(f"ping {user_input}", shell=True)

# SAFE: Pass arguments as a list (no shell interpretation)
def safe_ping(target: str):
    """Validate IP/hostname, then ping without shell."""
    import re
    if not re.match(r"^[a-zA-Z0-9.\\-]+$", target):
        raise ValueError("Invalid target")
    result = subprocess.run(
        ["ping", "-c", "3", target],
        capture_output=True, text=True, timeout=10,
    )
    return result.stdout
''',
    },
}

DEFAULT_FIX = {
    "title": "Generic Security Hardening",
    "description": "Apply vendor security patches and follow defense-in-depth.",
    "code": '''# General security checklist:
# 1. Update all software to latest versions
# 2. Enable WAF (ModSecurity, Cloudflare, AWS WAF)
# 3. Implement rate limiting
# 4. Enable logging and monitoring
# 5. Conduct regular security audits
# 6. Review OWASP Top 10 mitigations
# 7. Enable CSP, HSTS, X-Frame-Options headers
# 8. Rotate secrets and credentials
# 9. Implement input validation on all endpoints
# 10. Use parameterized queries for all database access
''',
}


class FixGenerator:
    """Generates remediation code for zero-day findings."""

    def __init__(self, context: Any):
        self.ctx = context

    def generate_fixes(self, findings: List[Finding]) -> List[Finding]:
        enriched = []
        for f in findings:
            if f.remediation_code and f.remediation_code not in ("", "No additional findings in this category."):
                enriched.append(f)
                continue

            cwe = f.cwe_id.upper() if f.cwe_id else ""
            fix = FIX_TEMPLATES.get(cwe, DEFAULT_FIX)

            # Combine code and optional WAF rule
            full_code = fix.get("code", "")
            if "waf_rule" in fix:
                full_code += "\n\n# --- WAF Virtual Patch Rule ---\n" + fix["waf_rule"]

            enriched_finding = Finding(
                title=f.title, description=f.description, severity=f.severity,
                finding_type=f.finding_type, cwe_id=f.cwe_id, cvss_score=f.cvss_score,
                affected_url=f.affected_url, affected_file_or_component=f.affected_file_or_component,
                affected_parameter=f.affected_parameter, payloads=f.payloads, evidence=f.evidence,
                reproduction_steps=f.reproduction_steps,
                remediation=fix["description"] + "\n\n" + f.remediation,
                remediation_code=full_code,
                compliance_mappings=f.compliance_mappings, is_zero_day=f.is_zero_day,
                zero_day_detail=f.zero_day_detail, phase=f.phase, weakness_type=f.weakness_type,
                discovered_at=f.discovered_at,
            )
            enriched.append(enriched_finding)
        return enriched