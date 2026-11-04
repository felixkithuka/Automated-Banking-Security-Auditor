"""
ABSA Fix Suggester
Maps vulnerability types to concrete remediation steps, code fixes,
and compliance requirements. Provides actionable guidance for developers.
"""

from typing import Dict, Any
from core.models import Finding, ComplianceMapping, Severity
from utils.logger import get_logger

logger = get_logger("correlation.fix")

FIX_DATABASE = {
    "CWE-89": {
        "description": "Use parameterized queries (prepared statements) for ALL database operations. "
                       "Never concatenate user input into SQL strings. Apply input validation with allowlists.",
        "code": "# Python (psycopg2):\nimport psycopg2\nconn = psycopg2.connect(DSN)\ncursor = conn.cursor()\n\n# VULNERABLE:\n# query = f\"SELECT * FROM accounts WHERE id = '{user_input}'\"\n# cursor.execute(query)\n\n# FIXED — Parameterized query:\nquery = \"SELECT * FROM accounts WHERE id = %s\"\ncursor.execute(query, (user_input,))\nrows = cursor.fetchall()\n\n# Java (PreparedStatement):\n# String sql = \"SELECT * FROM users WHERE id = ?\";\n# PreparedStatement ps = conn.prepareStatement(sql);\n# ps.setString(1, userId);\n# ResultSet rs = ps.executeQuery();\n\n# PHP (PDO):\n# $stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n# $stmt->execute(['id' => $userId]);",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="6.2.4",
                              clause_title="Protect Against Code Injection",
                              description="Address injection-based vulnerabilities through code review and testing."),
            ComplianceMapping(framework="OWASP ASVS 4.0", clause_id="5.3.1",
                              clause_title="SQL Injection Prevention",
                              description="Require parameterized queries for all SQL statements."),
        ],
    },
    "CWE-79": {
        "description": "Encode all user-supplied data before rendering in HTML. Use context-appropriate encoding "
                       "(HTML entity, JavaScript, URL, CSS). Implement Content-Security-Policy headers.",
        "code": "# Python (Jinja2 with auto-escape):\nfrom jinja2 import Environment, select_autoescape\nenv = Environment(autoescape=select_autoescape(['html', 'xml']))\ntemplate = env.from_string('<p>{{ user_input }}</p>')\nresult = template.render(user_input=request_data)\n\n# JavaScript:\n// SAFE: element.textContent = userInput;\n// UNSAFE: element.innerHTML = userInput;\n\n# CSP Header:\n# Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="6.2.4",
                              clause_title="Protect Against XSS",
                              description="Protect against cross-site scripting via output encoding."),
        ],
    },
    "CWE-352": {
        "description": "Implement anti-CSRF tokens on all state-changing forms. Use SameSite cookie attribute. "
                       "Verify Origin and Referer headers.",
        "code": "# Flask:\nfrom flask_wtf.csrf import CSRFProtect\ncsrf = CSRFProtect(app)\n\n# Django (built-in):\n# {% csrf_token %} in all forms\n\n# Custom implementation:\nimport secrets\n\ndef generate_csrf_token():\n    return secrets.token_hex(32)\n\n@app.before_request\ndef check_csrf():\n    if request.method in ('POST', 'PUT', 'DELETE'):\n        token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')\n        session_token = session.get('csrf_token')\n        if not token or not session_token or not secrets.compare_digest(token, session_token):\n            abort(403)",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="6.5.1.3",
                              clause_title="CSRF Protection",
                              description="Implement CSRF protection for all web applications."),
        ],
    },
    "CWE-22": {
        "description": "Validate and sanitize file paths. Use allowlists of permitted files/directories. "
                       "Use chroot jails. Never pass user input to filesystem operations directly.",
        "code": "import os\n\nALLOWED_FILES = {'reports/jan.pdf', 'reports/feb.pdf'}\nBASE_DIR = '/var/data/reports'\n\ndef safe_read(filename):\n    # Normalize and resolve the path\n    normalized = os.path.normpath(filename)\n    full_path = os.path.join(BASE_DIR, normalized)\n    \n    # Ensure we're still within BASE_DIR (prevent traversal)\n    if not os.path.abspath(full_path).startswith(os.path.abspath(BASE_DIR)):\n        raise ValueError('Path traversal detected')\n    \n    # Check allowlist\n    if normalized not in ALLOWED_FILES:\n        raise ValueError('File not in allowlist')\n    \n    with open(full_path, 'r') as f:\n        return f.read()",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="6.5.1.1",
                              clause_title="File Inclusion Prevention",
                              description="Validate and sanitize user input used in file operations."),
        ],
    },
    "CWE-78": {
        "description": "Never pass user input to OS command execution functions. Use language-native libraries. "
                       "If unavoidable, use strict allowlists and shlex.quote().",
        "code": "import subprocess\nimport shlex\n\n# VULNERABLE:\n# os.system(f\"ping {user_input}\")\n# subprocess.call(f\"ping {user_input}\", shell=True)\n\n# FIXED — Use list form (no shell):\nresult = subprocess.run(['ping', '-c', '1', user_input], capture_output=True, text=True, timeout=10)\n\n# With allowlist:\nALLOWED_HOSTS = {'10.0.0.1', '10.0.0.2', 'dns.server.local'}\nif user_input not in ALLOWED_HOSTS:\n    raise ValueError('Host not permitted')\nresult = subprocess.run(['ping', '-c', '1', user_input], capture_output=True)",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="6.2.4",
                              clause_title="Command Injection Prevention",
                              description="Prevent OS command injection through proper input handling."),
        ],
    },
    "CWE-1336": {
        "description": "Never interpolate user input directly into templates. Pass data as context variables. "
                       "Use auto-escaping. Use sandboxed template environments.",
        "code": "# VULNERABLE:\n# render_template_string(f\"Hello {{ {user_input} }}\")\n\n# FIXED — Pass as context variable:\nfrom jinja2 import Environment, select_autoescape\nenv = Environment(autoescape=select_autoescape(['html', 'xml']))\ntemplate = env.from_string('Hello {{ name }}')\nresult = template.render(name=safe_value)\n\n# For untrusted template authors, use sandbox:\nfrom jinja2.sandbox import SandboxedEnvironment\nsandbox_env = SandboxedEnvironment(autoescape=True)",
        "compliance": [],
    },
    "CWE-918": {
        "description": "Validate URLs server-side. Use domain allowlists. Block private IPs (RFC 1918), "
                       "link-local, cloud metadata endpoints. Use egress proxy with filtering.",
        "code": "import ipaddress\nimport urllib.parse\nimport socket\n\nBLOCKED_NETWORKS = [\n    ipaddress.ip_network('10.0.0.0/8'),\n    ipaddress.ip_network('172.16.0.0/12'),\n    ipaddress.ip_network('192.168.0.0/16'),\n    ipaddress.ip_network('169.254.0.0/16'),  # AWS/GCP metadata\n    ipaddress.ip_network('127.0.0.0/8'),\n    ipaddress.ip_network('::1/128'),\n    ipaddress.ip_network('fc00::/7'),\n    ipaddress.ip_network('fe80::/10'),\n]\n\nALLOWED_DOMAINS = {'api.partner.com', 'api.payment.com'}\n\ndef is_url_safe(url):\n    parsed = urllib.parse.urlparse(url)\n    if parsed.scheme not in ('http', 'https'):\n        return False\n    try:\n        ips = socket.getaddrinfo(parsed.hostname, None)\n        for _, _, _, _, sockaddr in ips:\n            ip = ipaddress.ip_address(sockaddr[0])\n            if any(ip in net for net in BLOCKED_NETWORKS):\n                return False\n    except socket.gaierror:\n        pass\n    return parsed.hostname in ALLOWED_DOMAINS",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="6.2.4",
                              clause_title="SSRF Prevention",
                              description="Validate and filter server-side URLs."),
        ],
    },
    "CWE-326": {
        "description": "Disable all weak TLS protocols (SSLv3, TLS 1.0, TLS 1.1). Remove weak ciphers. "
                       "Use only TLS 1.2+ with strong cipher suites (AES-GCM, ChaCha20-Poly1305).",
        "code": "# Nginx:\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';\nssl_prefer_server_ciphers off;\n\n# Apache:\nSSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384\nSSLHonorCipherOrder off",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="4.2.1",
                              clause_title="Strong Cryptography",
                              description="Only TLS 1.2 or higher with strong cipher suites."),
        ],
    },
    "CWE-16": {
        "description": "Implement all recommended security headers. Each header mitigates specific attack classes.",
        "code": "# Nginx:\nadd_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'\" always;\nadd_header X-Content-Type-Options 'nosniff' always;\nadd_header X-Frame-Options 'DENY' always;\nadd_header Referrer-Policy 'strict-origin-when-cross-origin' always;\nadd_header Permissions-Policy 'camera=(), microphone=(), geolocation=()' always;\nadd_header X-XSS-Protection '0' always;\n\n# Also in application code:\n# response.set_cookie('session', token, httponly=True, secure=True, samesite='Lax')",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="6.5.10",
                              clause_title="Security Headers",
                              description="Implement HTTP response headers for web application protection."),
        ],
    },
    "CWE-295": {
        "description": "Install a valid CA-signed certificate. Ensure the full certificate chain is served. "
                       "Enable HSTS. Set up certificate monitoring and auto-renewal.",
        "code": "# Auto-renewal with certbot:\n# certbot --nginx -d bank.example.com -d www.bank.example.com\n# certbot renew --dry-run\n# Add to crontab:\n# 0 3 * * * certbot renew --quiet --deploy-hook 'systemctl reload nginx'\n\n# Verify chain:\n# openssl s_client -connect bank.example.com:443 -showcerts",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="4.2.1",
                              clause_title="Certificate Management",
                              description="Maintain valid certificates with proper chain."),
        ],
    },
    "CWE-284": {
        "description": "Implement object-level authorization. Verify ownership before every data access. "
                       "Use UUIDs instead of sequential IDs to prevent enumeration.",
        "code": "# BEFORE every data access:\n@app.route('/api/accounts/<account_id>')\ndef get_account(account_id):\n    user = get_current_user()\n    account = Account.query.get(account_id)\n    \n    if account is None:\n        return jsonify({'error': 'Not found'}), 404\n    \n    # CRITICAL: Authorization check\n    if account.owner_id != user.id and not user.is_admin:\n        audit_log.warning(f'IDOR: user {user.id} accessed account {account_id}')\n        return jsonify({'error': 'Forbidden'}), 403\n    \n    return jsonify(account.to_dict())",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="7.1",
                              clause_title="Access Control",
                              description="Limit access to system components and data to authorized users."),
        ],
    },
    "CWE-362": {
        "description": "Implement idempotency keys on all financial transactions. Use database-level locks "
                       "(SELECT FOR UPDATE). Apply per-user rate limiting on critical endpoints.",
        "code": "import uuid\nfrom datetime import datetime, timedelta\n\n@app.route('/transfer', methods=['POST'])\ndef transfer():\n    idempotency_key = request.headers.get('Idempotency-Key')\n    if not idempotency_key:\n        return error(400, 'Missing Idempotency-Key')\n    \n    # Check duplicate\n    existing = TransferLog.query.filter_by(idempotency_key=idempotency_key).first()\n    if existing:\n        return jsonify(existing.to_dict())  # Return original result\n    \n    with db.session.begin():\n        # Row-level lock\n        account = db.session.query(Account)\\\n            .filter_by(id=from_account_id)\\\n            .with_for_update()\\\n            .first()\n        \n        if account.balance < amount:\n            return error(400, 'Insufficient funds')\n        \n        account.balance -= amount\n        transfer = TransferLog(\n            idempotency_key=idempotency_key,\n            from_account=from_account_id,\n            to_account=to_account_id,\n            amount=amount\n        )\n        db.session.add(transfer)\n    \n    return jsonify(transfer.to_dict())",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="5.2.3",
                              clause_title="Transaction Integrity",
                              description="Protect against transaction manipulation and race conditions."),
        ],
    },
    "CWE-915": {
        "description": "Use explicit field allowlists in input models (DTOs). Never bind request bodies "
                       "directly to database models.",
        "code": "# VULNERABLE:\n# user = User(**request.json)\n\n# FIXED — Use Data Transfer Objects:\nfrom pydantic import BaseModel\n\nclass UserUpdateDTO(BaseModel):\n    name: str\n    email: str\n    phone: Optional[str] = None\n    # NOTE: 'role', 'is_admin', 'balance' are NOT included\n\n@app.route('/users/me', methods=['PUT'])\ndef update_profile():\n    dto = UserUpdateDTO(**request.json)  # Only allowed fields accepted\n    user = get_current_user()\n    user.name = dto.name\n    user.email = dto.email\n    if dto.phone:\n        user.phone = dto.phone\n    db.session.commit()\n    return jsonify(user.to_dict())",
        "compliance": [],
    },
    "CWE-614": {
        "description": "Set HttpOnly, Secure, and SameSite attributes on all session cookies.",
        "code": "# Flask:\napp.config['SESSION_COOKIE_SECURE'] = True\napp.config['SESSION_COOKIE_HTTPONLY'] = True\napp.config['SESSION_COOKIE_SAMESITE'] = 'Lax'\n\n# Django (settings.py):\n# SESSION_COOKIE_SECURE = True\n# SESSION_COOKIE_HTTPONLY = True\n# CSRF_COOKIE_SECURE = True\n# CSRF_COOKIE_HTTPONLY = True\n\n# Manual set-cookie:\n# Set-Cookie: session=token; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="6.5.10",
                              clause_title="Cookie Security",
                              description="Secure session cookies with HttpOnly, Secure, and SameSite attributes."),
        ],
    },
    "DEFAULT": {
        "description": "Implement defense-in-depth: input validation, output encoding, access control, "
                       "logging, and monitoring. Follow OWASP guidelines.",
        "code": "# General security checklist:\n# 1. Input validation (allowlist, type check, length limit)\n# 2. Output encoding (context-appropriate)\n# 3. Authentication (MFA, strong passwords, session management)\n# 4. Authorization (object-level, function-level)\n# 5. Logging and monitoring (audit trail, alerting)\n# 6. Error handling (no stack traces to users)\n# 7. Dependency management (regular updates, vulnerability scanning)",
        "compliance": [
            ComplianceMapping(framework="PCI DSS 4.0", clause_id="6.2",
                              clause_title="Secure Development",
                              description="Develop and maintain secure systems and software."),
            ComplianceMapping(framework="OWASP ASVS 4.0", clause_id="1.0",
                              clause_title="Architecture, Design, and Threat Modeling",
                              description="Verify use of secure design principles."),
        ],
    },
}


class FixSuggester:
    """Maps findings to concrete remediation based on CWE classification."""

    def __init__(self, context):
        self.ctx = context

    def suggest(self, finding) -> Dict[str, Any]:
        """Return remediation info for a finding."""
        entry = FIX_DATABASE.get(finding.cwe_id, FIX_DATABASE["DEFAULT"])
        return {
            "description": entry["description"],
            "code": entry["code"],
            "compliance": entry.get("compliance", []),
        }