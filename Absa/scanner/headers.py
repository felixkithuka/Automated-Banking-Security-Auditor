"""
ABSA Security Header Scanner
Checks presence and correct configuration of security headers.
Each missing/misconfigured header produces a finding with exact fix.
"""

from typing import List, Tuple

from core.models import HeaderResult, Finding, Severity, FindingType, ComplianceMapping, ScanContext
from utils.http_client import ThrottledClient
from utils.logger import get_logger
import config

logger = get_logger("scanner.headers")


class HeaderScanner:
    def __init__(self, context: ScanContext, client: ThrottledClient):
        self.ctx = context
        self.client = client

    async def scan(self) -> Tuple[List[HeaderResult], List[Finding]]:
        logger.info("Security header scan: %s", self.ctx.target_url)
        findings, results = [], []
        r = await self.client.get(self.ctx.target_url)
        if r["error"]:
            return results, findings
        hdrs = {k.lower(): v for k, v in r["headers"].items()}

        for key, spec in config.REQUIRED_SECURITY_HEADERS.items():
            h_lower = key.lower()
            present = h_lower in hdrs
            value = hdrs.get(h_lower, "")
            expected = spec["directive"]
            compliant = False
            if present and expected:
                compliant = expected.lower() in value.lower()
            elif present:
                compliant = True

            hr = HeaderResult(header_name=spec["name"], present=present,
                              value=value, expected_directive=expected,
                              compliant=compliant, fix=spec["fix"])
            results.append(hr)

            if not present:
                findings.append(Finding(
                    title=f"Missing Security Header: {spec['name']}",
                    description=f"Response from {self.ctx.target_url} does not include {spec['name']}. "
                                f"Banking applications require this header to prevent attack classes.",
                    severity=Severity.LOW, finding_type=FindingType.CONFIGURATION,
                    cwe_id="CWE-16", affected_url=self.ctx.target_url,
                    remediation=spec["fix"], cvss_score=3.1, phase="headers",
                    compliance_mappings=[ComplianceMapping(
                        framework="PCI DSS 4.0", clause_id="6.5.10",
                        clause_title="Security Headers",
                        description="Implement HTTP response headers to mitigate common web vulnerabilities.")],
                ))
                logger.debug("  [MISSING] %s", spec["name"])
            elif not compliant:
                findings.append(Finding(
                    title=f"Misconfigured Header: {spec['name']}",
                    description=f"{spec['name']} is present but misconfigured. "
                                f"Expected '{expected}' not found in: {value[:100]}",
                    severity=Severity.LOW, finding_type=FindingType.CONFIGURATION,
                    cwe_id="CWE-16", affected_url=self.ctx.target_url,
                    remediation=spec["fix"], cvss_score=3.1, phase="headers",
                    evidence=f"Current value: {value}",
                ))
                logger.debug("  [MISCONFIGURED] %s = %s", spec["name"], value[:80])
            else:
                logger.debug("  [OK] %s", spec["name"])

        # X-Powered-By information disclosure
        if "x-powered-by" in hdrs:
            findings.append(Finding(
                title=f"Information Disclosure: X-Powered-By: {hdrs['x-powered-by']}",
                description=f"The server discloses its backend technology via X-Powered-By header. "
                            f"This aids attackers in targeting known exploits.",
                severity=Severity.LOW, finding_type=FindingType.CONFIGURATION,
                cwe_id="CWE-200", affected_url=self.ctx.target_url,
                remediation="Remove the X-Powered-By header. In PHP: expose_php = Off in php.ini. "
                            "In Express: app.disable('x-powered-by'). In ASP.NET: remove via web.config.",
                cvss_score=3.1, phase="headers",
            ))

        # Server header disclosure
        if "server" in hdrs:
            server_val = hdrs["server"]
            if any(ver_indicator in server_val for ver_indicator in ["/", "v"]):
                findings.append(Finding(
                    title=f"Server Version Disclosure: {server_val}",
                    description=f"The Server header reveals exact software version: {server_val}. "
                                f"Attackers use this to search for known exploits.",
                    severity=Severity.LOW, finding_type=FindingType.CONFIGURATION,
                    cwe_id="CWE-200", affected_url=self.ctx.target_url,
                    remediation="Remove or obfuscate the Server header. In Nginx: server_tokens off;. "
                                "In Apache: ServerTokens Prod. Use a reverse proxy to strip it.",
                    cvss_score=3.1, phase="headers",
                    evidence=f"Server: {server_val}",
                ))

        # Cookie security analysis
        cookie_header = hdrs.get("set-cookie", "")
        if cookie_header:
            cookies = [c.strip() for c in cookie_header.split("\n") if c.strip()]
            for cookie in cookies:
                cookie_name = cookie.split("=")[0].strip() if "=" in cookie else "unknown"
                issues = []
                if "httponly" not in cookie.lower():
                    issues.append("Missing HttpOnly (vulnerable to XSS cookie theft)")
                if "secure" not in cookie.lower():
                    issues.append("Missing Secure (sent over HTTP)")
                if "samesite" not in cookie.lower():
                    issues.append("Missing SameSite (vulnerable to CSRF)")
                if issues:
                    findings.append(Finding(
                        title=f"Insecure Cookie: {cookie_name}",
                        description=f"Cookie '{cookie_name}' has security deficiencies: {'; '.join(issues)}",
                        severity=Severity.MEDIUM if "secure" not in cookie.lower() else Severity.LOW,
                        finding_type=FindingType.CONFIGURATION, cwe_id="CWE-614",
                        affected_url=self.ctx.target_url, cvss_score=4.3, phase="headers",
                        remediation="Set HttpOnly, Secure, and SameSite=Lax (or Strict) on all session cookies.\n"
                                    "Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/",
                    ))

        return results, findings