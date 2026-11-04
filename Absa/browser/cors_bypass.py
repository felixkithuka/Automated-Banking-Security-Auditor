"""
ABSA Advanced CORS Bypass Scanner
Tests for complex CORS misconfigurations like null origin reflection,
regex bypasses, and subdomain trust relationships.
"""

import json
from typing import Dict, List, Optional, Any
from datetime import datetime

from core.models import Finding, Severity, FindingType, Payload
from utils.logger import get_logger

logger = get_logger("browser.cors")


class CORSBypassScanner:
    """Aggressively bypasses CORS origin validation mechanisms."""

    def __init__(self, context: Any, client: Any):
        self.ctx = context
        self.client = client
        self.base_url = context.target_url.rstrip('/')

    async def run(self, config: Optional[Dict] = None) -> List[Finding]:
        findings = []
        logger.info("Starting Aggressive CORS Bypass Scanner for %s", self.base_url)

        if await self._test_origin_reflection(f"https://evil.com"):
            findings.append(self._create_finding("Standard Origin Reflection", "evil.com"))

        if await self._test_origin_reflection("null"):
            findings.append(self._create_finding("Null Origin Bypass", "null"))

        if await self._test_origin_reflection(f"https://evil.{self.ctx.target_domain}"):
            findings.append(self._create_finding("Subdomain Trust Bypass", f"evil.{self.ctx.target_domain}"))

        regex_payloads = [
            f"https://{self.ctx.target_domain}evil.com",
            f"https://{self.ctx.target_domain}.evil.com",
            f"https://{self.ctx.target_domain}%00.evil.com",
        ]
        for payload in regex_payloads:
            if await self._test_origin_reflection(payload):
                findings.append(self._create_finding("Regex Origin Bypass", payload))
                break

        if "https://" in self.base_url:
            if await self._test_origin_reflection(f"http://{self.ctx.target_domain}"):
                findings.append(self._create_finding("Scheme Downgrade Bypass", "http"))

        return findings

    async def _test_origin_reflection(self, origin: str) -> bool:
        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Content-Type, Authorization",
        }

        resp = await self.client.options(self.base_url, headers=headers)

        if not resp or resp.get("status") != 200:
            resp = await self.client.get(self.base_url, headers={"Origin": origin})

        if not resp: return False

        acao = resp.get("headers", {}).get("Access-Control-Allow-Origin", "")
        acac = resp.get("headers", {}).get("Access-Control-Allow-Credentials", "")

        if acao == origin and acac.lower() == "true":
            return True

        if acao == "*" and acac.lower() == "true":
            return True

        return False

    def _create_finding(self, desc: str, payload: str) -> Finding:
        return Finding(
            title=f"EXPLOIT: Advanced CORS Misconfiguration ({desc})",
            description=f"The server reflects the provided Origin '{payload}' in Access-Control-Allow-Origin alongside Allow-Credentials: true. An attacker can make authenticated cross-origin requests on behalf of the user.",
            severity=Severity.CRITICAL, finding_type=FindingType.ZERO_DAY, cwe_id="CWE-346",
            cvss_score=8.5, affected_url=self.base_url,
            affected_file_or_component="CORS Middleware / Web Server Config",
            evidence=f"Payload Origin: {payload}\nResponse: ACAO: {payload} | ACAC: true",
            payloads=[Payload(payload_string=f"Origin: {payload}", payload_type="cors_bypass",
                              evidence="Reflected + Credentials", success=True)],
            remediation="Never dynamically reflect Origin headers in ACAO. Maintain a strict allow-list of trusted origins. Never use ACAC: true with wildcards or dynamic reflections.",
            phase="browser_cors", weakness_type="CORS Bypass", discovered_at=datetime.utcnow().isoformat(),
        )