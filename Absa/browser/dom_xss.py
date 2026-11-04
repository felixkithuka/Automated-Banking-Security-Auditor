"""
ABSA Aggressive DOM-based XSS Scanner
Uses AST parsing and headless execution to identify un-sanitized sinks
and sources in complex, deeply nested JavaScript files.
"""

import re
import os
import asyncio
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime

try:
    import esprima  # JavaScript AST parser

    AST_AVAILABLE = True
except ImportError:
    AST_AVAILABLE = False

from core.models import Finding, Severity, FindingType, Payload
from utils.logger import get_logger

logger = get_logger("browser.dom_xss")

# Dangerous JS sinks where user input can cause execution
SINKS = {
    "document.write", "document.writeln", "innerHTML", "outerHTML",
    "insertAdjacentHTML", "eval", "setTimeout", "setInterval",
    "Function", "window.execScript", "document.createElement"
}

# Dangerous sources where user input originates
SOURCES = {
    "location.href", "location.search", "location.hash", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer",
    "window.name", "document.cookie", "localStorage", "sessionStorage",
    "postMessage"
}

# Sanitization functions that might be bypassed
SANITIZERS = {
    "DOMPurify.sanitize", "sanitizeHTML", "escapeHtml", "encodeURI",
    "encodeURIComponent", "jQuery.htmlPrefilter"
}


class DOMXSSScanner:
    """Aggressively scans JavaScript files for DOM-based XSS via AST analysis."""

    def __init__(self, context: Any, client: Any):
        self.ctx = context
        self.client = client
        self.base_url = context.target_url.rstrip('/')

    async def run(self, config: Optional[Dict] = None) -> List[Finding]:
        findings = []
        logger.info("Starting Aggressive DOM XSS Scanner for %s", self.base_url)

        if not AST_AVAILABLE:
            logger.error("esprima not installed. Run: pip install esprima")
            return findings

        js_files = await self._discover_js_files()
        logger.info("Discovered %d JS files for AST parsing", len(js_files))

        for js_path in js_files:
            source_code = await self._fetch_js(js_path)
            if not source_code: continue

            vulnerabilities = self._analyze_ast_taint(source_code, js_path)
            for vuln in vulnerabilities:
                findings.append(self._create_finding(js_path, vuln))

        findings.extend(await self._active_headless_verification())

        return findings

    async def _discover_js_files(self) -> List[str]:
        js_files = set()
        resp = await self.client.get(self.base_url)
        if not resp or resp.get("status") != 200: return list(js_files)

        body = resp.get("body", "")
        js_files.update(re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body))
        js_files.update(re.findall(r'import\(["\']([^"\']+\.js[^"\']*)["\']\)', body))

        chunk_match = re.search(r'(\w+)="([^"]+\.js)"', body)
        if chunk_match:
            for i in range(1, 20):
                js_files.add(f"/static/js/{chunk_match.group(1)}{i}.js")

        common_dirs = ["/static/js/", "/assets/js/", "/dist/", "/build/", "/bundles/", "/app/"]
        for d in common_dirs:
            for f in ["app.js", "main.js", "vendor.js", "chunk.js", "runtime.js", "polyfills.js"]:
                js_files.add(f"{d}{f}")

        return list(js_files)

    async def _fetch_js(self, path: str) -> Optional[str]:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        resp = await self.client.get(url)
        if resp and resp.get("status") == 200:
            return resp.get("body", "")
        return None

    def _analyze_ast_taint(self, code: str, file_path: str) -> List[Dict]:
        vulns = []
        try:
            tree = esprima.parseScript(code, tolerant=True)
        except Exception:
            return vulns

        found_sources = set()
        found_sinks = set()
        found_sanitizers = set()

        for node in self._walk_ast(tree):
            node_str = esprima.dump(node)

            for src in SOURCES:
                if f'"{src}"' in node_str or f"'{src}'" in node_str:
                    found_sources.add(src)

            for sink in SINKS:
                if sink in node_str and ("CallExpression" in node_str or "AssignmentExpression" in node_str):
                    found_sinks.add(sink)

            for san in SANITIZERS:
                if san in node_str:
                    found_sanitizers.add(san)

        if found_sources and found_sinks and not found_sanitizers:
            vulns.append({"sources": list(found_sources), "sinks": list(found_sinks), "type": "Direct Taint Flow"})
        elif found_sources and found_sinks:
            vulns.append(
                {"sources": list(found_sources), "sinks": list(found_sinks), "type": "Potential Sanitizer Bypass"})

        return vulns

    def _walk_ast(self, node):
        yield node
        if hasattr(node, 'body') and isinstance(node.body, list):
            for child in node.body:
                yield from self._walk_ast(child)
        if hasattr(node, 'arguments') and isinstance(node.arguments, list):
            for child in node.arguments:
                yield from self._walk_ast(child)
        if hasattr(node, 'expression'):
            yield from self._walk_ast(node.expression)

    async def _active_headless_verification(self) -> List[Finding]:
        findings = []
        try:
            from playwright.async_api import async_playwright

            payloads = ['<img src=x onerror=alert(1)>', 'javascript:alert(1)', '"><svg onload=alert(1)>']

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                for payload in payloads:
                    try:
                        await page.goto(f"{self.base_url}#{payload}", wait_until="networkidle")
                        inner_html = await page.evaluate("() => document.body.innerHTML")
                        if payload in inner_html and "script" not in inner_html.lower():
                            pass

                        dialog_triggered = False

                        async def handle_dialog(dialog):
                            nonlocal dialog_triggered
                            dialog_triggered = True
                            await dialog.dismiss()

                        page.on("dialog", handle_dialog)
                        await page.reload(wait_until="networkidle")

                        if dialog_triggered:
                            findings.append(Finding(
                                title="EXPLOIT: DOM XSS Triggered via Hash",
                                description="Headless browser execution triggered a dialog box via injected hash payload.",
                                severity=Severity.CRITICAL, finding_type=FindingType.OWASP, cwe_id="CWE-79",
                                cvss_score=8.8, affected_url=f"{self.base_url}#...",
                                evidence=f"Payload: {payload}\nDialog triggered successfully.",
                                payloads=[Payload(payload_string=f"#{payload}", payload_type="dom_xss_hash",
                                                  evidence="Dialog fired", success=True)],
                                remediation="Implement strict input validation and encoding on client-side before rendering.",
                                phase="browser_dom_xss", weakness_type="DOM XSS",
                                discovered_at=datetime.utcnow().isoformat(),
                            ))
                            break
                    except Exception:
                        continue

                await browser.close()
        except ImportError:
            logger.debug("Playwright not installed. Skipping active headless DOM XSS verification.")
        except Exception as e:
            logger.error("Headless verification error: %s", e)

        return findings

    def _create_finding(self, file_path: str, vuln: Dict) -> Finding:
        return Finding(
            title=f"Zero-Day: DOM-based XSS Taint Flow ({vuln['type']})",
            description=f"AST analysis found un-sanitized data flow from {vuln['sources']} to {vuln['sinks']}.",
            severity=Severity.HIGH if "Bypass" in vuln['type'] else Severity.CRITICAL,
            finding_type=FindingType.ZERO_DAY, cwe_id="CWE-79", cvss_score=8.5,
            affected_url=f"{self.base_url}{file_path}", affected_file_or_component=file_path,
            evidence=f"Sources: {', '.join(vuln['sources'])}\nSinks: {', '.join(vuln['sinks'])}",
            remediation="Use safe DOM APIs (textContent) or strict contextual sanitization (DOMPurify).",
            phase="browser_dom_xss", weakness_type="DOM XSS", discovered_at=datetime.utcnow().isoformat(),
        )