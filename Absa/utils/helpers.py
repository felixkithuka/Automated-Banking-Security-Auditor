"""ABSA Helper Utilities — URL parsing, scoring, sanitization, form/JS extraction."""

import re
from typing import List, Dict, Optional
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse

from core.models import Severity
import config


def parse_target(url: str) -> Dict[str, str]:
    """Parse target URL into its constituent components."""
    p = urlparse(url)
    return {
        "scheme": p.scheme or "https",
        "host": p.hostname or "",
        "port": p.port or (443 if p.scheme == "https" else 80),
        "path": p.path or "/",
        "query": p.query or "",
        "netloc": p.netloc
    }


def normalize_url(base: str, relative: str) -> str:
    """Join base URL and relative path safely."""
    return urljoin(base, relative)


def extract_params(url: str) -> Dict[str, str | List[str]]:
    """Extract and parse query parameters from a URL."""
    pq = parse_qs(urlparse(url).query)
    return {k: v[0] if len(v) == 1 else v for k, v in pq.items()}


def calculate_cvss(base: float, wtype: str = "default") -> float:
    """Calculate modified CVSS based on banking/industry weights."""
    w = config.CVSS_BANKING_WEIGHTS.get(wtype, 1.0)
    return min(round(base * w, 1), 10.0)


def calculate_cvss_base(impact: float, exploitability: float) -> float:
    """Simplified CVSS base score calculation."""
    return round(min(10.0, impact * exploitability), 1)


def score_to_severity(cvss: float) -> Severity:
    """Map CVSS score to Severity enum."""
    if cvss >= config.SEVERITY_THRESHOLDS["critical"]: return Severity.CRITICAL
    if cvss >= config.SEVERITY_THRESHOLDS["high"]: return Severity.HIGH
    if cvss >= config.SEVERITY_THRESHOLDS["medium"]: return Severity.MEDIUM
    if cvss >= config.SEVERITY_THRESHOLDS["low"]: return Severity.LOW
    return Severity.INFO


def sanitize_evidence(text: str, max_len: int = 2000) -> str:
    """Redact sensitive tokens and truncate evidence text."""
    for pat in [r'(?:password|passwd|pwd)\s*[:=]\s*\S+',
                r'(?:token|api_key|secret|private_key)\s*[:=]\s*\S+',
                r'(?:Bearer\s+)\S+']:
        text = re.sub(pat, '[REDACTED]', text, flags=re.I)
    return text[:max_len] + "... [truncated]" if len(text) > max_len else text


def extract_forms(html: str) -> List[Dict]:
    """Extract form actions, methods, and detailed input fields from HTML."""
    forms = []
    regex = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
    for match in regex.finditer(html):
        form_html = match.group(0)  # Use group(0) to capture the whole form tag for attribute searches
        action = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
        method = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)

        inputs = []
        for im in re.finditer(r'<input[^>]*>', form_html, re.I):
            inp_html = im.group(0)
            n = re.search(r'name=["\']([^"\']*)["\']', inp_html, re.I)
            t = re.search(r'type=["\']([^"\']*)["\']', inp_html, re.I)
            v = re.search(r'value=["\']([^"\']*)["\']', inp_html, re.I)
            inputs.append({
                "name": n.group(1) if n else "",
                "type": t.group(1) if t else "text",
                "value": v.group(1) if v else ""
            })

        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "GET").upper(),
            "inputs": inputs
        })
    return forms


def extract_js_endpoints(html: str) -> List[str]:
    """Extract API endpoints from JavaScript source."""
    endpoints = set()
    patterns = [
        r'''(?:fetch|axios\.\w+)\s*\(\s*["'`]([^"'`]+)["'`]''',
        r'''["'`](/(?:api|v\d|rest|graphql|ws|socket)/[^"'`]*)["'`]''',
        r'''url\s*[:=]\s*["'`]([^"'`]+)["'`]''',
        r'''endpoint\s*[:=]\s*["'`]([^"'`]+)["'`]''',
        r'''basePath\s*[:=]\s*["'`]([^"'`]+)["'`]''',
        r'''["\'](https?://[^"\']+)["\']''',
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, html, re.I):
            url = match.group(1)
            # Filter out static assets
            if url and not url.endswith(('.js', '.css', '.png', '.jpg', '.svg', '.gif')):
                if (url.startswith("/") or url.startswith("http")) and url not in endpoints:
                    endpoints.add(url)
    return list(endpoints)


def is_destructive(payload: str) -> bool:
    """Check if payload matches blocklist to prevent destructive actions."""
    pl = payload.lower()
    return any(b.lower() in pl for b in config.FUZZER_BLOCKLIST_PAYLOADS)


def make_url_with_param(url: str, param: str, value: str) -> str:
    """Append or replace a query parameter in a URL."""
    p = urlparse(url)
    params = parse_qs(p.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(p._replace(query=urlencode(params, doseq=True)))


def format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration string."""
    if seconds < 1: return f"{seconds * 1000:.0f}ms"
    if seconds < 60: return f"{seconds:.1f}s"
    return f"{int(seconds // 60)}m {seconds % 60:.0f}s"