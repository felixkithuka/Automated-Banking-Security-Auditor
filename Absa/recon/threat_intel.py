"""
Threat Intelligence Module for Absa Security Testing Framework

Enriches scan targets with contextual threat data, manages IOCs,
and correlates findings with known vulnerabilities and threat actors.

This module is designed for authorized security testing only.
"""

import re
import time
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Any, Tuple
from enum import Enum
from datetime import datetime
import asyncio

logger = logging.getLogger(__name__)


class IOCType(Enum):
    """Indicator of Compromise types."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    PORT = "port"
    USER_AGENT = "user_agent"
    JA3 = "ja3"


class ThreatSeverity(Enum):
    """Severity rating for threats."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(Enum):
    """Categories of threats."""
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    SPAM = "spam"
    SCAN = "scanning"
    EXPLOIT = "exploit"
    C2 = "command_and_control"
    TOR = "tor_exit_node"
    PROXY = "open_proxy"
    VPN = "vpn"
    DEFACEMENT = "defacement"
    RANSOMWARE = "ransomware"
    CREDENTIAL_THEFT = "credential_theft"
    UNKNOWN = "unknown"


class IntelSource(Enum):
    """Sources of threat intelligence."""
    LOCAL_CACHE = "local_cache"
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    ALIENVAULT_OTX = "alienvault_otx"
    SHODAN = "shodan"
    CIRCL = "circl_passive_dns"
    NIST_NVD = "nist_nvd"
    CUSTOM_FEED = "custom_feed"


@dataclass
class IOCRecord:
    """Represents a single Indicator of Compromise."""
    ioc_value: str
    ioc_type: IOCType
    severity: ThreatSeverity = ThreatSeverity.INFO
    categories: List[ThreatCategory] = field(default_factory=list)
    description: str = ""
    source: IntelSource = IntelSource.LOCAL_CACHE
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnerabilityRecord:
    """Represents a known vulnerability (CVE)."""
    cve_id: str
    severity: ThreatSeverity
    cvss_score: float = 0.0
    cvss_vector: str = ""
    description: str = ""
    affected_products: List[str] = field(default_factory=list)
    exploit_available: bool = False
    patch_available: bool = False
    references: List[str] = field(default_factory=list)
    source: IntelSource = IntelSource.NIST_NVD


@dataclass
class ThreatProfile:
    """Aggregated threat profile for a target."""
    target: str
    risk_score: int = 0  # 0-100
    iocs: List[IOCRecord] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityRecord] = field(default_factory=list)
    associated_malware: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ThreatDataCache:
    """
    Local in-memory cache for threat intelligence to prevent
    API rate limit exhaustion during scans.
    """

    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = ttl_seconds
        self._cache: Dict[str, Tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[Any]:
        if key in self._cache:
            data, timestamp = self._cache[key]
            if time.time() - timestamp < self.ttl:
                return data
            else:
                del self._cache[key]
        return None

    def set(self, key: str, value: Any):
        self._cache[key] = (value, time.time())

    def clear(self):
        self._cache.clear()


class IOCPARSER:
    """
    Utility class to extract and normalize Indicators of Compromise
    from arbitrary text, HTTP responses, or structured data.
    """

    # Regex patterns for IOC extraction
    PATTERNS = {
        IOCType.IPV4: r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        IOCType.DOMAIN: r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,})\b',
        IOCType.HASH_MD5: r'\b(?:[a-fA-F0-9]{32})\b',
        IOCType.HASH_SHA1: r'\b(?:[a-fA-F0-9]{40})\b',
        IOCType.HASH_SHA256: r'\b(?:[a-fA-F0-9]{64})\b',
        IOCType.EMAIL: r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        IOCType.CVE: r'\bCVE-\d{4}-\d{4,}\b',
        IOCType.URL: r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w .?=&#%-]*',
    }

    @classmethod
    def extract_iocs(cls, text: str, exclude_domains: Optional[Set[str]] = None) -> List[IOCRecord]:
        """
        Extract IOCs from a block of text.

        Args:
            text: The text to parse.
            exclude_domains: Set of safe domains to ignore (e.g., google.com, github.com).

        Returns:
            List of extracted IOCRecord objects.
        """
        exclude_domains = exclude_domains or set()
        records = []

        for ioc_type, pattern in cls.PATTERNS.items():
            matches = re.findall(pattern, text)
            for match in matches:
                match = match.strip()

                # Filtering
                if ioc_type == IOCType.DOMAIN:
                    if match.lower() in exclude_domains:
                        continue
                    if cls._is_false_positive_domain(match):
                        continue

                if ioc_type == IOCType.HASH_MD5:
                    if cls._is_false_positive_hash(match, text):
                        continue

                records.append(IOCRecord(
                    ioc_value=match,
                    ioc_type=ioc_type,
                    source=IntelSource.LOCAL_CACHE
                ))

        return records

    @staticmethod
    def _is_false_positive_domain(domain: str) -> bool:
        """Filter out domains that are clearly not malicious infrastructure."""
        fp_tlds = {'.exe', '.zip', '.tar', '.gz', '.jpg', '.png', '.js', '.css'}
        return any(domain.lower().endswith(tld) for tld in fp_tlds)

    @staticmethod
    def _is_false_positive_hash(hash_str: str, context: str) -> bool:
        """Filter out MD5 hashes that are likely CSS/JS cache busters or session IDs."""
        # If surrounded by ?= or similar, likely a cache buster
        if re.search(r'[?&=]' + re.escape(hash_str), context):
            return True
        return False

    @classmethod
    def classify_ioc(cls, value: str, ioc_type: Optional[IOCType] = None) -> IOCType:
        """Determine the type of an IOC string if not provided."""
        if ioc_type:
            return ioc_type

        if re.match(cls.PATTERNS[IOCType.HASH_SHA256], value): return IOCType.HASH_SHA256
        if re.match(cls.PATTERNS[IOCType.HASH_SHA1], value): return IOCType.HASH_SHA1
        if re.match(cls.PATTERNS[IOCType.HASH_MD5], value): return IOCType.HASH_MD5
        if re.match(cls.PATTERNS[IOCType.CVE], value, re.IGNORECASE): return IOCType.CVE
        if re.match(cls.PATTERNS[IOCType.IPV4], value): return IOCType.IPV4
        if re.match(cls.PATTERNS[IOCType.EMAIL], value): return IOCType.EMAIL
        if value.startswith('http://') or value.startswith('https://'): return IOCType.URL
        if re.match(cls.PATTERNS[IOCType.DOMAIN], value): return IOCType.DOMAIN

        return IOCType.UNKNOWN if hasattr(IOCType, 'UNKNOWN') else IOCType.DOMAIN


# Fix missing UNKNOWN type
IOCType.UNKNOWN = "unknown"


class ThreatProfiler:
    """
    Aggregates IOCs and vulnerability data into a comprehensive
    Risk Score for a specific target.
    """

    # Weights for risk calculation
    SEVERITY_WEIGHTS = {
        ThreatSeverity.INFO: 0,
        ThreatSeverity.LOW: 10,
        ThreatSeverity.MEDIUM: 30,
        ThreatSeverity.HIGH: 60,
        ThreatSeverity.CRITICAL: 100,
    }

    CATEGORY_MULTIPLIERS = {
        ThreatCategory.MALWARE: 1.5,
        ThreatCategory.C2: 1.8,
        ThreatCategory.RANSOMWARE: 2.0,
        ThreatCategory.EXPLOIT: 1.4,
        ThreatCategory.PHISHING: 1.0,
        ThreatCategory.SCAN: 0.5,
        ThreatCategory.UNKNOWN: 0.8,
    }

    def calculate_risk_score(self, profile: ThreatProfile) -> int:
        """
        Calculate a 0-100 risk score based on aggregated IOCs and CVEs.
        Uses a weighted algorithm factoring severity, confidence, and threat category.
        """
        score = 0.0

        # Process IOCs
        for ioc in profile.iocs:
            base_score = self.SEVERITY_WEIGHTS.get(ioc.severity, 0)

            # Apply category multiplier
            max_mult = 1.0
            for cat in ioc.categories:
                mult = self.CATEGORY_MULTIPLIERS.get(cat, 1.0)
                if mult > max_mult:
                    max_mult = mult

            # Apply confidence (0.0 to 1.0)
            ioc_score = base_score * max_mult * ioc.confidence
            score += ioc_score

        # Process CVEs
        for vuln in profile.vulnerabilities:
            if vuln.exploit_available:
                score += (vuln.cvss_score * 5)  # Heavy weight for exploitable vulns
            else:
                score += (vuln.cvss_score * 2)

        # Normalize to 0-100
        normalized_score = min(int(score), 100)
        profile.risk_score = normalized_score
        return normalized_score

    def generate_tags(self, profile: ThreatProfile) -> List[str]:
        """Generate actionable tags based on the threat profile."""
        tags = set()

        categories_seen = set()
        for ioc in profile.iocs:
            categories_seen.update(ioc.categories)

        for cat in categories_seen:
            tags.add(f"threat:{cat.value}")

        if any(v.exploit_available for v in profile.vulnerabilities):
            tags.add("status:exploitable_vulns")

        if profile.risk_score >= 80:
            tags.add("risk:critical")
        elif profile.risk_score >= 50:
            tags.add("risk:high")
        elif profile.risk_score > 0:
            tags.add("risk:elevated")
        else:
            tags.add("risk:clean")

        profile.tags = list(tags)
        return profile.tags


class ThreatIntelClient:
    """
    Main facade for Threat Intelligence operations.
    Handles caching, API abstraction, and profiling.
    """

    def __init__(self, api_keys: Optional[Dict[str, str]] = None, config: Optional[Dict] = None):
        """
        Initialize Threat Intel Client.

        Args:
            api_keys: Dictionary of API keys (e.g., {'virustotal': '...', 'abuseipdb': '...'})
            config: Configuration options (e.g., cache_ttl, timeouts)
        """
        self.api_keys = api_keys or {}
        self.config = config or {}

        ttl = self.config.get("cache_ttl", 7200)
        self.cache = ThreatDataCache(ttl_seconds=ttl)
        self.profiler = ThreatProfiler()

        # Safe domains to ignore during IOC extraction (common JS/CSS hosts)
        self.safe_domains = {
            'google.com', 'googleapis.com', 'gstatic.com', 'github.com',
            'cloudflare.com', 'jquery.com', 'cloudflareinsights.com',
            'wordpress.org', 'apache.org', 'microsoft.com', 'amazonaws.com'
        }

    async def enrich_target(self, url: str, response: Any = None, body_text: str = None) -> ThreatProfile:
        """
        Main entry point. Enriches a target URL with threat intelligence.

        Args:
            url: The target URL.
            response: Optional HTTP response object to extract IOCs from.
            body_text: Optional raw body text to extract IOCs from.

        Returns:
            A populated ThreatProfile.
        """
        profile = ThreatProfile(target=url)

        text_to_parse = body_text or ""
        if response and not text_to_parse:
            text_to_parse = self._extract_text_from_response(response)

        # 1. Extract IOCs from content
        if text_to_parse:
            extracted_iocs = IOCPARSER.extract_iocs(text_to_parse, self.safe_domains)
            profile.iocs.extend(extracted_iocs)

        # 2. Check external APIs if keys are present (placeholder logic)
        if self.api_keys.get('virustotal'):
            # await self._query_virustotal(url, profile)
            pass

        # 3. Calculate Risk
        self.profiler.calculate_risk_score(profile)

        # 4. Generate Tags
        self.profiler.generate_tags(profile)

        return profile

    def parse_response_for_iocs(self, response: Any) -> List[IOCRecord]:
        """Shortcut to just extract IOCs from a response."""
        text = self._extract_text_from_response(response)
        return IOCPARSER.extract_iocs(text, self.safe_domains)

    def create_ioc(self, value: str, ioc_type: Optional[IOCType] = None, **kwargs) -> IOCRecord:
        """Factory method to easily create a typed IOCRecord."""
        resolved_type = IOCPARSER.classify_ioc(value, ioc_type)
        return IOCRecord(ioc_value=value, ioc_type=resolved_type, **kwargs)

    def add_manual_vulnerability(self, profile: ThreatProfile, cve_id: str,
                                 severity: ThreatSeverity, cvss: float = 0.0, **kwargs):
        """Manually attach a vulnerability to a threat profile."""
        vuln = VulnerabilityRecord(
            cve_id=cve_id, severity=severity, cvss_score=cvss, **kwargs
        )
        profile.vulnerabilities.append(vuln)

    def _extract_text_from_response(self, response: Any) -> str:
        """Safely extract text from various HTTP client response types."""
        if hasattr(response, 'text'):
            return response.text
        if hasattr(response, 'body'):
            return response.body.decode('utf-8', errors='ignore') if isinstance(response.body, bytes) else str(
                response.body)
        return ""

    def get_profile_summary(self, profile: ThreatProfile) -> str:
        """Generate a human-readable summary of the threat profile."""
        lines = [
            f"Threat Intelligence Summary for: {profile.target}",
            f"Overall Risk Score: {profile.risk_score}/100",
            f"Tags: {', '.join(profile.tags) if profile.tags else 'None'}",
        ]

        if profile.iocs:
            lines.append(f"\nExtracted IOCs ({len(profile.iocs)}):")
            # Group by type
            ioc_groups: Dict[str, List[str]] = {}
            for ioc in profile.iocs:
                ioc_groups.setdefault(ioc.ioc_type.value, []).append(ioc.ioc_value)

            for ioc_type, values in ioc_groups.items():
                lines.append(f"  [{ioc_type.upper()}]")
                for val in values[:5]:  # Limit output
                    lines.append(f"    - {val}")
                if len(values) > 5:
                    lines.append(f"    - ...and {len(values) - 5} more")

        if profile.vulnerabilities:
            lines.append(f"\nKnown Vulnerabilities ({len(profile.vulnerabilities)}):")
            for vuln in profile.vulnerabilities:
                exploit_str = " [EXPLOIT AVAILABLE]" if vuln.exploit_available else ""
                lines.append(
                    f"  - {vuln.cve_id} (CVSS: {vuln.cvss_score}, Severity: {vuln.severity.value}){exploit_str}")

        return "\n".join(lines)