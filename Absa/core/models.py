"""
ABSA Data Models
All structured objects used across the framework.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(Enum):
    KNOWN_CVE = "known_cve"
    OWASP = "owasp"
    CONFIGURATION = "configuration"
    ZERO_DAY = "zero_day"
    BUSINESS_LOGIC = "business_logic"
    API_SECURITY = "api_security"
    AUTH_BYPASS = "auth_bypass"


class PhaseStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class Technology:
    name: str
    version: Optional[str] = None
    category: str = ""
    cpe: Optional[str] = None
    confidence: float = 0.0
    source: str = ""


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    status_code: int = 0
    content_type: str = ""
    parameters: List[str] = field(default_factory=list)
    forms: List[dict] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    discovery_source: str = ""
    is_login: bool = False
    is_api: bool = False
    body_sample: str = ""


@dataclass
class Subdomain:
    fqdn: str
    ip_addresses: List[str] = field(default_factory=list)
    source: str = ""
    http_status: int = 0


@dataclass
class TLSResult:
    version: str = ""
    cipher_suite: str = ""
    weak_ciphers_found: List[str] = field(default_factory=list)
    certificate_issuer: str = ""
    certificate_expiry: str = ""
    hsts_enabled: bool = False
    hsts_max_age: int = 0
    issues: List[str] = field(default_factory=list)


@dataclass
class HeaderResult:
    header_name: str
    present: bool = False
    value: str = ""
    expected_directive: Optional[str] = None
    compliant: bool = False
    fix: str = ""


@dataclass
class Payload:
    payload_string: str
    payload_type: str = ""
    parameter: str = ""
    location: str = ""
    response_code: int = 0
    response_time_ms: float = 0.0
    evidence: str = ""
    success: bool = False


@dataclass
class CVEDetail:
    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: Severity = Severity.INFO
    cwe_id: str = ""
    published_date: str = ""
    patch_url: str = ""
    exploit_available: bool = False
    exploit_db_id: Optional[int] = None


@dataclass
class ComplianceMapping:
    framework: str = ""
    clause_id: str = ""
    clause_title: str = ""
    description: str = ""


@dataclass
class Finding:
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    finding_type: FindingType = FindingType.OWASP
    cwe_id: str = ""
    cve_details: List[CVEDetail] = field(default_factory=list)
    affected_url: str = ""
    affected_file_or_component: str = ""  # Specific location of the flaw
    affected_parameter: str = ""
    payloads: List[Payload] = field(default_factory=list)
    evidence: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    remediation: str = ""
    remediation_code: str = ""
    compliance_mappings: List[ComplianceMapping] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    is_zero_day: bool = False
    zero_day_detail: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    phase: str = ""
    weakness_type: str = ""


@dataclass
class PhaseResult:
    phase_name: str
    status: PhaseStatus = PhaseStatus.PENDING
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    subdomains: List[Subdomain] = field(default_factory=list)
    endpoints: List[Endpoint] = field(default_factory=list)
    technologies: List[Technology] = field(default_factory=list)
    tls_result: Optional[TLSResult] = None
    header_results: List[HeaderResult] = field(default_factory=list)
    error_message: str = ""
    stats: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanContext:
    target_url: str
    target_domain: str = ""
    target_scheme: str = "https"
    target_port: int = 443
    session_id: str = ""
    authorization_token: str = ""
    concurrency: int = 10
    delay: float = 0.1
    timeout: int = 15
    output_dir: str = ""
    evidence_dir: str = ""
    findings: List[Finding] = field(default_factory=list)
    phase_results: Dict[str, PhaseResult] = field(default_factory=dict)
    is_authorized: bool = False
    start_time: Optional[str] = None
    end_time: Optional[str] = None

    def add_finding(self, finding: Finding) -> None:
        if finding.title not in {f.title for f in self.findings}:
            self.findings.append(finding)

    def add_findings(self, findings: List[Finding]) -> None:
        for f in findings:
            self.add_finding(f)