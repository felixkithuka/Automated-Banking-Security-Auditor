"""
ABSA Report Builder
Assembles all scan data into a structured dictionary ready for PDF generation.
Computes statistics, severity distributions, category breakdowns, and
produces all text sections using templates.py string constants.

Supports two modes:
  1. Full mode: receives PhaseResult objects (used by full pipeline orchestrator)
  2. Findings-only mode: receives just findings + context (used by main menu loop)

IMPORTANT: This module works with the dataclass-based models in core.models
where Severity values are lowercase ("critical", "high", etc.) and
FindingType values are lowercase ("known_cve", "owasp", etc.).
"""

from collections import Counter
from datetime import datetime
from typing import Dict, Any, List, Optional

from core.models import ScanContext, Finding, Severity, FindingType
from utils.logger import get_logger
from reporting import templates as T

logger = get_logger("reporting.builder")

try:
    import config
    _APP_VERSION = getattr(config, "APP_VERSION", "1.0.0")
except ImportError:
    _APP_VERSION = "1.0.0"


class ReportBuilder:
    """
    Transforms raw scan results into a structured report dictionary.
    The output dict contains every field needed by PDFGenerator.
    """

    SEVERITY_ORDER = [
        Severity.CRITICAL, Severity.HIGH,
        Severity.MEDIUM, Severity.LOW, Severity.INFO,
    ]

    SEVERITY_LABELS = {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Info",
    }

    FINDING_TYPE_LABELS = {
        "known_cve": "Known CVE",
        "owasp": "OWASP Top 10",
        "configuration": "Misconfiguration",
        "zero_day": "Zero-Day",
        "business_logic": "Business Logic",
        "api_security": "API Security",
        "auth_bypass": "Authentication Bypass",
    }

    def __init__(self, context: ScanContext,
                 phase_results: Optional[Dict[str, Any]] = None):
        self.ctx = context
        self.phases = phase_results or {}

    def build(self) -> Dict[str, Any]:
        """Build the complete report data structure."""
        findings = self.ctx.findings
        sorted_findings = self._sort_findings(findings)

        severity_dist = self._count_severities(findings)
        category_dist = self._count_types(findings)
        risk_rating = self._compute_risk_rating(severity_dist)

        zeroday_findings = [
            f for f in sorted_findings
            if getattr(f, "is_zero_day", False)
        ]

        session_id = getattr(self.ctx, "session_id", "") or "menu_session"
        start_time = getattr(self.ctx, "start_time", "") or ""
        if start_time and hasattr(start_time, "strftime"):
            start_time = start_time.strftime("%Y-%m-%d")
        elif not start_time:
            start_time = datetime.utcnow().strftime("%Y-%m-%d")

        return {
            "metadata": self._build_metadata(session_id, start_time),
            "executive_summary": self._build_executive_summary(
                findings, severity_dist, risk_rating, zeroday_findings,
                session_id, start_time,
            ),
            "severity_distribution": severity_dist,
            "category_breakdown": category_dist,
            "risk_rating": risk_rating,
            "phase_results": self._build_phase_results(),
            "findings": [
                self._render_finding(f) for f in sorted_findings
            ],
            "zeroday_findings": [
                self._render_zeroday_advisory(f, session_id)
                for f in zeroday_findings
            ],
            "compliance_summary": self._build_compliance_summary(findings),
            "stealth_info": self._build_stealth_info(),
            "disclaimer": T.DISCLAIMER.format(
                authorized_by="the authorized recipient",
                engagement_id=session_id,
                target_url=self.ctx.target_url,
            ),
            "title": T.TITLE,
            "classification": T.CLASSIFICATION,
            "generated_at": datetime.utcnow().isoformat() + "Z",
        }

    def _build_metadata(self, session_id: str, start_time: str) -> dict:
        return {
            "target_url": self.ctx.target_url,
            "target_domain": getattr(self.ctx, "target_domain", ""),
            "target_scheme": getattr(self.ctx, "target_scheme", "https"),
            "target_port": getattr(self.ctx, "target_port", 443),
            "session_id": session_id,
            "start_time": start_time,
            "end_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
            "report_version": _APP_VERSION,
        }

    def _build_executive_summary(self, findings, sev_dist, risk_rating,
                                  zeroday_findings, session_id,
                                  start_time) -> str:
        crits = [f for f in findings if f.severity == Severity.CRITICAL]
        top_items = ""
        for i, f in enumerate(crits[:5], 1):
            top_items += T.TOP_CRITICAL_ITEM_TEMPLATE.format(
                index=i,
                title=f.title,
                cvss=getattr(f, "cvss_score", 0),
                location=getattr(f, "affected_file_or_component", None) or getattr(f, "affected_url", "N/A") or "N/A",
                description=(f.description or "")[:200],
                remediation=(getattr(f, "remediation", "") or "See detailed finding below")[:200],
            ) + "\n\n"
        if not top_items:
            top_items = "No critical findings identified.\n\n"

        if zeroday_findings:
            zd_items = "\n".join(
                T.ZERODAY_ITEM_TEMPLATE.format(
                    title=f.title,
                    cvss=getattr(f, "cvss_score", 0),
                    location=getattr(f, "affected_file_or_component", None) or getattr(f, "affected_url", "N/A") or "N/A",
                    detail=(getattr(f, "zero_day_detail", None) or f.description or "")[:150],
                )
                for f in zeroday_findings[:5]
            )
            zd_section = T.ZERODAY_SECTION_TEMPLATE.format(
                zeroday_count=len(zeroday_findings),
                zeroday_items=zd_items,
            )
        else:
            zd_section = "No zero-day findings were identified during this assessment.\n"

        stealth_profile = "standard operational security measures"
        stealth_details = ""

        try:
            return T.EXECUTIVE_SUMMARY_TEMPLATE.format(
                target_url=self.ctx.target_url,
                engagement_id=session_id,
                authorized_by="the authorized party",
                issued_at=start_time,
                risk_rating=risk_rating,
                total_findings=len(findings),
                critical=sev_dist.get("Critical", 0),
                high=sev_dist.get("High", 0),
                medium=sev_dist.get("Medium", 0),
                low=sev_dist.get("Low", 0),
                info=sev_dist.get("Info", 0),
                top_critical_section=T.TOP_CRITICAL_TEMPLATE.format(
                    top_items=top_items.strip(),
                ),
                zeroday_section=zd_section,
                stealth_profile=stealth_profile,
            ).rstrip() + "\n" + stealth_details
        except (KeyError, ValueError) as exc:
            logger.error("Executive summary template error: %s", exc)
            return (
                f"Security assessment of {self.ctx.target_url} identified "
                f"{len(findings)} findings with risk rating {risk_rating}."
            )

    def _count_severities(self, findings: List[Finding]) -> Dict[str, int]:
        counts = Counter(
            self.SEVERITY_LABELS.get(f.severity, "Info")
            for f in findings
            if hasattr(f, "severity")
        )
        return {
            "Critical": counts.get("Critical", 0),
            "High": counts.get("High", 0),
            "Medium": counts.get("Medium", 0),
            "Low": counts.get("Low", 0),
            "Info": counts.get("Info", 0),
        }

    def _count_types(self, findings: List[Finding]) -> Dict[str, int]:
        counts = Counter()
        for f in findings:
            ft = f.finding_type
            if hasattr(ft, "value"):
                key = self.FINDING_TYPE_LABELS.get(ft.value, ft.value)
            else:
                key = self.FINDING_TYPE_LABELS.get(str(ft), str(ft))
            counts[key] += 1
        return dict(counts.most_common())

    def _compute_risk_rating(self, sev_dist: Dict[str, int]) -> str:
        crit = sev_dist.get("Critical", 0)
        high = sev_dist.get("High", 0)

        if crit >= 3 or (crit >= 1 and high >= 5):
            return "CRITICAL"
        elif crit >= 1 or high >= 3:
            return "HIGH"
        elif high >= 1 or sev_dist.get("Medium", 0) >= 5:
            return "MEDIUM"
        elif sev_dist.get("Medium", 0) >= 1 or sev_dist.get("Low", 0) >= 3:
            return "LOW"
        else:
            return "INFORMATIONAL"

    def _build_phase_results(self) -> List[Dict[str, Any]]:
        if self.phases:
            results = []
            for key, pr in self.phases.items():
                if hasattr(pr, "status"):
                    status_str = pr.status.value.upper() if hasattr(pr.status, "value") else str(pr.status)
                else:
                    status_str = str(pr)

                stats_parts = []
                if hasattr(pr, "stats") and pr.stats:
                    for sk, sv in pr.stats.items():
                        if isinstance(sv, (int, float)):
                            stats_parts.append(f"{sk}={sv}")
                        elif isinstance(sv, str) and len(sv) < 60:
                            stats_parts.append(f"{sk}={sv}")

                results.append({
                    "name": getattr(pr, "phase_name", key),
                    "status": status_str,
                    "duration": f"{getattr(pr, 'duration_seconds', 0):.1f}s"
                    if getattr(pr, "duration_seconds", 0) > 0 else "N/A",
                    "finding_count": len(getattr(pr, "findings", [])),
                    "stats_str": " | ".join(stats_parts) if stats_parts else "N/A",
                    "error": getattr(pr, "error_message", ""),
                })
            return results

        phase_map: Dict[str, List] = {}
        for f in self.ctx.findings:
            ph = getattr(f, "phase", "unknown") or "unknown"
            phase_map.setdefault(ph, []).append(f)

        results = []
        phase_labels = {
            "recon_infrastructure": "Reconnaissance",
            "recon": "Reconnaissance",
            "scanner_auth": "Auth Scanner",
            "scanner_api": "API Scanner",
            "scanner": "Vulnerability Scanner",
            "zeroday_financial": "Zero-Day (Financial)",
            "zeroday_smuggling": "Zero-Day (Smuggling)",
            "zeroday": "Zero-Day Simulation",
            "stealth": "Stealth & WAF",
            "tls": "TLS Analysis",
            "headers": "Header Analysis",
        }
        for ph, ph_findings in phase_map.items():
            results.append({
                "name": phase_labels.get(ph, ph.replace("_", " ").title()),
                "status": "COMPLETE",
                "duration": "N/A",
                "finding_count": len(ph_findings),
                "stats_str": f"{len(ph_findings)} finding(s)",
                "error": "",
            })

        if not results:
            results = [{
                "name": "Scan",
                "status": "COMPLETE",
                "duration": "N/A",
                "finding_count": len(self.ctx.findings),
                "stats_str": f"{len(self.ctx.findings)} finding(s)",
                "error": "",
            }]

        return results

    def _sort_findings(self, findings: List[Finding]) -> List[Finding]:
        order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
        }
        return sorted(
            findings,
            key=lambda f: (
                order.get(f.severity, 5) if hasattr(f, "severity") else 5,
                -(getattr(f, "cvss_score", 0)),
            ),
        )

    def _render_finding(self, f: Finding) -> Dict[str, Any]:
        cve_section = ""
        cve_details = getattr(f, "cve_details", None)
        if cve_details:
            cve_items = []
            for cve in cve_details:
                exploit_status = (
                    f"Yes (EDB-{cve.exploit_db_id})"
                    if getattr(cve, "exploit_available", False)
                    else "No public exploit"
                )
                sev_val = getattr(cve, "severity", "N/A")
                if hasattr(sev_val, "value"):
                    sev_val = sev_val.value.upper()
                else:
                    sev_val = str(sev_val).upper()

                cve_items.append(T.CVE_ITEM_TEMPLATE.format(
                    cve_id=getattr(cve, "cve_id", ""),
                    cvss_score=getattr(cve, "cvss_score", 0),
                    severity=sev_val,
                    description=getattr(cve, "description", "")[:300],
                    published_date=getattr(cve, "published_date", "N/A"),
                    patch_url=getattr(cve, "patch_url", "N/A"),
                    exploit_status=exploit_status,
                ))
            cve_section = T.CVE_SECTION_TEMPLATE.format(
                cve_items="\n".join(cve_items)
            )

        compliance_section = ""
        compliance_mappings = getattr(f, "compliance_mappings", None)
        if compliance_mappings:
            comp_items = []
            for cm in compliance_mappings:
                comp_items.append(T.COMPLIANCE_ITEM_TEMPLATE.format(
                    framework=getattr(cm, "framework", ""),
                    clause_id=getattr(cm, "clause_id", ""),
                    clause_title=getattr(cm, "clause_title", ""),
                    description=getattr(cm, "description", ""),
                ))
            compliance_section = T.COMPLIANCE_SECTION_TEMPLATE.format(
                compliance_items="\n".join(comp_items)
            )

        repro_steps = getattr(f, "reproduction_steps", None)
        if repro_steps:
            repro = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(repro_steps))
        else:
            repro = "  See evidence section for details."

        evidence = getattr(f, "affected_url", None) or "N/A"
        if getattr(f, "evidence", None):
            evidence += "\n" + str(f.evidence)
        payloads = getattr(f, "payloads", None)
        if payloads:
            for p in payloads[:3]:
                payload_str = getattr(p, "payload_string", str(p))
                evidence += f"\nPayload: {payload_str}"
                if getattr(p, "evidence", None):
                    evidence += f"\n  {p.evidence}"

        ft = f.finding_type
        ft_label = ft.value if hasattr(ft, "value") else str(ft)
        ft_label = self.FINDING_TYPE_LABELS.get(ft_label, ft_label)

        sev_label = self.SEVERITY_LABELS.get(f.severity, "Info") if hasattr(f, "severity") else "Info"

        remediation_code = getattr(f, "remediation_code", "") or ""
        if not remediation_code.strip():
            remediation_code = T.NO_FINDINGS_MESSAGE

        try:
            rendered = T.FINDING_TEMPLATE.format(
                title=f.title,
                severity=sev_label,
                cvss_score=getattr(f, "cvss_score", 0),
                cwe_id=getattr(f, "cwe_id", "N/A"),
                finding_type=ft_label,
                phase=getattr(f, "phase", "unknown"),
                affected_url=getattr(f, "affected_url", "N/A") or "N/A",
                affected_file_or_component=getattr(f, "affected_file_or_component", "N/A") or "N/A",
                affected_parameter=getattr(f, "affected_parameter", "N/A") or "N/A",
                discovered_at=(getattr(f, "discovered_at", "") or "")[:19],
                description=f.description or "",
                cve_section=cve_section,
                evidence=evidence.strip(),
                reproduction_steps=repro,
                remediation=getattr(f, "remediation", None) or T.NO_FINDINGS_MESSAGE,
                remediation_code=remediation_code,
                compliance_section=compliance_section,
            )
        except (KeyError, ValueError) as exc:
            logger.error("Finding template error for %s: %s", f.title, exc)
            rendered = f"{f.title}\nSeverity: {sev_label}\n{f.description or ''}"

        return {
            "title": f.title,
            "severity": sev_label,
            "cvss_score": getattr(f, "cvss_score", 0),
            "cwe_id": getattr(f, "cwe_id", "N/A"),
            "finding_type": ft_label,
            "phase": getattr(f, "phase", "unknown"),
            "affected_url": getattr(f, "affected_url", "N/A"),
            "affected_file_or_component": getattr(f, "affected_file_or_component", "N/A"),
            "affected_parameter": getattr(f, "affected_parameter", "N/A"),
            "discovered_at": (getattr(f, "discovered_at", "") or "")[:19],
            "is_zero_day": getattr(f, "is_zero_day", False),
            "rendered_text": rendered,
        }

    def _render_zeroday_advisory(self, f: Finding,
                                  session_id: str) -> Dict[str, Any]:
        evidence = getattr(f, "affected_url", None) or "N/A"
        if getattr(f, "evidence", None):
            evidence += "\n" + str(f.evidence)
        payloads = getattr(f, "payloads", None)
        if payloads:
            for p in payloads[:3]:
                payload_str = getattr(p, "payload_string", str(p))
                evidence += f"\nPayload: {payload_str}"

        sev_label = self.SEVERITY_LABELS.get(f.severity, "Info") if hasattr(f, "severity") else "Info"

        remediation_code = getattr(f, "remediation_code", "") or ""
        if not remediation_code.strip():
            remediation_code = T.NO_FINDINGS_MESSAGE

        try:
            rendered = T.ZERODAY_ADVISORY_TEMPLATE.format(
                title=f.title,
                severity=sev_label,
                cvss_score=getattr(f, "cvss_score", 0),
                cwe_id=getattr(f, "cwe_id", "N/A"),
                affected_url=getattr(f, "affected_url", "N/A"),
                affected_file_or_component=getattr(f, "affected_file_or_component", "N/A") or "N/A",
                description=f.description or "",
                detail=getattr(f, "zero_day_detail", None) or f.description or "",
                evidence=evidence.strip(),
                remediation=getattr(f, "remediation", None) or T.NO_FINDINGS_MESSAGE,
                remediation_code=remediation_code,
                engagement_id=session_id,
            )
        except (KeyError, ValueError) as exc:
            logger.error("Zero-day template error for %s: %s", f.title, exc)
            rendered = f"ZERO-DAY: {f.title}\nSeverity: {sev_label}\n{f.description or ''}"

        return {
            "title": f.title,
            "severity": sev_label,
            "cvss_score": getattr(f, "cvss_score", 0),
            "cwe_id": getattr(f, "cwe_id", "N/A"),
            "rendered_text": rendered,
        }

    def _build_compliance_summary(self, findings: List[Finding]) -> Dict[str, List[Dict]]:
        framework_map: Dict[str, List[Dict]] = {}
        for f in findings:
            for cm in getattr(f, "compliance_mappings", []):
                fw = getattr(cm, "framework", "")
                if fw not in framework_map:
                    framework_map[fw] = []
                sev_label = self.SEVERITY_LABELS.get(f.severity, "Info") if hasattr(f, "severity") else "Info"
                framework_map[fw].append({
                    "clause_id": getattr(cm, "clause_id", ""),
                    "clause_title": getattr(cm, "clause_title", ""),
                    "description": getattr(cm, "description", ""),
                    "finding_title": f.title,
                    "severity": sev_label,
                    "cvss": getattr(f, "cvss_score", 0),
                })

        for fw in framework_map:
            framework_map[fw].sort(key=lambda x: x["clause_id"])

        return framework_map

    def _build_stealth_info(self) -> Dict[str, Any]:
        return {
            "enabled": False,
            "profile": "standard",
            "proxy_count": 0,
            "rotation_threshold": 0,
            "rendered_text": "Stealth measures were not enabled for this assessment. Standard browser-like headers and request timing were used.",
        }