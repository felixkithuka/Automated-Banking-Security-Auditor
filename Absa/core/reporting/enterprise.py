"""
ABSA Enterprise Reporting & Collaboration Engine
Handles metric aggregation, ticket generation, and executive summary finalization.
"""

import json
from typing import Dict, List, Optional, Any
from datetime import datetime

from core.models import ScanContext, Finding, Severity
from utils.logger import get_logger

logger = get_logger("reporting.enterprise")


class EnterpriseReporter:
    """Finalizes enterprise reporting workflows and collaboration tasks."""

    def __init__(self, context: ScanContext):
        self.ctx = context

    def generate_jira_tickets(self) -> List[Dict]:
        tickets = []
        priority_map = {
            Severity.CRITICAL: "Highest",
            Severity.HIGH: "High",
            Severity.MEDIUM: "Medium",
            Severity.LOW: "Low",
            Severity.INFO: "Lowest"
        }

        for finding in self.ctx.findings:
            if finding.remediation:
                desc = f"{finding.description}\n\n**Evidence:**\n{finding.evidence}\n\n**Fix:**\n{finding.remediation}"
            else:
                desc = finding.description

            if finding.remediation_code:
                desc += f"\n\n**Code Fix:**\n```{finding.remediation_code}```"

            tickets.append({
                "project": "SEC",
                "summary": f"[ABSA] {finding.title}",
                "description": desc,
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority_map.get(finding.severity, "Low")},
                "labels": ["security", "absa", finding.weakness_type or "vulnerability"],
                "components": [{"name": "Security Remediation"}]
            })
        return tickets

    def calculate_executive_metrics(self) -> Dict[str, Any]:
        total = len(self.ctx.findings)
        if total == 0:
            return {"risk_score": 0, "status": "Secure"}

        counts = {sev: 0 for sev in Severity}
        for f in self.ctx.findings:
            counts[f.severity] += 1

        risk_score = (
                (counts[Severity.CRITICAL] * 10) +
                (counts[Severity.HIGH] * 5) +
                (counts[Severity.MEDIUM] * 2) +
                (counts[Severity.LOW] * 0.5)
        )
        risk_score = min(risk_score, 100)

        if counts[Severity.CRITICAL] > 0:
            status = "Critical Risk"
        elif risk_score > 30:
            status = "High Risk"
        elif risk_score > 10:
            status = "Medium Risk"
        else:
            status = "Low Risk"

        return {
            "risk_score": risk_score,
            "status": status,
            "total_vulnerabilities": total,
            "breakdown": {sev.name: count for sev, count in counts.items()},
            "exploitable_zero_days": sum(1 for f in self.ctx.findings if f.is_zero_day),
            "remediation_effort_days": sum(
                1 for f in self.ctx.findings if f.severity in [Severity.CRITICAL, Severity.HIGH]) * 2
        }

    def generate_remediation_workflow(self) -> Dict[str, List[str]]:
        workflow = {
            "Phase 1: Immediate Critical Fixes (0-3 Days)": [],
            "Phase 2: High Priority Hardening (1-2 Weeks)": [],
            "Phase 3: Systemic Architecture Changes (1 Month+)": []
        }

        for f in self.ctx.findings:
            task = f"[{f.cwe_id}] {f.title} - {f.affected_url or 'N/A'}"
            if f.severity == Severity.CRITICAL:
                workflow["Phase 1: Immediate Critical Fixes (0-3 Days)"].append(task)
            elif f.severity == Severity.HIGH:
                workflow["Phase 2: High Priority Hardening (1-2 Weeks)"].append(task)
            else:
                workflow["Phase 3: Systemic Architecture Changes (1 Month+)"].append(task)

        return workflow

    def export_json(self) -> str:
        return json.dumps({
            "target": self.ctx.target_url,
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": self.calculate_executive_metrics(),
            "jira_tickets": self.generate_jira_tickets(),
            "remediation_roadmap": self.generate_remediation_workflow()
        }, indent=4)