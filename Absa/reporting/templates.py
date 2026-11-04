TITLE = "Automated Banking Security Auditor - Zero-Day Aware Assessment"
CLASSIFICATION = "CONFIDENTIAL"

EXECUTIVE_SUMMARY_TEMPLATE = """This report presents the findings from a comprehensive security assessment conducted against {target_url}. The assessment was performed under engagement {engagement_id}, authorized by {authorized_by} on {issued_at}.
OVERALL RISK RATING: {risk_rating}
A total of {total_findings} vulnerabilities were identified. The breakdown is as follows:
  - Critical: {critical} - Require immediate remediation
  - High:     {high} - Significant risk requiring priority remediation
  - Medium:   {medium} - Moderate risk; remediate within 30 days
  - Low:      {low} - Minimal risk
  - Info:     {info} - Informational findings
{top_critical_section}
{zeroday_section}
All tests were non-destructive; no data was modified or deleted during the assessment."""

TOP_CRITICAL_TEMPLATE = "TOP CRITICAL FINDINGS:\n\n{top_items}"
ZERODAY_SECTION_TEMPLATE = "ZERO-DAY FINDINGS:\n{zeroday_count} potential zero-day vulnerability(ies) were discovered.\n{zeroday_items}"
TOP_CRITICAL_ITEM_TEMPLATE = "{index}. {title} (CVSS {cvss})\n   Location: {location}\n   {description}\n   Immediate Action: {remediation}"
ZERODAY_ITEM_TEMPLATE = "- {title} (CVSS {cvss})\n  Location: {location}\n  Detail: {detail}"

FINDING_TEMPLATE = """TITLE: {title}
SEVERITY: {severity} | CVSS: {cvss_score} | CWE: {cwe_id}
TYPE: {finding_type}
PHASE DISCOVERED: {phase}
AFFECTED URL: {affected_url}
AFFECTED FILE/COMPONENT: {affected_file_or_component}
AFFECTED PARAMETER: {affected_parameter}
DISCOVERED: {discovered_at}

DESCRIPTION:
{description}

{cve_section}

EVIDENCE:
{evidence}

REPRODUCTION STEPS:
{reproduction_steps}

REMEDIATION:
{remediation}

REMEDIATION CODE:
{remediation_code}

{compliance_section}"""

CVE_SECTION_TEMPLATE = "KNOWN CVE REFERENCES:\n{cve_items}"
CVE_ITEM_TEMPLATE = "  - {cve_id} - CVSS {cvss_score} ({severity})\n    {description}\n    Patch: {patch_url} | Public Exploit: {exploit_status}"
COMPLIANCE_SECTION_TEMPLATE = "COMPLIANCE MAPPING:\n{compliance_items}"
COMPLIANCE_ITEM_TEMPLATE = "  - {framework} - Clause {clause_id}: {clause_title}\n    {description}"

ZERODAY_ADVISORY_TEMPLATE = """ZERO-DAY ADVISORY: {title}
CLASSIFICATION: {severity} | CVSS: {cvss_score}
CWE: {cwe_id}
AFFECTED URL: {affected_url}
AFFECTED FILE/COMPONENT: {affected_file_or_component}
DESCRIPTION:
{description}
DETAILED ANALYSIS:
{detail}
PROOF-OF-CONCEPT:
{evidence}
PROPOSED PATCH:
{remediation}
PROPOSED CODE FIX:
{remediation_code}
DISCLOSURE RECOMMENDATION:
This vulnerability was discovered during authorized assessment ({engagement_id}). Coordinate responsible disclosure."""

STEALTH_SECTION = "Stealth measures were standard browser-like headers and request timing."
DISCLAIMER = "DISCLAIMER: This report is provided in strict confidence to {authorized_by} as part of engagement {engagement_id}. It contains detailed technical information about security vulnerabilities discovered in {target_url}. All testing was performed with explicit written authorization. No data was modified, created, or deleted during the assessment."
NO_FINDINGS_MESSAGE = "No additional findings in this category."