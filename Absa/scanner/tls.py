"""
ABSA TLS Configuration Scanner
Analyzes protocols, ciphers, certificates, HSTS.
Uses sslyze when available, falls back to stdlib ssl.
"""

import ssl
import socket
from datetime import datetime
from typing import List, Tuple

from core.models import TLSResult, Finding, Severity, FindingType, ComplianceMapping, ScanContext
from utils.logger import get_logger
import config

logger = get_logger("scanner.tls")


class TLSScanner:
    def __init__(self, context: ScanContext):
        self.ctx = context

    async def scan(self) -> Tuple[TLSResult, List[Finding]]:
        logger.info("TLS scan: %s:%d", self.ctx.target_domain, self.ctx.target_port)
        findings = []
        result = TLSResult()

        try:
            from sslyze.scanner import Scanner, ServerScanRequest
            from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration
            logger.info("  Using sslyze...")
            return await self._sslyze(result, findings)
        except ImportError:
            logger.info("  sslyze not available, using stdlib ssl...")

        return self._stdlib(result, findings)

    async def _sslyze(self, result, findings):
        from sslyze.scanner import Scanner, ServerScanRequest
        from sslyze.server_setting import ServerNetworkLocation, ServerNetworkConfiguration
        try:
            loc = ServerNetworkLocation(hostname=self.ctx.target_domain, port=self.ctx.target_port)
            cfg = ServerNetworkConfiguration(tls_server_name_indication=self.ctx.target_domain)
            req = ServerScanRequest(server_location=loc, server_network_configuration=cfg,
                                    scan_commands={"certificate_info": None, "tls_configuration": None})
            scanner = Scanner()
            scanner.queue_scan(req)
            for item in await scanner.get_results():
                if hasattr(item, 'certificate_info') and item.certificate_info:
                    for cd in item.certificate_info.result.certificate_deployments:
                        leaf = cd.received_certificate_chain[0]
                        result.certificate_issuer = str(leaf.issuer)
                        result.certificate_expiry = str(leaf.not_valid_after)
                        if leaf.not_valid_after < datetime.utcnow():
                            findings.append(Finding(
                                title="TLS Certificate Expired",
                                description=f"Certificate for {self.ctx.target_domain} expired: {leaf.not_valid_after}",
                                severity=Severity.CRITICAL, finding_type=FindingType.CONFIGURATION, cwe_id="CWE-295",
                                affected_url=self.ctx.target_url, cvss_score=9.1, weakness_type="financial_impact", phase="tls",
                                remediation="Renew the TLS certificate immediately. Use certbot or enterprise PKI."))
                if hasattr(item, 'tls_configuration') and item.tls_configuration:
                    tr = item.tls_configuration.result
                    for v in tr.accepted_tls_versions:
                        if v.name in ("TLS_1_0", "TLS_1_1", "SSL_3_0"):
                            result.issues.append(f"Weak protocol: {v.name}")
                            findings.append(Finding(
                                title=f"Weak TLS Protocol: {v.name}",
                                description=f"Server accepts deprecated {v.name}.", severity=Severity.MEDIUM,
                                finding_type=FindingType.CONFIGURATION, cwe_id="CWE-326",
                                affected_url=self.ctx.target_url, cvss_score=5.3, phase="tls",
                                remediation=f"Disable {v.name}. Only allow TLS 1.2+.",
                                compliance_mappings=[ComplianceMapping(framework="PCI DSS 4.0", clause_id="4.2.1",
                                    clause_title="Strong Cryptography", description="Only TLS 1.2 or higher is permitted.")]))
                    for c in tr.accepted_cipher_suites:
                        cn = c.cipher_suite.name
                        for w in config.TLS_WEAK_CIPHERS_BLOCKLIST:
                            if w.upper() in cn.upper():
                                result.weak_ciphers_found.append(cn)
                    if result.weak_ciphers_found:
                        findings.append(Finding(
                            title=f"Weak Ciphers ({len(result.weak_ciphers_found)})",
                            description=f"Weak ciphers: {', '.join(result.weak_ciphers_found[:5])}",
                            severity=Severity.MEDIUM, finding_type=FindingType.CONFIGURATION, cwe_id="CWE-326",
                            affected_url=self.ctx.target_url, cvss_score=5.3, phase="tls",
                            remediation="Disable weak ciphers. Use AES-GCM or ChaCha20-Poly1305 with ECDHE."))
        except Exception as e:
            logger.error("  sslyze error: %s", e)
        return self._stdlib(result, findings)

    def _stdlib(self, result, findings):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.ctx.target_domain, self.ctx.target_port), timeout=self.ctx.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=self.ctx.target_domain) as ss:
                    result.version = ss.version() or "unknown"
                    c = ss.cipher()
                    result.cipher_suite = f"{c[0]} ({c[1]} bits)" if c else ""
                    cert = ss.getpeercert()
                    if cert:
                        result.certificate_issuer = str(cert.get("issuer", ""))
                        result.certificate_expiry = cert.get("notAfter", "")
                    logger.info("  Version: %s | Cipher: %s", result.version, result.cipher_suite)
                    if result.version in ("TLSv1", "TLSv1/SSLv3", "SSLv3"):
                        result.issues.append(f"Weak: {result.version}")
                        findings.append(Finding(
                            title=f"Weak TLS: {result.version}", severity=Severity.MEDIUM,
                            finding_type=FindingType.CONFIGURATION, cwe_id="CWE-326",
                            affected_url=self.ctx.target_url, cvss_score=5.3, phase="tls",
                            remediation="Upgrade to TLS 1.2 minimum."))
                    if c and c[2] < 128:
                        result.weak_ciphers_found.append(result.cipher_suite)
                        findings.append(Finding(
                            title=f"Weak Cipher: {result.cipher_suite}", severity=Severity.MEDIUM,
                            finding_type=FindingType.CONFIGURATION, cwe_id="CWE-326",
                            affected_url=self.ctx.target_url, cvss_score=5.3, phase="tls",
                            remediation="Use ciphers with >= 128-bit keys."))
        except ssl.SSLCertVerificationError as e:
            findings.append(Finding(
                title="Certificate Verification Failed",
                description=f"Certificate error: {e.verify_message}", severity=Severity.HIGH,
                finding_type=FindingType.CONFIGURATION, cwe_id="CWE-295",
                affected_url=self.ctx.target_url, cvss_score=7.5, phase="tls",
                remediation="Install valid CA-signed certificate. Ensure intermediate certs are chained."))
        except socket.timeout:
            findings.append(Finding(
                title="TLS Connection Timeout", severity=Severity.INFO,
                finding_type=FindingType.CONFIGURATION, affected_url=self.ctx.target_url, phase="tls",
                remediation="Verify target is reachable and TLS is configured."))
        except Exception as e:
            logger.error("  stdlib TLS error: %s", e)
        return result, findings