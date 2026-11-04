"""
ABSA Orchestrator Engine
Coordinates all assessment phases across the framework using asyncio.
Builds a single shared stealth-enabled HTTP client and passes it to every module,
ensuring consistent proxy routing, identity masking, fingerprint mimicry, and timing
jitter across the entire scan.

Usage:
    orch = Orchestrator(
        target_url="https://bank.example.com",
        auth_token="eyJ...",
        stealth_enabled=True,
        stealth_profile="bot",
        proxy="socks5://127.0.0.1:9050",
    )
    await orch.run()
"""

import asyncio
import time
from datetime import datetime, timezone
from typing import Optional

from core.models import ScanContext, PhaseResult, PhaseStatus, Finding, Severity
from core.auth import require_authorization
from recon.dns_deep import DeepDNSEnumerator
from recon.fingerprint import TechnologyFingerprinter
from recon.infrastructure import InfrastructureScanner
from recon.spider import EndpointSpider
from recon.threat_intel import ThreatIntelScanner
from scanner.passive import PassiveScanner
from scanner.active import ActiveScanner
from scanner.tls import TLSScanner
from scanner.headers import HeaderScanner
from zeroday.fuzzer import IntelligentFuzzer
from zeroday.payload_crafter import PayloadCrafter
from zeroday.logic_fuzzer import BusinessLogicFuzzer
from zeroday.exploit import ExploitOrchestrator
from correlation.cve_lookup import CVELookup
from correlation.exploit_db import ExploitDBLookup
from correlation.fix_suggester import FixSuggester
from reporting.report_builder import ReportBuilder
from reporting.pdf_generator import PDFGenerator
from utils.logger import get_logger
import config

logger = logger


class Orchestrator:
    """
    Main assessment driver.

    Builds one shared stealth-enabled HTTP client and passes it to every module,
    guaranteeing consistent proxy routing, identity masking, fingerprint mimicry, and timing
    jitter across the entire scan.

    Usage:
        orch = Orchestrator(
            target_url="https://bank.example.com",
            auth_token="eyJ...",
            stealth_enabled=True,
            stealth_profile="bot",
            proxy="socks5://127.0.0.1:9050",
        )
        await orch.run()
    """

    PHASE_ORDER = [
        "recon_subdomain",
        "recon_fingerprint",
        "recon_spider",
        "recon_dns_deep",
        "recon_infra",
        "recon_threat",
        "scan_passive",
        "scan_active",
        "scan_tls",
        "scan_headers",
        "zeroday_fuzz",
        "zeroday_logic",
        "zeroday_exploit",
        "correlation",
        "report",
    ]

    PHASE_NAMES = {
        "recon_subdomain":   "Phase 1A — Subdomain Enumeration",
        "recon_fingerprint": "Phase 1B — Technology Fingerprinting",
        "recon_spider":      "Phase 1C — Endpoint Discovery (Spidering)",
        "recon_dns_deep":   "Phase 1D — Deep DNS Enumeration",
        "recon_infra":      "Phase 1E — Infrastructure Discovery",
        "recon_threat":     "Phase 1F — Threat Intelligence",
        "scan_passive":      "Phase 2A — Passive CVE Lookup",
        "scan_active":       "Phase 2B — Active OWASP Top 10 Scanning",
        "scan_tls":          "Phase 2C — TLS Configuration Analysis",
        "scan_headers":      "Phase 2D — Security Header Audit",
        "zeroday_fuzz":      "Phase 3A — Intelligent Fuzzing",
        "zeroday_logic":     "Phase 3B — Business Logic State Analysis",
        "zeroday_exploit":   "Phase 3C — Safe Exploit Orchestration",
        "correlation":       "Phase 4  — CVE Correlation & Fix Suggestion",
        "report":            "Phase 5  — PDF Report Generation",
    }

    PHASE_HANDLERS = {
        "recon_subdomain":   "_run_recon_subdomain",
        "recon_fingerprint": "_run_recon_fingerprint",
        "recon_spider":      "_run_recon_spider",
        "recon_dns_deep":   "_run_recon_dns_deep",
        "recon_infra":      "_run_recon_infra",
        "recon_threat":     "_run_recon_threat",
        "scan_passive":      "_run_scan_passive",
        "scan_active":       "_run_scan_active",
        "scan_tls":          "_run_scan_tls",
        "scan_headers":      "_run_scan_headers",
        "zeroday_fuzz":      "_run_zeroday_fuzz",
        "zeroday_logic":     "_run_zeroday_logic",
        "zeroday_exploit":   "_run_zeroday_exploit",
        "correlation":       "_run_correlation",
        "report":            "_run_report",
    }

    def __init__(
        self,
        target_url: str,
        auth_token: str,
        concurrency: int = None,
        delay: float = None,
        skip_zeroday: bool = False,
        skip_tls: bool = False,
        stealth_enabled: bool = False,
        stealth_profile: str = "bot",
        proxy: str = None,
        proxy_file: str = None,
        jitter: float = 0.5,
        max_requests_per_proxy: int = 100,
    ):
        self.target_url = target_url
        self.auth_token = auth_token
        self.concurrency = concurrency or config.DEFAULT_CONCURRENCY
        self.delay = delay or config.DEFAULT_DELAY
        self.skip_zeroday = skip_zeroday
        self.skip_tls = skip_tls

        # Stealth parameters
        self.stealth_enabled = stealth_enabled
        self.stealth_profile = stealth_profile
        self.proxy = proxy
        self.proxy_file = proxy_file
        self.jitter = jitter
        self.max_requests_per_proxy = max_requests_per_proxy

        self.context: Optional[ScanContext] = None
        self.phase_results: dict = {}
        self._shared_client: Optional[ThrottledClient] = None
        self._proxy_mgr = None
        self._ua_rotator = None
        self._fp_mimic = None
        self._timing_ctrl = None

    # ─── Stealth Initialization ─────────────────────────────────────────────

    def _init_stealth_components(self):
        """
        Initialize all stealth modules. Called once before any phase runs.
        All components are created here and injected into the shared client.
        """
        if not self.stealth_enabled:
            logger.info("Stealth: DISABLED — using direct connections")
            return

        logger.info("Stealth: initializing operational security modules...")
        logger.info("  Profile: %s", self.stealth_profile)

        from stealth.proxy_manager import ProxyManager
        self._proxy_mgr = ProxyManager(
            proxy_url=self.proxy,
            proxy_file=self.proxy_file,
            max_per_proxy=self.max_requests_per_proxy,
        )
        if self._proxy_mgr.pool_size > 0:
            logger.info("  Proxy pool: %d proxy(ies) loaded", self._proxy_mgr.pool_size)
        else:
            logger.info("  Proxy pool: none — relying on identity masking only")

        from stealth.user_agent_rotator import UserAgentRotator
        self._ua_rotator = UserAgentRotator(profile=self.stealth_profile)
        logger.info("  UA profiles: %d (%s mode)",
                     self._ua_rotator.profile_count,
                     self._ua_rotator.current_type)

        from stealth.fingerprint_mimic import FingerprintMimic
        self._fp_mimic = FingerprintMimic()
        logger.info("  TLS fingerprint: browser-like cipher ordering active")

        from stealth.timing import TimingController
        self._timing_ctrl = TimingController(
            base_delay=self.delay,
            jitter=self.jitter,
        )
        logger.info("  Timing jitter: %.1f (burst-then-pause pattern)", self.jitter)

    def _build_shared_client(self) -> ThrottledClient:
        """
        Build the single shared HTTP client with all stealth components.
        Every module receives THIS client — no duplicate connections, no
        inconsistent identities.
        """
        client = ThrottledClient(
            concurrency=self.concurrency,
            delay=self.delay,
            timeout=config.DEFAULT_TIMEOUT,
            verify_ssl=True,
            proxy_manager=self._proxy_mgr,
            ua_rotator=self._ua_rotator,
            fingerprint_mimic=self._fp_mimic,
            timing_controller=self._timing_ctrl,
            rotate_identity_every=50,
        )
        return client

    # ─── Context Building ──────────────────────────────────────────────────

    def _build_context(self, engagement: dict) -> ScanContext:
        from urllib.parse import urlparse
        p = urlparse(self.target_url)
        return ScanContext(
            target_url=self.target_url,
            target_domain=p.hostname or "",
            target_scheme=p.scheme or "https",
            target_port=p.port or (443 if p.scheme == "https" else 80),
            session_id=f"ABSA-{engagement['engagement_id']}-{int(time.time())}",
            authorization_token=self.auth_token,
            concurrency=self.concurrency,
            delay=self.delay,
            timeout=config.DEFAULT_TIMEOUT,
            output_dir=config.REPORT_DIR,
            evidence_dir=config.EVIDENCE_DIR,
            is_authorized=True,
            start_time=datetime.now(timezone.utc).isoformat(),
        )

    # ─── Phase Tracking Helpers ───────────────────────────────────────

    def _init_phase(self, key: str) -> PhaseResult:
        return PhaseResult(phase_name=self.PHASE_NAMES.get(key, key))

    def _set_status(self, key: str, status: PhaseStatus):
        if key in self.phase_results:
            self.phase_results[key].status = status

    def _add_findings(self, key: str, findings: list):
        pr = self.phase_results.get(key)
        if pr:
            pr.findings.extend(findings)
        self.context.findings.extend(findings)

    def _phase_header(self, key: str):
        logger.info("=" * 70)
        logger.info("  %s", self.PHASE_NAMES.get(key, key))
        logger.info("=" * 70)

    def _log_stealth_status(self):
        """Log current stealth status for audit trail."""
        if not self.stealth_enabled or not self._shared_client:
            return
        info = self._shared_client.get_stealth_info()
        logger.info("  Stealth active — UA: %s...", info.get("ua", "N/A")[:55])
        logger.info("  Proxy: %s", info.get("proxy", "direct"))
        pool = info.get("proxy_pool", "")
        if pool:
            logger.info("  Pool: %s active proxies", pool)

    # ─── Phase Implementations ────────────────────────────────────────

    async def _run_recon_subdomain(self):
        k = "recon_subdomain"
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            known_subs = self.phase_results.get("recon_subdomain", PhaseResult("")).subdomains
            enumerator = DeepDNSEnumerator(
                self.context, client=self._shared_client,
            )
            dns_results = await enumerator.enumerate(known_subs)
            self._add_findings(k, dns_results["findings"])
            self.phase_results[k].stats["dns_deep_findings"] = len(dns_results["findings"])
            self.phase_results[k].stats["cname_takeovers"] = len(dns_results["cname_takeovers"])
            self.phase_results[k].stats["zone_transfers"] = len(dns_results["zone_transfers"])
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info("Deep DNS: %d findings", len(dns_results["findings"]))
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Deep DNS failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_recon_fingerprint(self):
        k = "recon_fingerprint"
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            from recon.fingerprint import TechnologyFingerprinter
            fp = TechnologyFingerprinter(
                self.context, client=self._shared_client,
            )
            techs = await fp.fingerprint()
            self.phase_results[k].technologies = techs
            self.phase_results[k].stats["technologies_found"] = len(techs)
            self._set_status(k, PhaseStatus.COMPLETE)
            for t in techs:
                logger.info("  [%s] %s %s (%.0f%%)",
                             t.category, t.name, t.version or "", t.confidence * 100)
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Fingerprinting failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_recon_spider(self):
        k = "recon_spider"
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            from recon.spider import EndpointSpider
            spider = EndpointSpider(
                self.context, client=self._shared_client,
            )
            eps = await spider.crawl()
            self.phase_results[k].endpoints = eps
            self.phase_results[k].stats["endpoints_found"] = len(eps)
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info("Spider done: %d endpoint(s)", len(eps))
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Spidering failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_recon_dns_deep(self):
        k = "recon_dns_deep"
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            known_subs = self.phase_results.get("recon_subdomain", PhaseResult("")).subdomains
            enumerator = DeepDNSEnumerator(
                self.context, client=self._shared_client,
            )
            dns_results = await enumerator.enumerate(known_subs)
            self._add_findings(k, dns_results["findings"])
            self.phase_results[k].stats["dns_deep_findings"] = len(dns_results["findings"])
            self.phase_results[k].stats["cname_takeovers"] = len(dns_results["cname_takeovers"])
            self.phase_results[k].stats["zone_transfers"] = len(dns_results["zone_transfers"])
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info("Deep DNS: %d findings", len(dns_results["findings"]))
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Deep DNS failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_recon_infra(self):
        k = "recon_infra"
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            scanner = InfrastructureScanner(
                self.context, client=self._shared_client,
            )
            infra_results = await scanner.scan()
            self._add_findings(k, infra_results["findings"])
            self.phase_results[k].stats["open_ports"] = len(infra_results["open_ports"])
            self.phase_results[k].stats["admin_panels"] = len(infra_results["admin_panels"])
            self.phase_results[k].stats["cdn"] = infra_results["cdn"] or "None"
            self.phase_results[k].stats["real_ip"] = infra_results["real_ip"] or "Not found"
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info("Infrastructure: %d ports, %d admin panels, CDN: %s, IP: %s",
                         len(infra_results["open_ports"]),
                         len(infra_results["admin_panels"]),
                         infra_results["cdn"],
                         infra_results["real_ip"])
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Infrastructure scan failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_recon_threat(self):
        k = "recon_threat"
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            endpoints = self.phase_results.get("recon_spider", PhaseResult("")).endpoints
            intel = ThreatIntelScanner(
                self.context, client=self._shared_client,
            )
            intel_results = intel.scan(endpoints)
            self._add_findings(k, intel_results["findings"])
            self.phase_results[k].stats["emails"] = len(intel_results["emails"])
            self.phase_results[k].stats["usernames"] = len(intel_results["usernames"])
            self.phase_results[k].stats["breaches"] = sum(
                len(v.get("breaches", []))
                for v in intel_results["breach_data"].values()
            )
            self.phase_results[k].stats["secrets"] = len(intel_results["exposed_secrets"])
            self.phase_results[k].stats["repos"] = len(intel_results["repo_findings"])
            self.phase_results[k].stats["wayback"] = len(intel_results["wayback_urls"])
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info(
                "Threat intel: %d emails, %d usernames, %d breach hits, %d secrets, %d repos, %d wayback URLs",
                len(intel_results["emails"]),
                len(intel_results["usernames"]),
                self.phase_results[k].stats["breaches"],
                len(intel_results["secrets"]),
                len(intel_results["repo_findings"]),
                len(intel_results["wayback_urls"]),
            )
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Threat intel failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_scan_passive(self):
        k = "scan_passive"
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            techs = self.phase_results.get("recon_fingerprint", PhaseResult("")).technologies
            scanner = PassiveScanner(self.context)
            findings = await scanner.scan(techs)
            self._add_findings(k, findings)
            self.phase_results[k].stats["cves_matched"] = len(findings)
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info("Passive scan matched %d known CVE(s)", len(findings))
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Passive scan failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_scan_active(self):
        k = "scan_active"
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            eps = self.phase_results.get("recon_spider", PhaseResult("")).endpoints
            scanner = ActiveScanner(
                self.context, client=self._shared_client,
            )
            findings = await scanner.scan(eps)
            self._add_findings(k, findings)
            self.phase_results[k].stats["active_findings"] = len(findings)
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info("Active scan: %d finding(s)", len(findings))
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Active scan failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_scan_tls(self):
        k = "scan_tls"
        if self.skip_tls:
            self._set_status(k, PhaseStatus.SKIPPED)
            self.phase_results[k].stats["reason"] = "Skipped by user"
            logger.info("[SKIPPED] TLS scanning disabled by user")
            return
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            from scanner.tls import TLSScanner
            tls_r, findings = await TLSScanner(self.context).scan()
            self.phase_results[k].tls_result = tls_r
            self._add_findings(k, findings)
            self.phase_results[k].stats["tls_issues"] = len(findings)
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info("TLS: %d issue(s)", len(findings))
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("TLS scan failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_scan_headers(self):
        k = "scan_headers"
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            from scanner.headers import HeaderScanner
            scanner = HeaderScanner(
                self.context, client=self._shared_client,
            )
            hr, findings = scanner.scan()
            self.phase_results[k].header_results = hr
            self._add_findings(k, findings)
            self.phase_results[k].stats["header_issues"] = len(findings)
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info("Headers: %d issue(s)", len(findings))
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Header scan failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_zeroday_fuzz(self):
        k = "zeroday_fuzz"
        if self.skip_zeroday:
            self._set_status(k, PhaseStatus.SKIPPED)
            logger.info("[SKIPPED] Zero-day fuzzing disabled by user")
            return
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            from zeroday.fuzzer import IntelligentFuzzer
            from zeroday.payload_crafter import PayloadCrafter
            eps = self.phase_results.get("recon_spider", PhaseResult("")).endpoints
            crafter = PayloadCrafter(self.context)
            fuzzer = IntelligentFuzzer(
                self.context, crafter, client=self._shared_client,
            )
            findings = await fuzzer.fuzz(eps)
            self._add_findings(k, findings)
            self.phase_results[k].stats["anomalies"] = len(findings)
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info("Fuzzer: %d anomaly/anomalies", len(findings))
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Fuzzer failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_zeroday_logic(self):
        k = "zeroday_logic"
        if self.skip_zeroday:
            self._set_status(k, PhaseStatus.SKIPPED)
            return
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            from zeroday.logic_fuzzer import BusinessLogicFuzzer
            eps = self.phase_results.get("recon_spider", PhaseResult("")).endpoints
            logic_fuzzer = BusinessLogicFuzzer(
                self.context, client=self._shared_client,
            )
            findings = await logic_fuzzer.analyze(eps)
            self._add_findings(k, findings)
            self.phase_results[k].stats["logic_issues"] = len(findings)
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info("Logic fuzzer: %d issue(s)", len(findings))
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Logic fuzzer failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_zeroday_exploit(self):
        k = "zeroday_exploit"
        if self.skip_zeroday:
            self._set_status(k, PhaseStatus.SKIPPED)
            return
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            from zeroday.exploit import ExploitOrchestrator
            candidates = [
                f for f in self.context.findings if f.is_zero_day or
                f.finding_type.value in ("zero_day", "business_logic")
            ]
            exploiter = ExploitOrchestrator(
                self.context, client=self._shared_client,
            )
            verified = await exploiter.verify(candidates)
            self._add_findings(k, verified)
            self.phase_results[k].stats["verified_zerodays"] = len(verified)
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info("Exploit: %d verified zero-day finding(s)", len(verified))
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Exploit orchestration failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_correlation(self):
        k = "correlation"
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            from correlation.cve_lookup import CVELookup
            from correlation.exploit_db import ExploitDBLookup
            from correlation.fix_suggester import FixSuggester
            cve = CVELookup(self.context)
            edb = ExploitDBLookup(self.context)
            fixer = FixSuggester(self.context)
            enriched = 0
            for f in self.context.findings:
                if f.cwe_id and not f.cve_details:
                    cves = await cve.lookup_by_cwe(f.cwe_id)
                    if cves:
                        f.cve_details = cves
                        enriched += 1
                for cve in f.cve_details:
                    if not cve.exploit_db_id:
                        eid = edb.search(cve.cve_id)
                        if eid:
                            cve.exploit_db_id = eid
                            cve.exploit_available = True
                if not f.remediation:
                    fix = fixer.suggest(f)
                    f.remediation = fix["description"]
                    f.remediation_code = fix.get("code", "")
                    if not f.compliance_mappings:
                        f.compliance_mappings = fix.get("compliance", [])
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Correlation failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    async def _run_report(self):
        k = "report"
        self._set_status(k, PhaseStatus.RUNNING)
        self._phase_header(k)
        t0 = time.time()
        try:
            from reporting.report_builder import ReportBuilder
            from reporting.pdf_generator import PDFGenerator
            data = ReportBuilder(self.context, self.phase_results).build()
            generator = PDFGenerator(self.context)
            path = generator.generate(data)
            self.phase_results[k].stats["report_path"] = path
            self._set_status(k, PhaseStatus.COMPLETE)
            logger.info("PDF report: %s", path)
        except Exception as e:
            self.phase_results[k].error_message = str(e)
            self._set_status(k, PhaseStatus.ERROR)
            logger.error("Report failed: %s", e)
        self.phase_results[k].duration_seconds = time.time() - t0

    # ─── Main Entry Point ───────────────────────────────────────────────────────

    async def run(self) -> ScanContext:
        """
        Execute the full assessment pipeline.

        Execution order:
          1. Authorization gate (blocks if no valid token)
          2. Build scan context
          3. Initialize stealth modules
          4. Build shared client
          5. Initialize phase tracking
          6. Execute phases (with concurrency where safe)
          7. Close shared client
          8. Print final summary

        Execution order:
          Phase 1 Recon:   1A+1B+1D+1E+1F (5 parallel)
          Phase 1C Spider:  sequential (depends on 1B fingerprint data)
          Phase 2 Scan:     2A sequential → 2B+2C+2D (3 parallel)
          Phase 3 Zero-Day: 3A+3B (2 parallel) → 3C (sequential)
          Phase 4 Correlation: sequential (needs all findings)
          Phase 5 Report: sequential (needs enriched findings)
        """
        logger.info("ABSA v%s starting...", config.APP_VERSION)
        logger.info("Target: %s", self.target_url)

        # ── Step 1: Authorization ───────────────────────────────────────────────
        logger.info("─" * 70)
        logger.info("AUTHORIZATION GATE")
        logger.info("─" * 70)
        engagement = require_authorization(self.auth_token, self.target_url)
        self.context = self._build_context(engagement)
        logger.info("Session: %s", self.context.session_id)

        # ── Step 2: Initialize stealth ────────────────────────────────────────
        if self.stealth_enabled:
            logger.info("─" * 70)
            logger.info("STEALTH INITIALIZATION")
            logger.info("─" * 70)
            self._init_stealth_components()
            self._log_stealth_status()

        # ── Step 3: Build shared client ──────────────────────────────────
        self._shared_client = self._build_shared_client()
        logger.info("Shared HTTP client initialized (concurrency=%d)", self.concurrency)

        # ── Step 4: Initialize phase tracking ────────────────────────────
        for pk in self.PHASE_ORDER:
            self.phase_results[pk] = self._init_phase(pk)

        logger.info("")
        logger.info("Starting assessment pipeline...")
        logger.info("")

        # ─�─ Step 5: Execute phases ────────────────────────────────────────
        # Phase 1: Reconnaissance (5 modules, parallel)
        await asyncio.gather(
            self._run_recon_subdomain(),
            self._run_recon_fingerprint(),
            self._run_recon_dns_deep(),
            self._run_recon_infra(),
            self._run_recon_threat(),
        )
        await self._run_recon_spider()

        # Phase 2: Scanning (partial parallelism)
        await self._run_scan_passive()
        await asyncio.gather(
            self._run_scan_active(),
            self._run_scan_tls(),
            self._run_scan_headers(),
        )

        # Phase 3: Zero-Day Simulation (partial parallelism)
        await asyncio.gather(
            self._run_zeroday_fuzz(),
            self._run_zeroday_logic(),
        )
        await self._run_zeroday_exploit()

        # Phase 4: Correlation (sequential — needs all findings)
        await self._run_correlation()

        # Phase 5: Report Generation (sequential — needs enriched findings)
        await self._run_report()

        # ── Step 6: Cleanup ────────────────────────────────────────────
        if self._shared_client:
            req_count = self._shared_client.request_count
            await self._shared_client.close()
            logger.info("Shared client closed (%d total requests)", req_count)

        # ── Step 7: Final Summary ────────────────────────────────────────
        self.context.end_time = datetime.now(timezone.utc).isoformat()
        total = len(self.context.findings)
        crit = sum(1 for f in self.context.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.context.findings if f.severity == Severity.HIGH)
        med = sum(1 for f in self.context.findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in self.context.findings if f.severity in (Severity.LOW, Severity.INFO))
        zds = sum(1 for f in self.context.findings if f.is_zero_day)

        logger.info("")
        logger.info("=" * 70)
        logger.info("  ASSESSMENT COMPLETE")
        logger.info("=" * 70)
        logger.info("  Total Findings:    %d", total)
        logger.info("  Critical:        %d", crit)
        logger.info("  High:            %d", high)
        logger.info("  Medium:          %d", med)
        logger.info("  Low / Info:      %d", low)
        logger.info("  Zero-Day:        %d", zds)
        logger.info("  Session:         %s", self.context.session_id)

        rp = self.phase_results.get("report", PhaseResult("")).stats.get("report_path", "")
        if rp:
            logger.info("  Report:          %s", rp)

        logger.info("=" * 70)
        logger.info("")

        return self.context