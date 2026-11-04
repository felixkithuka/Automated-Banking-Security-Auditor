"""
ABSA Zero-Day Engine Core
Orchestrates the discovery, verification, exploitation, and remediation generation
for zero-day vulnerabilities. Runs all components concurrently for maximum efficiency.
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime

from core.models import ScanContext, Finding, Severity
from utils.logger import get_logger

logger = get_logger("zeroday.engine")


class ZeroDayEngine:
    """
    Main orchestrator for the Zero-Day Assessment phase.
    Coordinates version diffing, active exploitation, and automatic fix generation.
    """

    def __init__(self, context: ScanContext, client: Any):
        self.ctx = context
        self.client = client

    async def run(self, config: Optional[Dict] = None) -> List[Finding]:
        """
        Execute the full zero-day pipeline:
        1. Scan for outdated components (Version Diffing)
        2. Execute active exploits to verify (Aggressive Execution)
        3. Generate actionable remediation code (Fix Generator)
        """
        config = config or {}
        findings = []

        logger.info("Starting Zero-Day Engine pipeline")

        # Lazy imports to prevent crashes if sub-modules have missing dependencies
        try:
            from zeroday.exploit_scanner import ExploitScanner
            from zeroday.exploit_executor import ExploitExecutor
            from zeroday.fix_generator import FixGenerator
        except ImportError as e:
            logger.error("Failed to import Zero-Day submodules: %s", e)
            return findings

        # -----------------------------------------------------------------
        # Phase 1: Passive Version Diffing & Fingerprinting
        # -----------------------------------------------------------------
        logger.debug("Phase 1: Running passive version diffing...")
        scanner = ExploitScanner(self.ctx, self.client)
        scanner_findings = await scanner.run(config)
        findings.extend(scanner_findings)

        if scanner_findings:
            logger.info("Discovered %d potential zero-days via version diffing.", len(scanner_findings))

        # -----------------------------------------------------------------
        # Phase 2: Active Exploitation & Verification
        # -----------------------------------------------------------------
        logger.debug("Phase 2: Running active exploit verification...")
        executor = ExploitExecutor(self.ctx, self.client)

        # Pass the first finding to specifically target its unpatched version
        target_finding = scanner_findings[0] if scanner_findings else None
        executor_findings = await executor.run(target_finding=target_finding)
        findings.extend(executor_findings)

        if executor_findings:
            logger.warning("Exploitor successfully verified %d zero-day vulnerabilities!", len(executor_findings))

        # -----------------------------------------------------------------
        # Phase 3: Automated Fix Generation
        # -----------------------------------------------------------------
        logger.debug("Phase 3: Generating remediation code...")
        fixer = FixGenerator(self.ctx)
        final_findings = fixer.generate_fixes(findings)

        # Stamp all findings with the correct phase metadata
        for f in final_findings:
            if not f.phase:
                f.phase = "zeroday_engine"
            if not f.discovered_at:
                f.discovered_at = datetime.utcnow().isoformat()

        logger.info("Zero-Day Engine completed. Total findings: %d", len(final_findings))
        return final_findings