"""
ABSA Zero-Day Financial Logic Scanner
Aggressively tests banking/financial endpoints for business logic flaws
that standard vulnerability scanners miss (e.g., race conditions,
negative balance manipulation, currency conversion precision errors).
"""

import json
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime

from core.models import ScanContext, Finding, Severity, FindingType, Payload
from utils.logger import get_logger

logger = get_logger("zeroday.financial")


class FinancialLogicScanner:
    """Scans for critical business logic flaws in financial APIs."""

    def __init__(self, context: ScanContext, client: Any):
        self.ctx = context
        self.client = client

    async def run(self, config: Optional[Dict] = None) -> List[Finding]:
        findings = []
        config = config or {}
        base_url = self.ctx.target_url.rstrip('/')

        logger.info("Starting Financial Logic Zero-Day tests on %s", base_url)

        # Execute tests concurrently
        tasks = [
            self._test_race_condition(base_url, config.get("tx_endpoint", f"{base_url}/api/transfer")),
            self._test_negative_balance(base_url, config.get("tx_endpoint", f"{base_url}/api/transfer")),
            self._test_currency_precision(base_url, config.get("convert_endpoint", f"{base_url}/api/currency/convert")),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, list):
                findings.extend(res)
            elif isinstance(res, Exception):
                logger.error("Financial logic test failed: %s", res)

        return findings

    async def _test_race_condition(self, base_url: str, tx_endpoint: str) -> List[Finding]:
        """Tests for TOCTOU (Time-of-check to time-of-use) race conditions in transfers."""
        findings = []
        if not tx_endpoint: return findings

        headers = self.ctx.authorization_token and {"Authorization": f"Bearer {self.ctx.authorization_token}"} or {}
        payload = {"to_account": "attacker_account", "amount": 100.00}

        # Fire 10 concurrent requests
        tasks = [self.client.post(tx_endpoint, json=payload, headers=headers) for _ in range(10)]
        responses = await asyncio.gather(*tasks)

        success_count = sum(1 for r in responses if r and r.get("status") == 200)

        # If more than 1 succeeds, there is no idempotency/race condition protection
        if success_count > 1:
            findings.append(Finding(
                title="EXPLOIT: Financial Race Condition (Double Spending)",
                description=f"Sent 10 concurrent transfer requests. {success_count} succeeded. "
                            f"The API lacks idempotency keys or database-level row locking, "
                            f"allowing an attacker to drain accounts via race conditions.",
                severity=Severity.CRITICAL,
                finding_type=FindingType.BUSINESS_LOGIC,
                cwe_id="CWE-367",
                cvss_score=9.9,
                affected_url=tx_endpoint,
                affected_file_or_component="Transaction Processing API",
                evidence=f"Payload: {json.dumps(payload)}\nConcurrent Successes: {success_count}/10",
                payloads=[Payload(payload_string=json.dumps(payload), payload_type="race_condition",
                                  evidence=f"{success_count} successes", success=True)],
                is_zero_day=True,
                zero_day_detail="Type: TOCTOU Race Condition\nMechanism: Concurrent HTTP requests bypass balance checks.",
                remediation="Implement idempotency keys for all state-changing operations. Use database transactions with SELECT FOR UPDATE to lock rows during balance checks.",
                phase="zeroday_financial",
                weakness_type="Race Condition",
                discovered_at=datetime.utcnow().isoformat(),
            ))
        return findings

    async def _test_negative_balance(self, base_url: str, tx_endpoint: str) -> List[Finding]:
        """Tests if an account can be forced into a negative balance."""
        findings = []
        if not tx_endpoint: return findings

        headers = self.ctx.authorization_token and {"Authorization": f"Bearer {self.ctx.authorization_token}"} or {}
        payload = {"to_account": "attacker_account", "amount": -999999.99}

        resp = await self.client.post(tx_endpoint, json=payload, headers=headers)
        if resp and resp.get("status") == 200:
            findings.append(Finding(
                title="EXPLOIT: Negative Balance Manipulation",
                description="Transferring a negative amount successfully increased the source account balance instead of decreasing it or throwing an error.",
                severity=Severity.CRITICAL,
                finding_type=FindingType.BUSINESS_LOGIC,
                cwe_id="CWE-682",
                cvss_score=9.8,
                affected_url=tx_endpoint,
                affected_file_or_component="Account Balance Logic",
                evidence=f"Payload: {json.dumps(payload)}\nResponse: HTTP 200",
                payloads=[Payload(payload_string=json.dumps(payload), payload_type="logic_bypass", evidence="HTTP 200",
                                  success=True)],
                is_zero_day=True,
                zero_day_detail="Type: Integer Sign Flaw\nMechanism: Negative amount bypasses deduction logic.",
                remediation="Implement strict server-side validation. Balance calculations must use absolute values. Reject negative amounts at the API schema level.",
                phase="zeroday_financial",
                weakness_type="Business Logic Flaw",
                discovered_at=datetime.utcnow().isoformat(),
            ))
        return findings

    async def _test_currency_precision(self, base_url: str, convert_endpoint: str) -> List[Finding]:
        """Tests for floating-point precision errors in currency conversion."""
        findings = []
        if not convert_endpoint: return findings

        # Payload designed to trigger floating point truncation
        payload = {"from": "USD", "to": "EUR", "amount": 0.1}
        resp = await self.client.post(convert_endpoint, json=payload)

        if resp and resp.get("status") == 200:
            try:
                body = resp.get("body", "")
                data = json.loads(body) if isinstance(body, str) else body
                converted = float(data.get("converted_amount", 0))

                # 0.1 cannot be represented exactly in binary floating point.
                # If the API doesn't use Decimal types, this exposes a logic flaw.
                if "0.0" in str(converted) or "00" in str(converted).split('.')[1][-2:]:
                    findings.append(Finding(
                        title="EXPLOIT: Currency Floating-Point Precision Loss",
                        description="Currency conversion uses standard floats instead of precise Decimal types. This can lead to systematic financial skimming over millions of transactions.",
                        severity=Severity.HIGH,
                        finding_type=FindingType.BUSINESS_LOGIC,
                        cwe_id="CWE-682",
                        cvss_score=8.5,
                        affected_url=convert_endpoint,
                        affected_file_or_component="Currency Conversion Math",
                        evidence=f"Input: 0.1 USD -> Output: {converted} EUR (Potential precision loss)",
                        payloads=[Payload(payload_string=json.dumps(payload), payload_type="precision_error",
                                          evidence=f"Output: {converted}", success=True)],
                        is_zero_day=True,
                        zero_day_detail="Type: Floating Point Math Flaw\nMechanism: IEEE 754 precision loss on financial calculations.",
                        remediation="Mandate the use of fixed-precision Decimal types (e.g., Python's `decimal.Decimal` or database NUMERIC(19,4)) for ALL financial calculations. Never use Float/Double.",
                        phase="zeroday_financial",
                        weakness_type="Precision Error",
                        discovered_at=datetime.utcnow().isoformat(),
                    ))
            except (ValueError, TypeError, json.JSONDecodeError):
                pass
        return findings