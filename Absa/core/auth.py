"""
ABSA Authorization Gate
The framework REFUSES to run without a valid engagement token signed
by the target bank. Uses HMAC-SHA256 for demonstration; production
should use PGP/GPG or HSM-backed keys.
"""

import base64
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger("auth")

_HMAC_KEY = os.environ.get(
    "ABSA_AUTH_KEY",
    "absa-demo-authorization-key-replace-in-production-do-not-use-default"
)


class AuthorizationError(Exception):
    pass


def _decode_token(token: str) -> dict:
    try:
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded)
        return json.loads(raw)
    except Exception as e:
        raise AuthorizationError(f"Malformed token: {e}")


def _verify_signature(payload: dict, signature: str) -> bool:
    signed_fields = {k: v for k, v in sorted(payload.items()) if k != "signature"}
    message = json.dumps(signed_fields, sort_keys=True, separators=(",", ":"))
    expected = hmac.new(_HMAC_KEY.encode(), message.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _validate_scope(target_domain: str, allowed_scope: list) -> bool:
    for entry in allowed_scope:
        if entry == "*":
            return True
        entry_clean = entry.lstrip("*. ")
        if target_domain.endswith(entry_clean) or target_domain == entry_clean:
            return True
    return False


def _validate_operations(operations: list) -> bool:
    valid = {"recon", "scan", "fuzz", "report", "zeroday", "all"}
    return all(op in valid for op in operations)


def _validate_dates(issued_at: str, expires_at: str = None) -> bool:
    try:
        issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return False
    now = datetime.now(timezone.utc)
    if issued > now:
        return False
    if expires_at:
        try:
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if now > exp:
                return False
        except ValueError:
            return False
    return True


def validate_authorization(token: str, target_url: str) -> dict:
    logger.info("Validating engagement authorization token...")
    payload = _decode_token(token)

    required = ["engagement_id", "target_domain", "scope", "operations",
                "issued_at", "authorized_by", "signature"]
    for f in required:
        if f not in payload:
            raise AuthorizationError(f"Missing required field: '{f}'")

    if not _verify_signature(payload, payload["signature"]):
        raise AuthorizationError("Signature verification FAILED — token may be tampered.")
    logger.info("  [OK] Signature verified")

    target_domain = urlparse(target_url).hostname or ""
    if not target_domain:
        raise AuthorizationError("Cannot extract domain from target URL")

    if not _validate_scope(target_domain, payload["scope"]):
        raise AuthorizationError(
            f"Domain '{target_domain}' not in authorized scope: {payload['scope']}"
        )
    logger.info("  [OK] Domain '%s' within scope", target_domain)

    if not _validate_operations(payload["operations"]):
        raise AuthorizationError(f"Invalid operations: {payload['operations']}")
    logger.info("  [OK] Operations: %s", payload["operations"])

    if not _validate_dates(payload["issued_at"], payload.get("expires_at")):
        raise AuthorizationError("Token expired or has invalid dates.")
    logger.info("  [OK] Dates valid (issued: %s)", payload["issued_at"])

    logger.info("Authorization GRANTED — Engagement %s by %s",
                payload["engagement_id"], payload["authorized_by"])
    return {k: v for k, v in payload.items() if k != "signature"}


def require_authorization(token: str, target_url: str) -> dict:
    try:
        return validate_authorization(token, target_url)
    except AuthorizationError as e:
        logger.critical("AUTHORIZATION DENIED: %s", e)
        logger.critical("ABSA will NOT proceed. Obtain a valid token from the bank's CISO office.")
        sys.exit(1)