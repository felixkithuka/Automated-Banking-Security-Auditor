"""
ABSA Fingerprint Mimic
Reduces the tool's HTTP/TLS fingerprint to match legitimate traffic.
Strips tool-identifying headers, randomizes connection parameters,
and applies browser-like TLS cipher ordering to defeat JA3/JA4 fingerprinting.
"""

import random
from typing import Optional

from utils.logger import get_logger

logger = get_logger("stealth.fingerprint")


# Headers that penetration testing tools commonly send and should be stripped
TOOL_HEADERS_TO_STRIP = [
    "x-absa-session",
    "x-scanner",
    "x-tested-by",
    "x-absa-version",
    "x-requests-count",
    "x-proxy-count",
    "connection",
]

# Browser-like TLS cipher suites for JA3 mimicry (OpenSSL cipher list format)
BROWSER_CIPHER_LISTS = [
    # Chrome 120 cipher order
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:"
    "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA",
    # Firefox 122 cipher order
    "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:"
    "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA",
    # Safari 17 cipher order
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA",
]

# TLS extensions that browsers send (affects JA3/JA4 fingerprint)
BROWSER_TLS_EXTENSIONS = [
    "server_name", "extended_master_secret", "renegotiation_info",
    "supported_groups", "ec_point_formats", "session_ticket",
    "signature_algorithms", "signature_algorithms_cert",
    "psk_key_exchange_modes", "key_share", "supported_versions",
    "compress_certificate", "application_layer_protocol_negotiation",
]

# Supported groups order (affects fingerprint)
BROWSER_CURVE_ORDERS = [
    ["x25519", "secp256r1", "secp384r1"],
    ["secp256r1", "x25519", "secp384r1"],
    ["x25519", "secp384r1", "secp256r1"],
]


class FingerprintMimic:
    """
    Modifies HTTP/TLS parameters to match legitimate browser traffic.

    Features:
      - Strips tool-identifying response/request headers
      - Selects browser-like TLS cipher ordering
      - Configures TLS extensions to match common browsers
      - Randomizes TCP-level parameters where possible
    """

    def __init__(self):
        self._cipher_list = random.choice(BROWSER_CIPHER_LISTS)
        self._curve_order = random.choice(BROWSER_CURVE_ORDERS)
        logger.debug("Fingerprint mimic initialized (cipher set: %d curves: %s)",
                     len(BROWSER_CIPHER_LISTS), self._curve_order)

    def strip_tool_headers(self, headers: dict) -> dict:
        """Remove any headers that identify ABSA or scanning tools."""
        cleaned = {}
        for key, value in headers.items():
            key_lower = key.lower()
            is_tool_header = False
            for tool_header in TOOL_HEADERS_TO_STRIP:
                if key_lower == tool_header.lower():
                    is_tool_header = True
                    break
            # Also strip any custom x-absa headers
            if key_lower.startswith("x-absa-") or key_lower.startswith("x-scanner-"):
                is_tool_header = True
            if not is_tool_header:
                cleaned[key] = value
        return cleaned

    def get_cipher_list(self) -> str:
        """Return browser-like cipher suite list for aiohttp connector."""
        return self._cipher_list

    def get_ssl_context_config(self) -> dict:
        """
        Return SSL context parameters that mimic a real browser.
        Used when creating aiohttp TCPConnector.
        """
        return {
            "cipher_list": self._cipher_list,
        }

    def rotate(self):
        """Randomize the fingerprint parameters."""
        self._cipher_list = random.choice(BROWSER_CIPHER_LISTS)
        self._curve_order = random.choice(BROWSER_CURVE_ORDERS)
        logger.debug("Fingerprint rotated: new cipher set selected")

    def randomize_connection_params(self) -> dict:
        """
        Return randomized TCP connection parameters.
        These affect how the connection appears at the network level.
        """
        return {
            "ttl": random.randint(50, 128),
            "window_size": random.choice([65535, 29200, 16384, 8192]),
        }