"""
Network Fingerprint Module for Absa Security Testing Framework

Normalizes TCP/IP and HTTP/2 fingerprints to mimic legitimate browsers:
- TCP options normalization (TTL, window size, MSS, DF flag)
- HTTP/2 frame ordering mimicry
- TLS fingerprint considerations
- Connection parameter normalization

This module is designed for authorized security testing only.
"""

import struct
import socket
import random
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any
from enum import Enum

logger = logging.getLogger(__name__)


class OSProfile(Enum):
    """Operating system profiles for TCP fingerprinting."""
    WINDOWS_10 = "windows_10"
    WINDOWS_11 = "windows_11"
    MACOS_VENTURA = "macos_ventura"
    MACOS_SONOMA = "macos_sonoma"
    LINUX_Ubuntu = "linux_ubuntu"
    LINUX_FEDORA = "linux_fedora"
    ANDROID_13 = "android_13"
    IOS_17 = "ios_17"


class BrowserProfile(Enum):
    """Browser profiles for HTTP/2 fingerprinting."""
    CHROME_120 = "chrome_120"
    CHROME_121 = "chrome_121"
    FIREFOX_121 = "firefox_121"
    SAFARI_17 = "safari_17"
    EDGE_120 = "edge_120"


@dataclass
class TCPFingerprint:
    """TCP/IP fingerprint parameters."""
    ttl: int = 128
    window_size: int = 8192
    mss: int = 1460
    df_flag: bool = True  # Don't Fragment
    sack_permitted: bool = True
    window_scale: int = 8
    timestamp: bool = True
    timestamp_value: int = 0
    nop_count: int = 1
    selective_ack: bool = False
    tcp_options_order: List[str] = field(
        default_factory=lambda: ["MSS", "NOP", "WINDOW_SCALE", "NOP", "NOP", "TIMESTAMPS", "SACK_PERMITTED"])
    syn_retries: int = 2
    keepalive_interval: int = 10


@dataclass
class HTTP2Fingerprint:
    """HTTP/2 connection fingerprint."""
    settings_frame: Dict[str, int] = field(default_factory=dict)
    settings_order: List[str] = field(default_factory=list)
    window_update_size: int = 15663105
    priority_frames: List[Dict] = field(default_factory=list)
    pseudo_header_order: List[str] = field(default_factory=lambda: [
        ":method", ":authority", ":scheme", ":path"
    ])
    header_table_size: int = 65536
    max_concurrent_streams: int = 1000
    initial_window_size: int = 6291456
    max_frame_size: int = 16384
    max_header_list_size: int = 262144
    enable_push: int = 0
    connection_preface_sent: bool = True
    frames_before_headers: List[str] = field(default_factory=lambda: ["SETTINGS"])


@dataclass
class TLSFingerprint:
    """TLS fingerprint parameters (JA3-like)."""
    version: str = "TLS 1.3"
    cipher_suites: List[str] = field(default_factory=lambda: [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    ])
    extensions: List[str] = field(default_factory=lambda: [
        "server_name",
        "extended_master_secret",
        "renegotiation_info",
        "supported_groups",
        "ec_point_formats",
        "session_ticket",
        "signature_algorithms",
        "key_share",
        "psk_key_exchange_modes",
        "supported_versions",
        "compress_certificate",
    ])
    curves: List[str] = field(default_factory=lambda: [
        "x25519", "secp256r1", "secp384r1"
    ])
    signature_algorithms: List[str] = field(default_factory=lambda: [
        "ecdsa_secp256r1_sha256",
        "rsa_pss_rsae_sha256",
        "rsa_pkcs1_sha256",
    ])
    alpn: List[str] = field(default_factory=lambda: ["h2", "http/1.1"])


@dataclass
class NetworkProfile:
    """Combined network fingerprint profile."""
    name: str
    os: OSProfile
    browser: BrowserProfile
    tcp: TCPFingerprint
    http2: HTTP2Fingerprint
    tls: TLSFingerprint
    description: str = ""


# Pre-defined browser profiles with complete fingerprints
BROWSER_PROFILES: Dict[str, NetworkProfile] = {
    "chrome_120": NetworkProfile(
        name="Chrome 120",
        os=OSProfile.WINDOWS_10,
        browser=BrowserProfile.CHROME_120,
        tcp=TCPFingerprint(
            ttl=128,
            window_size=64240,
            mss=1460,
            df_flag=True,
            sack_permitted=True,
            window_scale=8,
            timestamp=True,
            nop_count=1,
            tcp_options_order=["MSS", "NOP", "WINDOW_SCALE", "NOP", "NOP", "TIMESTAMPS", "NOP", "NOP",
                               "SACK_PERMITTED"],
        ),
        http2=HTTP2Fingerprint(
            settings_frame={
                "HEADER_TABLE_SIZE": 65536,
                "ENABLE_PUSH": 0,
                "MAX_CONCURRENT_STREAMS": 1000,
                "INITIAL_WINDOW_SIZE": 6291456,
                "MAX_FRAME_SIZE": 16384,
                "MAX_HEADER_LIST_SIZE": 262144,
            },
            settings_order=["HEADER_TABLE_SIZE", "ENABLE_PUSH", "MAX_CONCURRENT_STREAMS",
                            "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "MAX_HEADER_LIST_SIZE"],
            window_update_size=15663105,
            pseudo_header_order=[":method", ":authority", ":scheme", ":path"],
            frames_before_headers=["SETTINGS"],
        ),
        tls=TLSFingerprint(
            version="TLS 1.3",
            cipher_suites=[
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA",
            ],
        ),
        description="Chrome 120 on Windows 10"
    ),

    "chrome_121": NetworkProfile(
        name="Chrome 121",
        os=OSProfile.WINDOWS_10,
        browser=BrowserProfile.CHROME_121,
        tcp=TCPFingerprint(
            ttl=128,
            window_size=64240,
            mss=1460,
            df_flag=True,
            sack_permitted=True,
            window_scale=8,
            timestamp=True,
            nop_count=1,
            tcp_options_order=["MSS", "NOP", "WINDOW_SCALE", "NOP", "NOP", "TIMESTAMPS", "NOP", "NOP",
                               "SACK_PERMITTED"],
        ),
        http2=HTTP2Fingerprint(
            settings_frame={
                "HEADER_TABLE_SIZE": 65536,
                "ENABLE_PUSH": 0,
                "MAX_CONCURRENT_STREAMS": 1000,
                "INITIAL_WINDOW_SIZE": 6291456,
                "MAX_FRAME_SIZE": 16384,
                "MAX_HEADER_LIST_SIZE": 262144,
            },
            settings_order=["HEADER_TABLE_SIZE", "ENABLE_PUSH", "MAX_CONCURRENT_STREAMS",
                            "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "MAX_HEADER_LIST_SIZE"],
            window_update_size=15663105,
            pseudo_header_order=[":method", ":authority", ":scheme", ":path"],
            frames_before_headers=["SETTINGS"],
        ),
        tls=TLSFingerprint(
            version="TLS 1.3",
            cipher_suites=[
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            ],
        ),
        description="Chrome 121 on Windows 10"
    ),

    "firefox_121": NetworkProfile(
        name="Firefox 121",
        os=OSProfile.WINDOWS_10,
        browser=BrowserProfile.FIREFOX_121,
        tcp=TCPFingerprint(
            ttl=128,
            window_size=64240,
            mss=1460,
            df_flag=True,
            sack_permitted=True,
            window_scale=8,
            timestamp=True,
            nop_count=1,
            tcp_options_order=["MSS", "NOP", "WINDOW_SCALE", "NOP", "NOP", "TIMESTAMPS", "SACK_PERMITTED"],
        ),
        http2=HTTP2Fingerprint(
            settings_frame={
                "HEADER_TABLE_SIZE": 65536,
                "ENABLE_PUSH": 0,
                "MAX_CONCURRENT_STREAMS": 100,
                "INITIAL_WINDOW_SIZE": 131072,
                "MAX_FRAME_SIZE": 16384,
                "MAX_HEADER_LIST_SIZE": 262144,
            },
            settings_order=["HEADER_TABLE_SIZE", "ENABLE_PUSH", "MAX_CONCURRENT_STREAMS",
                            "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "MAX_HEADER_LIST_SIZE"],
            window_update_size=983041,
            pseudo_header_order=[":method", ":authority", ":scheme", ":path"],
            frames_before_headers=["SETTINGS"],
        ),
        tls=TLSFingerprint(
            version="TLS 1.3",
            cipher_suites=[
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ],
        ),
        description="Firefox 121 on Windows 10"
    ),

    "safari_17": NetworkProfile(
        name="Safari 17",
        os=OSProfile.MACOS_SONOMA,
        browser=BrowserProfile.SAFARI_17,
        tcp=TCPFingerprint(
            ttl=64,
            window_size=65535,
            mss=1460,
            df_flag=True,
            sack_permitted=True,
            window_scale=6,
            timestamp=True,
            nop_count=1,
            tcp_options_order=["MSS", "NOP", "WINDOW_SCALE", "NOP", "NOP", "TIMESTAMPS", "SACK_PERMITTED"],
        ),
        http2=HTTP2Fingerprint(
            settings_frame={
                "HEADER_TABLE_SIZE": 4096,
                "ENABLE_PUSH": 1,
                "MAX_CONCURRENT_STREAMS": 100,
                "INITIAL_WINDOW_SIZE": 65535,
                "MAX_FRAME_SIZE": 16384,
                "MAX_HEADER_LIST_SIZE": 8192,
            },
            settings_order=["HEADER_TABLE_SIZE", "MAX_CONCURRENT_STREAMS", "INITIAL_WINDOW_SIZE",
                            "MAX_FRAME_SIZE", "MAX_HEADER_LIST_SIZE", "ENABLE_PUSH"],
            window_update_size=1048576,
            pseudo_header_order=[":method", ":path", ":authority", ":scheme"],
            frames_before_headers=["SETTINGS"],
        ),
        tls=TLSFingerprint(
            version="TLS 1.3",
            cipher_suites=[
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            ],
        ),
        description="Safari 17 on macOS Sonoma"
    ),

    "edge_120": NetworkProfile(
        name="Edge 120",
        os=OSProfile.WINDOWS_11,
        browser=BrowserProfile.EDGE_120,
        tcp=TCPFingerprint(
            ttl=128,
            window_size=64240,
            mss=1460,
            df_flag=True,
            sack_permitted=True,
            window_scale=8,
            timestamp=True,
            nop_count=1,
            tcp_options_order=["MSS", "NOP", "WINDOW_SCALE", "NOP", "NOP", "TIMESTAMPS", "NOP", "NOP",
                               "SACK_PERMITTED"],
        ),
        http2=HTTP2Fingerprint(
            settings_frame={
                "HEADER_TABLE_SIZE": 65536,
                "ENABLE_PUSH": 0,
                "MAX_CONCURRENT_STREAMS": 1000,
                "INITIAL_WINDOW_SIZE": 6291456,
                "MAX_FRAME_SIZE": 16384,
                "MAX_HEADER_LIST_SIZE": 262144,
            },
            settings_order=["HEADER_TABLE_SIZE", "ENABLE_PUSH", "MAX_CONCURRENT_STREAMS",
                            "INITIAL_WINDOW_SIZE", "MAX_FRAME_SIZE", "MAX_HEADER_LIST_SIZE"],
            window_update_size=15663105,
            pseudo_header_order=[":method", ":authority", ":scheme", ":path"],
            frames_before_headers=["SETTINGS"],
        ),
        tls=TLSFingerprint(
            version="TLS 1.3",
            cipher_suites=[
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ],
        ),
        description="Edge 120 on Windows 11"
    ),
}


class TCPNormalizer:
    """
    TCP options normalization for fingerprint mimicry.

    Note: Actual TCP option modification requires raw socket access
    or kernel-level hooks. This class provides the configuration
    and validation logic.
    """

    # Standard TCP option codes
    TCP_OPTIONS = {
        "END": 0,
        "NOP": 1,
        "MSS": 2,
        "WINDOW_SCALE": 3,
        "SACK_PERMITTED": 4,
        "SACK": 5,
        "TIMESTAMPS": 8,
        "FAST_OPEN": 34,
    }

    # Option sizes
    TCP_OPTION_SIZES = {
        "END": 1,
        "NOP": 1,
        "MSS": 4,
        "WINDOW_SCALE": 3,
        "SACK_PERMITTED": 2,
        "TIMESTAMPS": 10,
        "FAST_OPEN": 2,
    }

    def __init__(self, profile: Optional[TCPFingerprint] = None):
        """
        Initialize TCP normalizer.

        Args:
            profile: TCP fingerprint to mimic (default: Chrome on Windows)
        """
        self.profile = profile or TCPFingerprint()
        self._validate_profile()

    def _validate_profile(self):
        """Validate TCP fingerprint parameters."""
        if self.profile.ttl < 1 or self.profile.ttl > 255:
            raise ValueError(f"Invalid TTL: {self.profile.ttl}")

        if self.profile.window_size < 1:
            raise ValueError(f"Invalid window size: {self.profile.window_size}")

        if self.profile.mss < 536 or self.profile.mss > 9000:
            raise ValueError(f"Invalid MSS: {self.profile.mss}")

        if self.profile.window_scale < 0 or self.profile.window_scale > 14:
            raise ValueError(f"Invalid window scale: {self.profile.window_scale}")

    def get_tcp_options_bytes(self) -> bytes:
        """
        Build TCP options byte sequence matching the profile.

        Returns:
            Raw TCP options bytes
        """
        options = b""

        for opt_name in self.profile.tcp_options_order:
            opt_code = self.TCP_OPTIONS.get(opt_name)
            if opt_code is None:
                continue

            if opt_name == "NOP":
                options += struct.pack("B", opt_code)
            elif opt_name == "END":
                options += struct.pack("B", opt_code)
            elif opt_name == "MSS":
                options += struct.pack("BBH", opt_code, 4, self.profile.mss)
            elif opt_name == "WINDOW_SCALE":
                options += struct.pack("BBB", opt_code, 3, self.profile.window_scale)
            elif opt_name == "SACK_PERMITTED":
                options += struct.pack("BB", opt_code, 2)
            elif opt_name == "TIMESTAMPS":
                ts_val = self.profile.timestamp_value or random.randint(0, 0xFFFFFFFF)
                ts_ecr = 0  # Echo reply (0 for SYN)
                options += struct.pack("BBII", opt_code, 10, ts_val, ts_ecr)

        # Pad to multiple of 4 with NOPs, then END
        while len(options) % 4 != 0:
            options += struct.pack("B", self.TCP_OPTIONS["NOP"])
        options += struct.pack("B", self.TCP_OPTIONS["END"])

        return options

    def get_tcp_header_fields(self) -> Dict[str, Any]:
        """
        Get TCP header field values for the profile.

        Returns:
            Dictionary of TCP header fields
        """
        return {
            "window_size": self.profile.window_size,
            "df_flag": self.profile.df_flag,
            "ttl": self.profile.ttl,
            "options": self.get_tcp_options_bytes().hex(),
            "options_length": len(self.get_tcp_options_bytes()),
        }

    def compare_with_profile(self, other: TCPFingerprint) -> Dict[str, Any]:
        """
        Compare another fingerprint with this profile.

        Args:
            other: TCP fingerprint to compare

        Returns:
            Comparison results
        """
        differences = []

        fields = ['ttl', 'window_size', 'mss', 'df_flag', 'sack_permitted',
                  'window_scale', 'timestamp']

        for field_name in fields:
            our_val = getattr(self.profile, field_name)
            other_val = getattr(other, field_name)

            if our_val != other_val:
                differences.append({
                    "field": field_name,
                    "expected": our_val,
                    "actual": other_val,
                    "severity": "high" if field_name in ['ttl', 'window_size', 'mss'] else "medium"
                })

        # Check options order
        if self.profile.tcp_options_order != other.tcp_options_order:
            differences.append({
                "field": "tcp_options_order",
                "expected": self.profile.tcp_options_order,
                "actual": other.tcp_options_order,
                "severity": "high"
            })

        return {
            "differences": differences,
            "match_score": 1.0 - (len(differences) / max(len(fields) + 1, 1)),
            "is_compatible": all(d["severity"] != "high" for d in differences)
        }

    def set_profile(self, profile_name: str):
        """Set TCP profile by browser name."""
        if profile_name in BROWSER_PROFILES:
            self.profile = BROWSER_PROFILES[profile_name].tcp
        else:
            logger.warning(f"Unknown profile {profile_name}")


class HTTP2FrameBuilder:
    """
    HTTP/2 frame ordering and construction.
    """

    FRAME_TYPES = {
        "DATA": 0x0,
        "HEADERS": 0x1,
        "PRIORITY": 0x2,
        "RST_STREAM": 0x3,
        "SETTINGS": 0x4,
        "PUSH_PROMISE": 0x5,
        "PING": 0x6,
        "GOAWAY": 0x7,
        "WINDOW_UPDATE": 0x8,
        "CONTINUATION": 0x9,
    }

    SETTINGS_IDS = {
        "HEADER_TABLE_SIZE": 0x1,
        "ENABLE_PUSH": 0x2,
        "MAX_CONCURRENT_STREAMS": 0x3,
        "INITIAL_WINDOW_SIZE": 0x4,
        "MAX_FRAME_SIZE": 0x5,
        "MAX_HEADER_LIST_SIZE": 0x6,
    }

    FLAGS = {
        "END_STREAM": 0x1,
        "END_HEADERS": 0x4,
        "ACK": 0x1,  # For SETTINGS
    }

    def __init__(self, profile: Optional[HTTP2Fingerprint] = None):
        """
        Initialize HTTP/2 frame builder.

        Args:
            profile: HTTP/2 fingerprint to mimic
        """
        self.profile = profile or HTTP2Fingerprint()

    def build_settings_frame(self, ack: bool = False) -> bytes:
        """
        Build HTTP/2 SETTINGS frame.

        Args:
            ack: If True, send SETTINGS ACK (empty payload)

        Returns:
            Raw SETTINGS frame
        """
        if ack:
            payload = b""
            flags = self.FLAGS["ACK"]
        else:
            payload = b""
            for setting_name, value in self.profile.settings_frame.items():
                setting_id = self.SETTINGS_IDS.get(setting_name)
                if setting_id:
                    payload += struct.pack("!HI", setting_id, value)
            flags = 0x0

        return self._build_frame(0x4, flags, 0, payload)

    def build_settings_in_order(self) -> List[bytes]:
        """
        Build SETTINGS frames respecting the order in the profile.

        Returns:
            List of SETTINGS frames (usually just one)
        """
        # SETTINGS should be sent in specific parameter order
        ordered_payload = b""

        for setting_name in self.profile.settings_order:
            if setting_name in self.profile.settings_frame:
                setting_id = self.SETTINGS_IDS.get(setting_name)
                if setting_id:
                    value = self.profile.settings_frame[setting_name]
                    ordered_payload += struct.pack("!HI", setting_id, value)

        return [self._build_frame(0x4, 0x0, 0, ordered_payload)]

    def build_window_update_frame(self, stream_id: int = 0,
                                  increment: Optional[int] = None) -> bytes:
        """
        Build HTTP/2 WINDOW_UPDATE frame.

        Args:
            stream_id: Stream ID (0 for connection-level)
            increment: Window size increment

        Returns:
            Raw WINDOW_UPDATE frame
        """
        increment = increment or self.profile.window_update_size
        payload = struct.pack("!I", increment)
        return self._build_frame(0x8, 0x0, stream_id, payload)

    def build_headers_frame(self, headers: Dict[str, str], stream_id: int = 1,
                            end_stream: bool = True, end_headers: bool = True) -> bytes:
        """
        Build HTTP/2 HEADERS frame with pseudo-headers in correct order.

        Args:
            headers: Headers dictionary
            stream_id: Stream ID
            end_stream: END_STREAM flag
            end_headers: END_HEADERS flag

        Returns:
            Raw HEADERS frame (headers as raw bytes, not HPACK encoded)
        """
        # Build header block with correct pseudo-header order
        header_block = b""

        # Pseudo-headers first in specified order
        pseudo_headers = {k: v for k, v in headers.items() if k.startswith(":")}
        regular_headers = {k: v for k, v in headers.items() if not k.startswith(":")}

        for pseudo_name in self.profile.pseudo_header_order:
            if pseudo_name in pseudo_headers:
                header_block += self._encode_header(pseudo_name, pseudo_headers[pseudo_name])

        # Regular headers
        for name, value in regular_headers.items():
            header_block += self._encode_header(name, value)

        flags = 0x0
        if end_stream:
            flags |= self.FLAGS["END_STREAM"]
        if end_headers:
            flags |= self.FLAGS["END_HEADERS"]

        return self._build_frame(0x1, flags, stream_id, header_block)

    def build_priority_frame(self, stream_id: int = 1, weight: int = 16,
                             dependency: int = 0, exclusive: bool = False) -> bytes:
        """
        Build HTTP/2 PRIORITY frame.

        Args:
            stream_id: Stream to prioritize
            weight: Priority weight (1-256)
            dependency: Dependency stream ID
            exclusive: Exclusive dependency flag

        Returns:
            Raw PRIORITY frame
        """
        dep_with_exclusive = dependency | (0x80000000 if exclusive else 0)
        payload = struct.pack("!IH", dep_with_exclusive, weight)
        return self._build_frame(0x2, 0x0, stream_id, payload)

    def build_connection_preface(self) -> bytes:
        """
        Build HTTP/2 connection preface.

        Returns:
            Connection preface string
        """
        return b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    def get_initial_frame_sequence(self) -> List[bytes]:
        """
        Get the initial frame sequence for a new connection.

        Returns:
            List of frames in correct order
        """
        frames = []

        # Connection preface
        frames.append(self.build_connection_preface())

        # Frames before headers (as per profile)
        for frame_type in self.profile.frames_before_headers:
            if frame_type == "SETTINGS":
                frames.extend(self.build_settings_in_order())
            elif frame_type == "WINDOW_UPDATE":
                frames.append(self.build_window_update_frame(0))

        return frames

    def _build_frame(self, frame_type: int, flags: int, stream_id: int,
                     payload: bytes) -> bytes:
        """Build raw HTTP/2 frame."""
        length = len(payload)

        # Frame header: 3 bytes length, 1 byte type, 1 byte flags, 4 bytes stream ID
        header = struct.pack("!I", length)[1:]  # 3 bytes
        header += struct.pack("!B", frame_type)
        header += struct.pack("!B", flags)
        header += struct.pack("!I", stream_id & 0x7FFFFFFF)

        return header + payload

    def _encode_header(self, name: str, value: str) -> bytes:
        """
        Encode header for inclusion in frame (simplified, not HPACK).

        In production, this would use proper HPACK encoding.
        """
        # Literal header field never indexed
        result = b"\x00"
        result += bytes([len(name)]) + name.encode("ascii")
        result += bytes([len(value)]) + value.encode("ascii")
        return result

    def set_profile(self, profile_name: str):
        """Set HTTP/2 profile by browser name."""
        if profile_name in BROWSER_PROFILES:
            self.profile = BROWSER_PROFILES[profile_name].http2
        else:
            logger.warning(f"Unknown profile {profile_name}")


class NetworkFingerprintManager:
    """
    Main manager for network fingerprint normalization.
    """

    def __init__(self, profile_name: str = "chrome_120"):
        """
        Initialize network fingerprint manager.

        Args:
            profile_name: Browser profile name to mimic
        """
        self.profile_name = profile_name
        self.profile = BROWSER_PROFILES.get(profile_name, BROWSER_PROFILES["chrome_120"])

        self.tcp_normalizer = TCPNormalizer(self.profile.tcp)
        self.http2_builder = HTTP2FrameBuilder(self.profile.http2)

    def get_profile(self) -> NetworkProfile:
        """Get current network profile."""
        return self.profile

    def get_tcp_options(self) -> bytes:
        """Get TCP options for current profile."""
        return self.tcp_normalizer.get_tcp_options_bytes()

    def get_tcp_header_fields(self) -> Dict[str, Any]:
        """Get TCP header fields for current profile."""
        return self.tcp_normalizer.get_tcp_header_fields()

    def get_http2_settings_frame(self) -> bytes:
        """Get HTTP/2 SETTINGS frame for current profile."""
        return self.http2_builder.build_settings_frame()

    def get_http2_initial_frames(self) -> List[bytes]:
        """Get initial HTTP/2 frame sequence."""
        return self.http2_builder.get_initial_frame_sequence()

    def get_http2_window_update(self) -> bytes:
        """Get HTTP/2 WINDOW_UPDATE frame."""
        return self.http2_builder.build_window_update_frame()

    def get_http2_headers_frame(self, headers: Dict[str, str],
                                stream_id: int = 1) -> bytes:
        """Get HTTP/2 HEADERS frame with correct ordering."""
        return self.http2_builder.build_headers_frame(headers, stream_id)

    def set_profile(self, profile_name: str):
        """
        Set browser profile to mimic.

        Args:
            profile_name: Profile name (chrome_120, firefox_121, safari_17, edge_120)
        """
        if profile_name in BROWSER_PROFILES:
            self.profile_name = profile_name
            self.profile = BROWSER_PROFILES[profile_name]
            self.tcp_normalizer.set_profile(profile_name)
            self.http2_builder.set_profile(profile_name)
            logger.info(f"Switched to profile: {profile_name}")
        else:
            available = ", ".join(BROWSER_PROFILES.keys())
            logger.warning(f"Unknown profile '{profile_name}'. Available: {available}")

    def list_profiles(self) -> List[str]:
        """List available browser profiles."""
        return list(BROWSER_PROFILES.keys())

    def get_connection_config(self) -> Dict[str, Any]:
        """
        Get complete connection configuration for the profile.

        Returns:
            Dictionary with all connection parameters
        """
        return {
            "profile_name": self.profile_name,
            "os": self.profile.os.value,
            "browser": self.profile.browser.value,
            "tcp": {
                "ttl": self.profile.tcp.ttl,
                "window_size": self.profile.tcp.window_size,
                "mss": self.profile.tcp.mss,
                "df_flag": self.profile.tcp.df_flag,
                "window_scale": self.profile.tcp.window_scale,
                "options_order": self.profile.tcp.tcp_options_order,
            },
            "http2": {
                "settings": self.profile.http2.settings_frame,
                "settings_order": self.profile.http2.settings_order,
                "window_update_size": self.profile.http2.window_update_size,
                "pseudo_header_order": self.profile.http2.pseudo_header_order,
            },
            "tls": {
                "version": self.profile.tls.version,
                "alpn": self.profile.tls.alpn,
                "cipher_count": len(self.profile.tls.cipher_suites),
            }
        }

    def compare_with_server_settings(self, server_settings: Dict[str, int]) -> Dict[str, Any]:
        """
        Compare our profile with server HTTP/2 settings.

        Args:
            server_settings: Server's SETTINGS frame values

        Returns:
            Comparison results
        """
        comparison = {
            "matches": [],
            "mismatches": [],
            "our_values": self.profile.http2.settings_frame,
            "server_values": server_settings,
        }

        for name, our_value in self.profile.http2.settings_frame.items():
            server_value = server_settings.get(name)
            if server_value is not None:
                if our_value == server_value:
                    comparison["matches"].append(name)
                else:
                    comparison["mismatches"].append({
                        "setting": name,
                        "our_value": our_value,
                        "server_value": server_value,
                    })

        return comparison


# Convenience function
def get_fingerprint_config(profile_name: str = "chrome_120") -> Dict[str, Any]:
    """Quick get fingerprint configuration for a profile."""
    manager = NetworkFingerprintManager(profile_name)
    return manager.get_connection_config()