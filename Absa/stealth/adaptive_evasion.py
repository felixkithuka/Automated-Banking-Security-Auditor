"""
Adaptive Evasion Module for Absa Security Testing Framework

Provides intelligent payload encoding and evasion strategies that adapt
based on detected WAF profiles. Includes:
- Rate limit probing and adaptive timing
- Encoding chain builder with multiple encoding methods
- Payload mutation based on WAF-specific rules
- HTTP/2 SETTINGS frame normalization
- Content-type and boundary manipulation

This module is designed for authorized security testing only.
"""

import re
import base64
import hashlib
import random
import string
import time
import asyncio
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any, Callable, Union
from enum import Enum
from collections import deque
import logging
import struct

logger = logging.getLogger(__name__)


class EncodingType(Enum):
    """Supported encoding types for payload transformation."""
    NONE = "none"
    URL = "url"
    URL_DOUBLE = "url_double"
    URL_TRIPLE = "url_triple"
    HTML_ENTITY = "html_entity"
    HTML_DECIMAL = "html_decimal"
    HTML_HEX = "html_hex"
    UNICODE = "unicode"
    BASE64 = "base64"
    HEX = "hex"
    MIXED_CASE = "mixed_case"
    COMMENT_INSERTION = "comment_insertion"
    NULL_BYTE = "null_byte"
    TAB_NEWLINE = "tab_newline"
    BACKTICK = "backtick"
    CONCAT_SQL = "concat_sql"
    CHAR_SQL = "char_sql"
    OVERLONG_UTF8 = "overlong_utf8"
    HPP = "hpp"  # HTTP Parameter Pollution


class WAFCategory(Enum):
    """WAF categories for evasion strategy selection."""
    NONE = "none"
    CLOUD_BASED = "cloud_based"
    APPLIANCE = "appliance"
    SOFTWARE = "software"
    CDN_INTEGRATED = "cdn_integrated"
    UNKNOWN = "unknown"


@dataclass
class EncodingChain:
    """Represents a sequence of encoding transformations."""
    encodings: List[EncodingType] = field(default_factory=list)
    effectiveness_score: float = 0.0
    description: str = ""

    def __str__(self) -> str:
        return " -> ".join(e.value for e in self.encodings) if self.encodings else "none"


@dataclass
class RateLimitProfile:
    """Detected rate limit characteristics."""
    max_requests: int = 0
    window_seconds: float = 0
    threshold_reached: bool = False
    block_duration: float = 0
    retry_after: Optional[float] = None
    detection_method: str = ""
    recommended_delay: float = 1.0
    recommended_burst: int = 5
    recommended_sustained: float = 0.5


@dataclass
class PayloadVariant:
    """A transformed payload with metadata."""
    payload: str
    encoding_chain: EncodingChain
    original_payload: str
    category: str
    mutations_applied: List[str] = field(default_factory=list)


@dataclass
class EvasionConfig:
    """Configuration for adaptive evasion."""
    max_encoding_depth: int = 3
    prefer_fast_encodings: bool = True
    respect_rate_limits: bool = True
    adaptive_timing: bool = True
    hpp_enabled: bool = True
    boundary_variation: bool = True
    chunked_encoding: bool = False
    http2_normalization: bool = True
    custom_mutators: List[Callable] = field(default_factory=list)


class EncodingEngine:
    """
    Payload encoding and transformation engine.
    """

    # Characters safe for different contexts
    SQL_SAFE_CHARS = set(string.ascii_letters + string.digits + "_-")
    XSS_SAFE_CHARS = set(string.ascii_letters + string.digits + "_-./")
    PATH_SAFE_CHARS = set(string.ascii_letters + string.digits + "_-./")

    def __init__(self, config: Optional[EvasionConfig] = None):
        self.config = config or EvasionConfig()

        # Encoding effectiveness cache (learns from feedback)
        self._effectiveness_cache: Dict[str, Dict[EncodingType, float]] = {}

        # Pre-built encoding chains by category
        self._chain_templates = self._build_chain_templates()

    def encode(self, payload: str, encoding: EncodingType, context: str = "generic") -> str:
        """Apply a single encoding to a payload."""
        if encoding == EncodingType.NONE:
            return payload

        encoders = {
            EncodingType.URL: self._encode_url,
            EncodingType.URL_DOUBLE: lambda p: self._encode_url(self._encode_url(p)),
            EncodingType.URL_TRIPLE: lambda p: self._encode_url(self._encode_url(self._encode_url(p))),
            EncodingType.HTML_ENTITY: self._encode_html_entity,
            EncodingType.HTML_DECIMAL: self._encode_html_decimal,
            EncodingType.HTML_HEX: self._encode_html_hex,
            EncodingType.UNICODE: self._encode_unicode,
            EncodingType.BASE64: self._encode_base64,
            EncodingType.HEX: self._encode_hex,
            EncodingType.MIXED_CASE: self._encode_mixed_case,
            EncodingType.COMMENT_INSERTION: self._encode_comment_insertion,
            EncodingType.NULL_BYTE: self._encode_null_byte,
            EncodingType.TAB_NEWLINE: self._encode_tab_newline,
            EncodingType.BACKTICK: self._encode_backtick,
            EncodingType.CONCAT_SQL: self._encode_concat_sql,
            EncodingType.CHAR_SQL: self._encode_char_sql,
            EncodingType.OVERLONG_UTF8: self._encode_overlong_utf8,
            EncodingType.HPP: lambda p: p,  # HPP is applied at request level
        }

        encoder = encoders.get(encoding)
        if encoder:
            try:
                return encoder(payload)
            except Exception as e:
                logger.debug(f"Encoding {encoding.value} failed: {e}")
                return payload

        return payload

    def apply_chain(self, payload: str, chain: EncodingChain, context: str = "generic") -> str:
        """Apply a sequence of encodings to a payload."""
        result = payload
        for encoding in chain.encodings:
            result = self.encode(result, encoding, context)
        return result

    def build_chain(self, payload: str, category: str = "generic",
                    waf_profile: Optional[Any] = None) -> EncodingChain:
        """Build an optimal encoding chain for the given context."""
        if waf_profile:
            return self._build_waf_specific_chain(payload, category, waf_profile)

        # Get templates for category
        templates = self._chain_templates.get(category, self._chain_templates["generic"])

        # Score and select best chain
        best_chain = None
        best_score = -1

        for template in templates:
            score = self._score_chain(template, payload, category)
            if score > best_score:
                best_score = score
                best_chain = template

        return best_chain or EncodingChain(encodings=[EncodingType.NONE], description="Fallback: no encoding")

    def generate_variants(self, payload: str, category: str = "generic",
                          count: int = 5, waf_profile: Optional[Any] = None) -> List[PayloadVariant]:
        """Generate multiple payload variants with different encodings."""
        variants = []

        # Generate chains
        chains = self._generate_diverse_chains(payload, category, count, waf_profile)

        for chain in chains:
            encoded = self.apply_chain(payload, chain, category)
            variant = PayloadVariant(
                payload=encoded,
                encoding_chain=chain,
                original_payload=payload,
                category=category,
                mutations_applied=[e.value for e in chain.encodings if e != EncodingType.NONE]
            )
            variants.append(variant)

        return variants

    def record_effectiveness(self, payload: str, encoding: EncodingType,
                             was_effective: bool) -> None:
        """Record whether an encoding was effective (bypassed WAF)."""
        if payload not in self._effectiveness_cache:
            self._effectiveness_cache[payload] = {}

        current = self._effectiveness_cache[payload].get(encoding, 0.5)
        # Exponential moving average
        alpha = 0.3
        new_score = alpha * (1.0 if was_effective else 0.0) + (1 - alpha) * current
        self._effectiveness_cache[payload][encoding] = new_score

    def get_effective_encoding(self, payload: str,
                               candidate_encodings: List[EncodingType]) -> Optional[EncodingType]:
        """Get the most effective encoding for a payload based on history."""
        if payload not in self._effectiveness_cache:
            return candidate_encodings[0] if candidate_encodings else None

        cache = self._effectiveness_cache[payload]
        best_encoding = None
        best_score = -1

        for encoding in candidate_encodings:
            score = cache.get(encoding, 0.5)
            if score > best_score:
                best_score = score
                best_encoding = encoding

        return best_encoding

    # --- Encoding Implementations ---

    def _encode_url(self, payload: str) -> str:
        """URL encode a payload."""
        return urllib.parse.quote(payload, safe='')

    def _encode_html_entity(self, payload: str) -> str:
        """Encode using HTML named entities."""
        entity_map = {
            '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;',
            '&': '&amp;', '(': '&#40;', ')': '&#41;', '#': '&#35;',
            '/': '&#47;', '\\': '&#92;', ';': '&#59;'
        }
        result = []
        for char in payload:
            result.append(entity_map.get(char, char))
        return ''.join(result)

    def _encode_html_decimal(self, payload: str) -> str:
        """Encode using HTML decimal entities."""
        result = []
        for char in payload:
            if char not in string.ascii_letters + string.digits:
                result.append(f"&#{ord(char)};")
            else:
                result.append(char)
        return ''.join(result)

    def _encode_html_hex(self, payload: str) -> str:
        """Encode using HTML hexadecimal entities."""
        result = []
        for char in payload:
            if char not in string.ascii_letters + string.digits:
                result.append(f"&#x{ord(char):02x};")
            else:
                result.append(char)
        return ''.join(result)

    def _encode_unicode(self, payload: str) -> str:
        """Encode using Unicode escapes."""
        result = []
        for char in payload:
            if ord(char) > 127 or not char.isalnum():
                result.append(f"\\u{ord(char):04x}")
            else:
                result.append(char)
        return ''.join(result)

    def _encode_base64(self, payload: str) -> str:
        """Encode using base64."""
        return base64.b64encode(payload.encode()).decode()

    def _encode_hex(self, payload: str) -> str:
        """Encode using hex."""
        return payload.encode().hex()

    def _encode_mixed_case(self, payload: str) -> str:
        """Randomly mix case of alphabetic characters."""
        result = []
        for char in payload:
            if char.isalpha():
                if random.random() > 0.5:
                    result.append(char.upper())
                else:
                    result.append(char.lower())
            else:
                result.append(char)
        return ''.join(result)

    def _encode_comment_insertion(self, payload: str) -> str:
        """Insert inline comments to break patterns (SQL-specific)."""
        # Insert SQL comments between keywords
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT',
                    'UPDATE', 'DELETE', 'DROP', 'EXEC', 'EXECUTE']

        result = payload
        for keyword in keywords:
            # Split keyword with comments
            if keyword.lower() in result.lower():
                idx = result.lower().index(keyword.lower())
                original = result[idx:idx + len(keyword)]
                # Insert comment in middle
                mid = len(keyword) // 2
                commented = original[:mid] + "/**/" + original[mid:]
                result = result.replace(original, commented, 1)

        return result

    def _encode_null_byte(self, payload: str) -> str:
        """Insert null bytes to break parsing."""
        # Insert after special characters
        special = ["'", '"', "<", ">", "(", ")", ";"]
        result = list(payload)
        offset = 0
        for i, char in enumerate(payload):
            if char in special:
                result.insert(i + 1 + offset, "\x00")
                offset += 1
        return ''.join(result)

    def _encode_tab_newline(self, payload: str) -> str:
        """Replace spaces with tabs and newlines."""
        result = payload
        # Replace spaces randomly with tabs or newlines
        i = 0
        while i < len(result):
            if result[i] == ' ':
                replacement = random.choice(['\t', '\n', '\r', ' '])
                result = result[:i] + replacement + result[i + 1:]
            i += 1
        return result

    def _encode_backtick(self, payload: str) -> str:
        """Wrap identifiers in backticks (MySQL)."""
        # Wrap table/column names
        words = re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', payload)
        sql_keywords = {'SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'NOT',
                        'NULL', 'IS', 'IN', 'LIKE', 'BETWEEN', 'EXISTS', 'CASE',
                        'WHEN', 'THEN', 'ELSE', 'END', 'AS', 'ON', 'JOIN', 'LEFT',
                        'RIGHT', 'INNER', 'OUTER', 'GROUP', 'ORDER', 'BY', 'HAVING',
                        'LIMIT', 'OFFSET', 'INSERT', 'INTO', 'VALUES', 'UPDATE', 'SET',
                        'DELETE', 'DROP', 'CREATE', 'ALTER', 'TABLE', 'INDEX', 'VIEW'}

        result = payload
        for word in words:
            if word.upper() not in sql_keywords and word.isidentifier():
                result = result.replace(word, f"`{word}`", 1)

        return result

    def _encode_concat_sql(self, payload: str) -> str:
        """Use SQL CONCAT to build strings."""
        # Convert string literals to CONCAT form
        strings = re.findall(r"'([^']*)'", payload)

        result = payload
        for s in strings:
            if len(s) > 1:
                # Split string and use CONCAT
                parts = [f"CHR({ord(c)})" for c in s]
                concat_expr = "||".join(parts) if random.random() > 0.5 else f"CONCAT({','.join(parts)})"
                result = result.replace(f"'{s}'", f"({concat_expr})", 1)

        return result

    def _encode_char_sql(self, payload: str) -> str:
        """Use SQL CHAR() function for string literals."""
        strings = re.findall(r"'([^']*)'", payload)

        result = payload
        for s in strings:
            if s:
                chars = ','.join(str(ord(c)) for c in s)
                result = result.replace(f"'{s}'", f"CHAR({chars})", 1)

        return result

    def _encode_overlong_utf8(self, payload: str) -> str:
        """Encode using overlong UTF-8 sequences (bypasses some filters)."""
        result = bytearray()
        for char in payload:
            code = ord(char)
            if code < 128:
                # 2-byte overlong for ASCII
                result.extend([0xC0 | (code >> 6), 0x80 | (code & 0x3F)])
            else:
                result.extend(char.encode('utf-8'))
        return result.decode('latin-1')

    def _build_chain_templates(self) -> Dict[str, List[EncodingChain]]:
        """Build pre-configured encoding chain templates."""
        templates = {
            "sqli": [
                EncodingChain(
                    encodings=[EncodingType.URL],
                    effectiveness_score=0.7,
                    description="Simple URL encoding - good baseline"
                ),
                EncodingChain(
                    encodings=[EncodingType.URL_DOUBLE],
                    effectiveness_score=0.6,
                    description="Double URL encoding - bypasses decoders"
                ),
                EncodingChain(
                    encodings=[EncodingType.COMMENT_INSERTION],
                    effectiveness_score=0.75,
                    description="SQL comment insertion - breaks keyword detection"
                ),
                EncodingChain(
                    encodings=[EncodingType.MIXED_CASE, EncodingType.COMMENT_INSERTION],
                    effectiveness_score=0.8,
                    description="Mixed case + comments - strong combo"
                ),
                EncodingChain(
                    encodings=[EncodingType.TAB_NEWLINE, EncodingType.COMMENT_INSERTION],
                    effectiveness_score=0.7,
                    description="Whitespace variation + comments"
                ),
                EncodingChain(
                    encodings=[EncodingType.CHAR_SQL],
                    effectiveness_score=0.65,
                    description="CHAR() encoding - avoids string literals"
                ),
                EncodingChain(
                    encodings=[EncodingType.NULL_BYTE, EncodingType.URL],
                    effectiveness_score=0.55,
                    description="Null byte + URL - parser confusion"
                ),
                EncodingChain(
                    encodings=[EncodingType.CONCAT_SQL, EncodingType.URL],
                    effectiveness_score=0.6,
                    description="CONCAT + URL - dual encoding"
                ),
                EncodingChain(
                    encodings=[EncodingType.BACKTICK, EncodingType.COMMENT_INSERTION],
                    effectiveness_score=0.7,
                    description="Backticks + comments - MySQL specific"
                ),
                EncodingChain(
                    encodings=[EncodingType.URL_DOUBLE, EncodingType.COMMENT_INSERTION],
                    effectiveness_score=0.65,
                    description="Double URL + comments - layered bypass"
                ),
            ],
            "xss": [
                EncodingChain(
                    encodings=[EncodingType.HTML_ENTITY],
                    effectiveness_score=0.75,
                    description="HTML entity encoding - standard XSS bypass"
                ),
                EncodingChain(
                    encodings=[EncodingType.HTML_DECIMAL],
                    effectiveness_score=0.7,
                    description="HTML decimal entities"
                ),
                EncodingChain(
                    encodings=[EncodingType.HTML_HEX],
                    effectiveness_score=0.7,
                    description="HTML hex entities"
                ),
                EncodingChain(
                    encodings=[EncodingType.URL, EncodingType.HTML_ENTITY],
                    effectiveness_score=0.65,
                    description="URL + HTML entity - dual layer"
                ),
                EncodingChain(
                    encodings=[EncodingType.NULL_BYTE, EncodingType.HTML_ENTITY],
                    effectiveness_score=0.6,
                    description="Null byte + HTML entity"
                ),
                EncodingChain(
                    encodings=[EncodingType.UNICODE],
                    effectiveness_score=0.55,
                    description="Unicode escapes"
                ),
                EncodingChain(
                    encodings=[EncodingType.MIXED_CASE, EncodingType.HTML_ENTITY],
                    effectiveness_score=0.7,
                    description="Mixed case + HTML entities"
                ),
                EncodingChain(
                    encodings=[EncodingType.TAB_NEWLINE],
                    effectiveness_score=0.5,
                    description="Tab/newline in event handlers"
                ),
            ],
            "lfi": [
                EncodingChain(
                    encodings=[EncodingType.URL],
                    effectiveness_score=0.7,
                    description="URL encoding - standard LFI bypass"
                ),
                EncodingChain(
                    encodings=[EncodingType.URL_DOUBLE],
                    effectiveness_score=0.8,
                    description="Double URL encoding - bypasses path normalization"
                ),
                EncodingChain(
                    encodings=[EncodingType.URL_TRIPLE],
                    effectiveness_score=0.6,
                    description="Triple URL encoding - deep bypass"
                ),
                EncodingChain(
                    encodings=[EncodingType.NULL_BYTE],
                    effectiveness_score=0.75,
                    description="Null byte - classic LFI bypass"
                ),
                EncodingChain(
                    encodings=[EncodingType.NULL_BYTE, EncodingType.URL],
                    effectiveness_score=0.8,
                    description="Null byte + URL - strong combo"
                ),
                EncodingChain(
                    encodings=[EncodingType.ENCODING, EncodingType.URL_DOUBLE],
                    effectiveness_score=0.7,
                    description="Overlong UTF-8 + double URL"
                ),
            ],
            "rce": [
                EncodingChain(
                    encodings=[EncodingType.URL],
                    effectiveness_score=0.65,
                    description="URL encoding - standard RCE bypass"
                ),
                EncodingChain(
                    encodings=[EncodingType.URL_DOUBLE],
                    effectiveness_score=0.7,
                    description="Double URL encoding"
                ),
                EncodingChain(
                    encodings=[EncodingType.TAB_NEWLINE],
                    effectiveness_score=0.6,
                    description="Whitespace variation - breaks command parsing"
                ),
                EncodingChain(
                    encodings=[EncodingType.MIXED_CASE, EncodingType.URL],
                    effectiveness_score=0.65,
                    description="Mixed case + URL encoding"
                ),
                EncodingChain(
                    encodings=[EncodingType.COMMENT_INSERTION, EncodingType.URL],
                    effectiveness_score=0.55,
                    description="Comments + URL (limited for RCE)"
                ),
            ],
            "ssrf": [
                EncodingChain(
                    encodings=[EncodingType.URL],
                    effectiveness_score=0.7,
                    description="URL encoding - standard SSRF bypass"
                ),
                EncodingChain(
                    encodings=[EncodingType.URL_DOUBLE],
                    effectiveness_score=0.75,
                    description="Double URL encoding - bypasses URL validation"
                ),
                EncodingChain(
                    encodings=[EncodingType.HEX],
                    effectiveness_score=0.6,
                    description="Hex encoding IP addresses"
                ),
                EncodingChain(
                    encodings=[EncodingType.HTML_DECIMAL],
                    effectiveness_score=0.65,
                    description="Decimal IP encoding"
                ),
            ],
            "generic": [
                EncodingChain(
                    encodings=[EncodingType.URL],
                    effectiveness_score=0.6,
                    description="Simple URL encoding"
                ),
                EncodingChain(
                    encodings=[EncodingType.URL_DOUBLE],
                    effectiveness_score=0.5,
                    description="Double URL encoding"
                ),
                EncodingChain(
                    encodings=[EncodingType.HTML_ENTITY],
                    effectiveness_score=0.5,
                    description="HTML entity encoding"
                ),
                EncodingChain(
                    encodings=[EncodingType.MIXED_CASE],
                    effectiveness_score=0.4,
                    description="Mixed case"
                ),
            ],
        }

        return templates

    def _score_chain(self, chain: EncodingChain, payload: str, category: str) -> float:
        """Score an encoding chain for effectiveness."""
        score = chain.effectiveness_score

        # Prefer simpler chains if configured
        if self.config.prefer_fast_encodings:
            depth_penalty = len(chain.encodings) * 0.05
            score -= depth_penalty

        # Check depth limit
        if len(chain.encodings) > self.config.max_encoding_depth:
            score -= 0.5

        # Check learned effectiveness
        for encoding in chain.encodings:
            learned = self._get_learned_effectiveness(payload, encoding)
            if learned is not None:
                score = score * 0.7 + learned * 0.3

        # Apply custom mutators bonus
        if self.config.custom_mutators:
            score += 0.1

        return score

    def _get_learned_effectiveness(self, payload: str, encoding: EncodingType) -> Optional[float]:
        """Get learned effectiveness score for an encoding."""
        if payload in self._effectiveness_cache:
            return self._effectiveness_cache[payload].get(encoding)
        return None

    def _build_waf_specific_chain(self, payload: str, category: str,
                                  waf_profile: Any) -> EncodingChain:
        """Build encoding chain optimized for specific WAF."""
        vendor = getattr(waf_profile, 'vendor', None)

        # WAF-specific chain preferences
        waf_chains = {
            "cloudflare": [
                EncodingChain([EncodingType.URL], 0.4, "Cloudflare: minimal encoding"),
                EncodingChain([EncodingType.MIXED_CASE], 0.3, "Cloudflare: case variation"),
                EncodingChain([EncodingType.HTML_ENTITY], 0.3, "Cloudflare: HTML entities"),
            ],
            "akamai": [
                EncodingChain([EncodingType.URL], 0.5, "Akamai: URL encoding"),
                EncodingChain([EncodingType.MIXED_CASE, EncodingType.URL], 0.4, "Akamai: mixed + URL"),
                EncodingChain([EncodingType.HTML_DECIMAL], 0.3, "Akamai: decimal entities"),
            ],
            "modsecurity": [
                EncodingChain([EncodingType.COMMENT_INSERTION], 0.8, "ModSec: comment insertion"),
                EncodingChain([EncodingType.URL_DOUBLE], 0.7, "ModSec: double URL"),
                EncodingChain([EncodingType.NULL_BYTE], 0.6, "ModSec: null byte"),
                EncodingChain([EncodingType.TAB_NEWLINE], 0.6, "ModSec: whitespace"),
                EncodingChain([EncodingType.MIXED_CASE, EncodingType.COMMENT_INSERTION], 0.75,
                              "ModSec: mixed + comments"),
            ],
            "aws_waf": [
                EncodingChain([EncodingType.URL_DOUBLE], 0.6, "AWS: double URL"),
                EncodingChain([EncodingType.HTML_ENTITY], 0.5, "AWS: HTML entities"),
                EncodingChain([EncodingType.MIXED_CASE], 0.4, "AWS: mixed case"),
            ],
            "imperva": [
                EncodingChain([EncodingType.URL], 0.5, "Imperva: URL encoding"),
                EncodingChain([EncodingType.URL_DOUBLE], 0.4, "Imperva: double URL"),
                EncodingChain([EncodingType.HTML_DECIMAL], 0.4, "Imperva: decimal entities"),
            ],
            "f5_asm": [
                EncodingChain([EncodingType.URL_DOUBLE], 0.6, "F5: double URL"),
                EncodingChain([EncodingType.COMMENT_INSERTION], 0.5, "F5: comments"),
                EncodingChain([EncodingType.NULL_BYTE], 0.4, "F5: null byte"),
            ],
        }

        vendor_name = vendor.value if vendor else "unknown"
        chains = waf_chains.get(vendor_name, self._chain_templates.get(category, []))

        if not chains:
            return EncodingChain([EncodingType.NONE], 0.1, "Fallback: no WAF-specific chain")

        # Select best based on scoring
        best = max(chains, key=lambda c: self._score_chain(c, payload, category))
        return best

    def _generate_diverse_chains(self, payload: str, category: str,
                                 count: int, waf_profile: Optional[Any]) -> List[EncodingChain]:
        """Generate diverse encoding chains."""
        chains = []

        # Get category templates
        templates = self._chain_templates.get(category, self._chain_templates["generic"])

        # If WAF profile provided, prioritize WAF-specific chains
        if waf_profile:
            waf_chain = self._build_waf_specific_chain(payload, category, waf_profile)
            if waf_chain.encodings != [EncodingType.NONE]:
                chains.append(waf_chain)

        # Add diverse templates
        sorted_templates = sorted(templates, key=lambda t: t.effectiveness_score, reverse=True)

        for template in sorted_templates:
            if len(chains) >= count:
                break

            # Avoid duplicates
            if any(str(c) == str(template) for c in chains):
                continue

            # Add with slight variation
            chain = EncodingChain(
                encodings=list(template.encodings),
                effectiveness_score=template.effectiveness_score,
                description=template.description
            )
            chains.append(chain)

        # Fill remaining with random combinations
        while len(chains) < count:
            chain = self._generate_random_chain(category)
            chains.append(chain)

        return chains[:count]

    def _generate_random_chain(self, category: str) -> EncodingChain:
        """Generate a random encoding chain."""
        category_encodings = {
            "sqli": [EncodingType.URL, EncodingType.URL_DOUBLE, EncodingType.COMMENT_INSERTION,
                     EncodingType.MIXED_CASE, EncodingType.TAB_NEWLINE, EncodingType.NULL_BYTE,
                     EncodingType.BACKTICK, EncodingType.CHAR_SQL],
            "xss": [EncodingType.HTML_ENTITY, EncodingType.HTML_DECIMAL, EncodingType.HTML_HEX,
                    EncodingType.URL, EncodingType.UNICODE, EncodingType.MIXED_CASE],
            "lfi": [EncodingType.URL, EncodingType.URL_DOUBLE, EncodingType.URL_TRIPLE,
                    EncodingType.NULL_BYTE],
            "rce": [EncodingType.URL, EncodingType.URL_DOUBLE, EncodingType.TAB_NEWLINE,
                    EncodingType.MIXED_CASE],
            "generic": [EncodingType.URL, EncodingType.URL_DOUBLE, EncodingType.HTML_ENTITY,
                        EncodingType.MIXED_CASE],
        }

        available = category_encodings.get(category, category_encodings["generic"])

        # Random depth 1-3
        depth = random.randint(1, min(3, self.config.max_encoding_depth))
        encodings = random.sample(available, min(depth, len(available)))

        return EncodingChain(
            encodings=encodings,
            effectiveness_score=0.3,
            description="Random chain"
        )


class RateLimitProber:
    """
    Probes rate limits by sending increasing request rates
    and detecting blocking thresholds.
    """

    def __init__(self, http_client, config: Optional[Dict] = None):
        """
        Initialize rate limit prober.

        Args:
            http_client: Async HTTP client
            config: Configuration options
                - max_test_requests: int (default: 50)
                - initial_delay: float (default: 0.1)
                - max_delay: float (default: 5.0)
                - backoff_factor: float (default: 1.5)
                - block_threshold: int (default: 3) consecutive blocks to confirm
        """
        self.http_client = http_client
        self.config = config or {}

        self.max_test_requests = self.config.get("max_test_requests", 50)
        self.initial_delay = self.config.get("initial_delay", 0.1)
        self.max_delay = self.config.get("max_delay", 5.0)
        self.backoff_factor = self.config.get("backoff_factor", 1.5)
        self.block_threshold = self.config.get("block_threshold", 3)

        self._request_history: deque = deque(maxlen=1000)
        self._current_delay = self.initial_delay

    async def probe(self, url: str) -> RateLimitProfile:
        """
        Probe rate limits for the given URL.

        Args:
            url: URL to probe

        Returns:
            RateLimitProfile with detected limits
        """
        profile = RateLimitProfile()

        consecutive_blocks = 0
        window_start = time.time()
        window_requests = 0

        for i in range(self.max_test_requests):
            try:
                response = await self.http_client.get(url)

                now = time.time()
                window_requests += 1

                # Record request
                self._request_history.append({
                    "timestamp": now,
                    "status": response.status_code,
                    "delay": self._current_delay
                })

                # Check for blocking
                if self._is_blocked(response):
                    consecutive_blocks += 1
                    profile.block_duration = response.headers.get("retry-after", None)
                    if profile.retry_after is None:
                        try:
                            profile.retry_after = float(profile.block_duration)
                        except (ValueError, TypeError):
                            profile.retry_after = None
                else:
                    consecutive_blocks = 0
                    profile.max_requests = window_requests

                # Check if threshold reached
                if consecutive_blocks >= self.block_threshold:
                    profile.threshold_reached = True
                    window_seconds = now - window_start
                    profile.window_seconds = window_seconds
                    profile.detection_method = "consecutive_blocks"
                    break

                # Adaptive delay
                self._update_delay(consecutive_blocks)

                await asyncio.sleep(self._current_delay)

            except Exception as e:
                logger.debug(f"Rate limit probe failed: {e}")
                consecutive_blocks += 1
                await asyncio.sleep(self._current_delay)
                continue

        # Calculate recommended settings
        self._calculate_recommendations(profile)

        return profile

    def _is_blocked(self, response) -> bool:
        """Check if response indicates rate limiting."""
        if response.status_code in (429, 503):
            return True

        headers = self._get_headers(response)
        if "retry-after" in headers:
            return True

        body = ""
        if hasattr(response, "text"):
            body = response.text[:1000].lower()

        rate_limit_phrases = ["rate limit", "too many requests", "slow down",
                              "try again later", "throttl"]
        if any(phrase in body for phrase in rate_limit_phrases):
            return True

        return False

    def _update_delay(self, consecutive_blocks: int):
        """Update request delay based on blocking."""
        if consecutive_blocks > 0:
            # Exponential backoff
            self._current_delay = min(
                self._current_delay * self.backoff_factor,
                self.max_delay
            )
        else:
            # Gradually reduce delay
            self._current_delay = max(
                self._current_delay * 0.9,
                self.initial_delay
            )

    def _calculate_recommendations(self, profile: RateLimitProfile):
        """Calculate recommended request parameters."""
        if profile.max_requests > 0 and profile.window_seconds > 0:
            # Calculate safe rate (70% of detected limit)
            safe_rate = (profile.max_requests / profile.window_seconds) * 0.7
            profile.recommended_delay = 1.0 / safe_rate if safe_rate > 0 else 1.0
            profile.recommended_burst = max(1, int(profile.max_requests * 0.3))
            profile.recommended_sustained = profile.recommended_delay
        else:
            # Conservative defaults
            profile.recommended_delay = 2.0
            profile.recommended_burst = 3
            profile.recommended_sustained = 1.0

        # Apply retry-after if available
        if profile.retry_after:
            profile.recommended_delay = max(profile.recommended_delay, profile.retry_after * 1.5)

    def _get_headers(self, response) -> Dict[str, str]:
        """Extract headers as lowercase dict."""
        headers = {}
        if hasattr(response, "headers"):
            if hasattr(response.headers, "items"):
                for k, v in response.headers.items():
                    headers[k.lower()] = str(v)
        return headers

    def get_current_delay(self) -> float:
        """Get current recommended delay."""
        return self._current_delay


class HTTP2Normalizer:
    """
    HTTP/2 SETTINGS frame and priority normalization.
    """

    # Common SETTINGS frame configurations
    SETTINGS_PRESETS = {
        "chrome": {
            "HEADER_TABLE_SIZE": 65536,
            "ENABLE_PUSH": 0,
            "MAX_CONCURRENT_STREAMS": 1000,
            "INITIAL_WINDOW_SIZE": 6291456,
            "MAX_FRAME_SIZE": 16384,
            "MAX_HEADER_LIST_SIZE": 262144,
            "frame_order": ["SETTINGS", "HEADERS", "DATA"],
            "priority_weight": 256,
            "priority_dependency": 0,
        },
        "firefox": {
            "HEADER_TABLE_SIZE": 65536,
            "ENABLE_PUSH": 0,
            "MAX_CONCURRENT_STREAMS": 100,
            "INITIAL_WINDOW_SIZE": 131072,
            "MAX_FRAME_SIZE": 16384,
            "MAX_HEADER_LIST_SIZE": 262144,
            "frame_order": ["SETTINGS", "HEADERS", "DATA"],
            "priority_weight": 64,
            "priority_dependency": 0,
        },
        "safari": {
            "HEADER_TABLE_SIZE": 4096,
            "ENABLE_PUSH": 1,
            "MAX_CONCURRENT_STREAMS": 100,
            "INITIAL_WINDOW_SIZE": 65535,
            "MAX_FRAME_SIZE": 16384,
            "MAX_HEADER_LIST_SIZE": 8192,
            "frame_order": ["SETTINGS", "HEADERS", "DATA"],
            "priority_weight": 16,
            "priority_dependency": 0,
        },
        "cloudflare_normal": {
            "HEADER_TABLE_SIZE": 65536,
            "ENABLE_PUSH": 0,
            "MAX_CONCURRENT_STREAMS": 128,
            "INITIAL_WINDOW_SIZE": 65535,
            "MAX_FRAME_SIZE": 16384,
            "MAX_HEADER_LIST_SIZE": 524288,
            "frame_order": ["SETTINGS", "HEADERS", "DATA"],
            "priority_weight": 256,
            "priority_dependency": 0,
        },
    }

    # Settings ID to name mapping
    SETTINGS_IDS = {
        0x1: "HEADER_TABLE_SIZE",
        0x2: "ENABLE_PUSH",
        0x3: "MAX_CONCURRENT_STREAMS",
        0x4: "INITIAL_WINDOW_SIZE",
        0x5: "MAX_FRAME_SIZE",
        0x6: "MAX_HEADER_LIST_SIZE",
    }

    # Frame type IDs
    FRAME_TYPES = {
        0x0: "DATA",
        0x1: "HEADERS",
        0x2: "PRIORITY",
        0x3: "RST_STREAM",
        0x4: "SETTINGS",
        0x5: "PUSH_PROMISE",
        0x6: "PING",
        0x7: "GOAWAY",
        0x8: "WINDOW_UPDATE",
        0x9: "CONTINUATION",
    }

    def __init__(self, browser_profile: str = "chrome"):
        """
        Initialize HTTP/2 normalizer.

        Args:
            browser_profile: Browser profile to mimic (chrome, firefox, safari)
        """
        self.browser_profile = browser_profile
        self.settings = self.SETTINGS_PRESETS.get(browser_profile, self.SETTINGS_PRESETS["chrome"])

    def get_settings_frame(self) -> bytes:
        """
        Build HTTP/2 SETTINGS frame bytes.

        Returns:
            Raw SETTINGS frame bytes
        """
        payload = b""

        settings_map = {
            "HEADER_TABLE_SIZE": 0x1,
            "ENABLE_PUSH": 0x2,
            "MAX_CONCURRENT_STREAMS": 0x3,
            "INITIAL_WINDOW_SIZE": 0x4,
            "MAX_FRAME_SIZE": 0x5,
            "MAX_HEADER_LIST_SIZE": 0x6,
        }

        for name, value in self.settings.items():
            if name in settings_map:
                setting_id = settings_map[name]
                payload += struct.pack("!HI", setting_id, value)

        # Frame header: length(3) + type(1) + flags(1) + stream_id(4)
        frame_header = struct.pack("!I", len(payload))[1:]  # 3 bytes length
        frame_header += struct.pack("!B", 0x4)  # SETTINGS type
        frame_header += struct.pack("!B", 0x0)  # No flags
        frame_header += struct.pack("!I", 0x0)  # Stream 0

        return frame_header + payload

    def get_window_update_frame(self, increment: int = 15663105) -> bytes:
        """
        Build HTTP/2 WINDOW_UPDATE frame.

        Args:
            increment: Window size increment

        Returns:
            Raw WINDOW_UPDATE frame bytes
        """
        payload = struct.pack("!I", increment)

        frame_header = struct.pack("!I", len(payload))[1:]
        frame_header += struct.pack("!B", 0x8)  # WINDOW_UPDATE type
        frame_header += struct.pack("!B", 0x0)  # No flags
        frame_header += struct.pack("!I", 0x0)  # Stream 0

        return frame_header + payload

    def get_priority_frame(self, stream_id: int = 1, weight: int = None,
                           dependency: int = None, exclusive: bool = False) -> bytes:
        """
        Build HTTP/2 PRIORITY frame.

        Args:
            stream_id: Stream to prioritize
            weight: Priority weight (1-256)
            dependency: Dependency stream ID
            exclusive: Exclusive dependency flag

        Returns:
            Raw PRIORITY frame bytes
        """
        weight = weight or self.settings.get("priority_weight", 256)
        dependency = dependency if dependency is not None else self.settings.get("priority_dependency", 0)

        # First bit is exclusive flag
        dep_and_exclusive = dependency | (0x80000000 if exclusive else 0)

        payload = struct.pack("!IH", dep_and_exclusive, weight)

        frame_header = struct.pack("!I", len(payload))[1:]
        frame_header += struct.pack("!B", 0x2)  # PRIORITY type
        frame_header += struct.pack("!B", 0x0)  # No flags
        frame_header += struct.pack("!I", stream_id)

        return frame_header + payload

    def get_headers_frame(self, headers: Dict[str, str], stream_id: int = 1,
                          end_stream: bool = True, end_headers: bool = True) -> bytes:
        """
        Build HTTP/2 HEADERS frame (without HPACK encoding for simplicity).

        Args:
            headers: Headers to include
            stream_id: Stream ID
            end_stream: END_STREAM flag
            end_headers: END_HEADERS flag

        Returns:
            Raw HEADERS frame (headers are not HPACK encoded)
        """
        # Build header block (simplified - real implementation needs HPACK)
        header_block = b""
        for name, value in headers.items():
            # Indexed header or literal (simplified)
            header_block += self._encode_header_literal(name, value)

        flags = 0x0
        if end_stream:
            flags |= 0x1
        if end_headers:
            flags |= 0x4

        frame_header = struct.pack("!I", len(header_block))[1:]
        frame_header += struct.pack("!B", 0x1)  # HEADERS type
        frame_header += struct.pack("!B", flags)
        frame_header += struct.pack("!I", stream_id)

        return frame_header + header_block

    def _encode_header_literal(self, name: str, value: str) -> bytes:
        """Encode a header as literal (simplified HPACK)."""
        # Never indexed literal with indexing
        result = b"\x00"  # Never indexed
        result += bytes([len(name)]) + name.encode()
        result += bytes([len(value)]) + value.encode()
        return result

    def parse_settings_frame(self, data: bytes) -> Dict[str, int]:
        """
        Parse HTTP/2 SETTINGS frame from server.

        Args:
            data: Raw frame data

        Returns:
            Dictionary of setting name to value
        """
        settings = {}

        if len(data) < 9:  # Minimum frame header
            return settings

        # Parse frame header
        length = (data[0] << 16) | (data[1] << 8) | data[2]
        frame_type = data[3]
        flags = data[4]
        stream_id = struct.unpack("!I", data[5:9])[0] & 0x7FFFFFFF

        if frame_type != 0x4:  # Not SETTINGS
            return settings

        # Parse settings payload
        payload = data[9:9 + length]

        for i in range(0, len(payload), 6):
            if i + 6 > len(payload):
                break
            setting_id = struct.unpack("!H", payload[i:i + 2])[0]
            value = struct.unpack("!I", payload[i + 2:i + 6])[0]

            name = self.SETTINGS_IDS.get(setting_id, f"UNKNOWN_{setting_id}")
            settings[name] = value

        return settings

    def compare_settings(self, server_settings: Dict[str, int]) -> Dict[str, Any]:
        """
        Compare server SETTINGS with our profile.

        Args:
            server_settings: Parsed server SETTINGS

        Returns:
            Comparison results
        """
        comparison = {
            "matches": [],
            "mismatches": [],
            "missing": [],
            "extra": [],
            "similarity_score": 0.0
        }

        for name, expected in self.settings.items():
            if name in ["frame_order", "priority_weight", "priority_dependency"]:
                continue

            if name in server_settings:
                if server_settings[name] == expected:
                    comparison["matches"].append(name)
                else:
                    comparison["mismatches"].append({
                        "name": name,
                        "expected": expected,
                        "actual": server_settings[name]
                    })
            else:
                comparison["missing"].append(name)

        for name in server_settings:
            if name not in self.settings:
                comparison["extra"].append(name)

        # Calculate similarity
        total = len(self.settings) - 3  # Exclude non-setting keys
        if total > 0:
            comparison["similarity_score"] = len(comparison["matches"]) / total

        return comparison

    def set_profile(self, profile_name: str):
        """Set browser profile for normalization."""
        if profile_name in self.SETTINGS_PRESETS:
            self.browser_profile = profile_name
            self.settings = self.SETTINGS_PRESETS[profile_name]
        else:
            logger.warning(f"Unknown profile {profile_name}, using chrome")
            self.browser_profile = "chrome"
            self.settings = self.SETTINGS_PRESETS["chrome"]


class AdaptiveEvasionEngine:
    """
    Main adaptive evasion engine that coordinates encoding,
    rate limiting, and HTTP/2 normalization.
    """

    def __init__(self, http_client=None, config: Optional[EvasionConfig] = None):
        """
        Initialize adaptive evasion engine.

        Args:
            http_client: Async HTTP client
            config: Evasion configuration
        """
        self.http_client = http_client
        self.config = config or EvasionConfig()

        self.encoding_engine = EncodingEngine(self.config)
        self.rate_limit_prober = None
        self.http2_normalizer = HTTP2Normalizer()

        # State
        self._rate_limit_profile: Optional[RateLimitProfile] = None
        self._waf_profile = None
        self._is_probing = False
        self._request_count = 0
        self._last_request_time = 0
        self._adaptive_delay = 1.0

    async def initialize(self, url: str, waf_profile=None):
        """
        Initialize evasion engine with rate limit probing.

        Args:
            url: Target URL for probing
            waf_profile: Detected WAF profile (optional)
        """
        self._waf_profile = waf_profile

        # Probe rate limits if HTTP client available
        if self.http_client and self.config.respect_rate_limits:
            self.rate_limit_prober = RateLimitProber(self.http_client)
            self._rate_limit_profile = await self.rate_limit_prober.probe(url)
            self._adaptive_delay = self._rate_limit_profile.recommended_delay
            logger.info(f"Rate limit detected: {self._rate_limit_profile.max_requests} "
                        f"req/{self._rate_limit_profile.window_seconds:.1f}s, "
                        f"delay: {self._adaptive_delay:.2f}s")

    async def prepare_payload(self, payload: str, category: str = "generic") -> PayloadVariant:
        """
        Prepare a payload with appropriate encoding.

        Args:
            payload: Original payload
            category: Payload category (sqli, xss, lfi, rce, ssrf, generic)

        Returns:
            PayloadVariant with encoding applied
        """
        chain = self.encoding_engine.build_chain(payload, category, self._waf_profile)
        encoded = self.encoding_engine.apply_chain(payload, chain, category)

        return PayloadVariant(
            payload=encoded,
            encoding_chain=chain,
            original_payload=payload,
            category=category,
            mutations_applied=[e.value for e in chain.encodings if e != EncodingType.NONE]
        )

    async def prepare_variants(self, payload: str, category: str = "generic",
                               count: int = 5) -> List[PayloadVariant]:
        """
        Prepare multiple payload variants.

        Args:
            payload: Original payload
            category: Payload category
            count: Number of variants to generate

        Returns:
            List of PayloadVariant
        """
        return self.encoding_engine.generate_variants(
            payload, category, count, self._waf_profile
        )

    async def record_result(self, variant: PayloadVariant, was_blocked: bool):
        """
        Record whether a payload variant was effective.

        Args:
            variant: The payload variant that was tried
            was_blocked: True if the WAF blocked it
        """
        for encoding in variant.encoding_chain.encodings:
            self.encoding_engine.record_effectiveness(
                variant.original_payload,
                encoding,
                not was_blocked  # Effective if NOT blocked
            )

    async def get_delay(self) -> float:
        """Get current recommended delay between requests."""
        if self.config.adaptive_timing and self.rate_limit_prober:
            return self.rate_limit_prober.get_current_delay()
        return self._adaptive_delay

    async def wait_for_rate_limit(self):
        """Wait appropriate time before next request."""
        delay = await self.get_delay()
        if delay > 0:
            await asyncio.sleep(delay)

    def get_http2_settings(self) -> bytes:
        """Get HTTP/2 SETTINGS frame for normalization."""
        return self.http2_normalizer.get_settings_frame()

    def get_http2_window_update(self) -> bytes:
        """Get HTTP/2 WINDOW_UPDATE frame."""
        return self.http2_normalizer.get_window_update_frame()

    def set_http2_profile(self, profile: str):
        """Set HTTP/2 normalization profile."""
        self.http2_normalizer.set_profile(profile)

    def get_rate_limit_profile(self) -> Optional[RateLimitProfile]:
        """Get detected rate limit profile."""
        return self._rate_limit_profile

    def get_status(self) -> Dict:
        """Get current evasion engine status."""
        return {
            "adaptive_delay": self._adaptive_delay,
            "rate_limit_detected": self._rate_limit_profile is not None,
            "rate_limit_profile": {
                "max_requests": self._rate_limit_profile.max_requests if self._rate_limit_profile else None,
                "window_seconds": self._rate_limit_profile.window_seconds if self._rate_limit_profile else None,
            },
            "waf_profile": self._waf_profile.vendor.value if self._waf_profile else None,
            "http2_profile": self.http2_normalizer.browser_profile,
            "request_count": self._request_count,
        }


# Convenience functions
def encode_payload(payload: str, encoding: EncodingType) -> str:
    """Quick encode a payload with a single encoding."""
    engine = EncodingEngine()
    return engine.encode(payload, encoding)


def generate_variants(payload: str, category: str = "generic", count: int = 5) -> List[PayloadVariant]:
    """Quick generate payload variants."""
    engine = EncodingEngine()
    return engine.generate_variants(payload, category, count)