"""
WAF Detector Module for Absa Security Testing Framework

Identifies Web Application Firewall products/vendors through:
- HTTP response header signature analysis
- Cookie name pattern matching
- Error page body content fingerprinting
- Behavioral trigger probing (safe payloads)

This module is designed for authorized security testing and WAF validation only.
"""

import re
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any
from enum import Enum
from urllib.parse import urlparse
import logging
import asyncio

logger = logging.getLogger(__name__)


class WAFVendor(Enum):
    """Known WAF vendors with identification capabilities."""
    UNKNOWN = "unknown"
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    AKAMAI_KONA = "akamai_kona"
    AWS_WAF = "aws_waf"
    AZURE_WAF = "azure_waf"
    GOOGLE_CLOUD_ARMOR = "google_cloud_armor"
    IMPERVA = "imperva"
    MODSECURITY = "modsecurity"
    F5_ASM = "f5_asm"
    CITRIX = "citrix"
    BARRACUDA = "barracuda"
    FORTINET = "fortinet"
    SUCURI = "sucuri"
    WORDFENCE = "wordfence"
    FASTLY = "fastly"
    WALLARM = "wallarm"
    SIGNAL_SCIENCES = "signal_sciences"
    EDGECAST = "edgecast"
    RADWARE = "radware"
    QRATOR = "qrator"
    STACKPATH = "stackpath"
    VARNISH = "varnish"
    APACHE_SHIELD = "apache_shield"
    NGINX_BASIC = "nginx_basic"
    COMODO = "comodo"
    DENYALL = "denyall"
    TRUSTWAVE = "trustwave"
    ZSCALER = "zscaler"
    PALO_ALTO = "palo_alto"
    SOPHOS = "sophos"
    CHECK_POINT = "check_point"
    CISCO_FTD = "cisco_ftd"
    YUNDUN = "yundun"
    SAFELINE = "safeline"


class ConfidenceLevel(Enum):
    """Confidence level for WAF detection."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    DEFINITIVE = 4


class DetectionMethod(Enum):
    """How the WAF was identified."""
    HEADER = "header"
    COOKIE = "cookie"
    BODY_FINGERPRINT = "body_fingerprint"
    BEHAVIORAL = "behavioral"
    HTTP2_SETTINGS = "http2_settings"
    COMBINED = "combined"


@dataclass
class WAFFingerprint:
    """Fingerprint entry for WAF detection."""
    vendor: WAFVendor
    pattern: str
    location: DetectionMethod
    confidence: ConfidenceLevel
    description: str


@dataclass
class WAFProfile:
    """Complete WAF detection profile."""
    vendor: WAFVendor
    confidence: ConfidenceLevel
    detection_methods: List[DetectionMethod] = field(default_factory=list)
    detected_signatures: List[str] = field(default_factory=list)
    version: Optional[str] = None
    bypass_strategies: List[str] = field(default_factory=list)
    characteristics: Dict[str, Any] = field(default_factory=dict)
    raw_evidence: List[Tuple[str, str]] = field(default_factory=list)


@dataclass
class WAFDetectionResult:
    """Complete WAF detection result."""
    detected: bool
    primary_profile: Optional[WAFProfile] = None
    secondary_profiles: List[WAFProfile] = field(default_factory=list)
    scan_metadata: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


class WAFSignatureDatabase:
    """Comprehensive WAF signature database."""

    # Header-based signatures: (header_name, pattern, vendor, confidence, description)
    HEADER_SIGNATURES: List[Tuple[str, str, WAFVendor, ConfidenceLevel, str]] = [
        # Cloudflare
        ("server", r"(?i)cloudflare", WAFVendor.CLOUDFLARE, ConfidenceLevel.HIGH, "Server header indicates Cloudflare"),
        ("cf-ray", r".+", WAFVendor.CLOUDFLARE, ConfidenceLevel.DEFINITIVE, "CF-Ray header is Cloudflare-specific"),
        ("cf-cache-status", r".+", WAFVendor.CLOUDFLARE, ConfidenceLevel.HIGH, "CF-Cache-Status header present"),
        ("cf-mitigated", r".+", WAFVendor.CLOUDFLARE, ConfidenceLevel.HIGH, "CF-Mitigated header present"),

        # Akamai & Akamai Kona
        ("x-akamai-staging", r".+", WAFVendor.AKAMAI, ConfidenceLevel.HIGH, "Akamai staging header"),
        ("x-akamai-request-id", r".+", WAFVendor.AKAMAI, ConfidenceLevel.DEFINITIVE, "Akamai request ID header"),
        ("x-akamai-edgescape", r".+", WAFVendor.AKAMAI, ConfidenceLevel.HIGH, "Akamai edgescape header"),
        ("akamai-origin-hop", r".+", WAFVendor.AKAMAI, ConfidenceLevel.HIGH, "Akamai origin hop header"),
        ("x-cache", r"(?i)akamai", WAFVendor.AKAMAI, ConfidenceLevel.MEDIUM, "X-Cache mentions Akamai"),
        ("x-akamai-ghost", r".+", WAFVendor.AKAMAI_KONA, ConfidenceLevel.DEFINITIVE, "Akamai Kona Ghost header"),
        ("x-akamai-x-cache-remote", r".+", WAFVendor.AKAMAI_KONA, ConfidenceLevel.HIGH,
         "Akamai Kona cache remote header"),
        ("x-akamai-astra-error", r".+", WAFVendor.AKAMAI_KONA, ConfidenceLevel.DEFINITIVE, "Akamai Kona ASTRA error"),

        # AWS WAF
        ("x-amzn-requestid", r".+", WAFVendor.AWS_WAF, ConfidenceLevel.MEDIUM, "AWS request ID header"),
        ("x-amzn-trace-id", r".+", WAFVendor.AWS_WAF, ConfidenceLevel.MEDIUM, "AWS trace ID header"),
        ("x-amz-cf-id", r".+", WAFVendor.AWS_WAF, ConfidenceLevel.MEDIUM, "AWS CloudFront ID header"),
        ("via", r"(?i)aws-elb|amazon", WAFVendor.AWS_WAF, ConfidenceLevel.MEDIUM, "Via header indicates AWS"),
        ("x-amz-apigw-id", r".+", WAFVendor.AWS_WAF, ConfidenceLevel.HIGH, "API Gateway ID header"),
        ("awswaf", r".+", WAFVendor.AWS_WAF, ConfidenceLevel.HIGH, "AWS WAF cookie/header"),

        # Azure WAF
        ("x-azure-ref", r".+", WAFVendor.AZURE_WAF, ConfidenceLevel.DEFINITIVE, "Azure WAF reference header"),
        ("x-azure-requestid", r".+", WAFVendor.AZURE_WAF, ConfidenceLevel.HIGH, "Azure request ID header"),
        ("x-ms-request-id", r".+", WAFVendor.AZURE_WAF, ConfidenceLevel.MEDIUM, "MS request ID header"),
        ("x-ms-apim-request-id", r".+", WAFVendor.AZURE_WAF, ConfidenceLevel.HIGH, "Azure APIM request ID"),
        ("x-fd-activityid", r".+", WAFVendor.AZURE_WAF, ConfidenceLevel.HIGH, "Azure Front Door activity ID"),

        # Google Cloud Armor
        ("x-google-error", r".+", WAFVendor.GOOGLE_CLOUD_ARMOR, ConfidenceLevel.HIGH, "Google Cloud error header"),
        ("x-gcp-error", r".+", WAFVendor.GOOGLE_CLOUD_ARMOR, ConfidenceLevel.HIGH, "GCP error header"),
        ("server-timing", r"(?i)gcp", WAFVendor.GOOGLE_CLOUD_ARMOR, ConfidenceLevel.MEDIUM, "GCP Server Timing"),

        # Check Point
        ("x-checkpoint-request-id", r".+", WAFVendor.CHECK_POINT, ConfidenceLevel.DEFINITIVE, "Check Point request ID"),
        ("x-checkpoint-response", r".+", WAFVendor.CHECK_POINT, ConfidenceLevel.DEFINITIVE,
         "Check Point response header"),
        ("x-cp-error", r".+", WAFVendor.CHECK_POINT, ConfidenceLevel.HIGH, "Check Point error header"),

        # Cisco FTD
        ("x-cisco-ndc-request-id", r".+", WAFVendor.CISCO_FTD, ConfidenceLevel.DEFINITIVE, "Cisco NDC request ID"),
        ("x-cisco-ftd-request-id", r".+", WAFVendor.CISCO_FTD, ConfidenceLevel.DEFINITIVE, "Cisco FTD request ID"),
        ("x-cisco-uaac-request-id", r".+", WAFVendor.CISCO_FTD, ConfidenceLevel.DEFINITIVE, "Cisco UAAC request ID"),

        # Imperva/Incapsula
        ("x-iinfo", r".+", WAFVendor.IMPERVA, ConfidenceLevel.DEFINITIVE, "Imperva X-IInfo header"),
        ("x-cdn", r"(?i)incapsula", WAFVendor.IMPERVA, ConfidenceLevel.HIGH, "Incapsula CDN header"),
        ("x-visitor-id", r".+", WAFVendor.IMPERVA, ConfidenceLevel.HIGH, "Imperva visitor ID header"),
        ("x-imperva-info", r".+", WAFVendor.IMPERVA, ConfidenceLevel.HIGH, "Imperva info header"),
        ("incap_ses_id", r".+", WAFVendor.IMPERVA, ConfidenceLevel.DEFINITIVE, "Incapsula session cookie (in headers)"),

        # ModSecurity
        ("server", r"(?i)mod_security|modsecurity", WAFVendor.MODSECURITY, ConfidenceLevel.HIGH,
         "Server header mentions ModSecurity"),
        ("x-modsecurity-rule-id", r".+", WAFVendor.MODSECURITY, ConfidenceLevel.DEFINITIVE,
         "ModSecurity rule ID header"),
        ("x-modsecurity-rule-message", r".+", WAFVendor.MODSECURITY, ConfidenceLevel.DEFINITIVE,
         "ModSecurity rule message"),
        ("x-modsecurity-rule-severity", r".+", WAFVendor.MODSECURITY, ConfidenceLevel.HIGH,
         "ModSecurity severity header"),
        ("mod_security", r".+", WAFVendor.MODSECURITY, ConfidenceLevel.HIGH, "ModSecurity header present"),

        # F5 ASM
        ("server", r"(?i)big-ip|bigip", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "Server header indicates F5 BIG-IP"),
        ("x-wa-info", r".+", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 WAF info header"),
        ("bigipauthcookie", r".+", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 authentication cookie"),
        ("f5-bigip-traversal-id", r".+", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 traversal ID"),
        ("x-f5-auth-token", r".+", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 auth token"),
        ("tsr-cookie", r".+", WAFVendor.F5_ASM, ConfidenceLevel.MEDIUM, "F5 TSR cookie"),

        # Citrix
        ("via", r"(?i)ns_focus|citrix", WAFVendor.CITRIX, ConfidenceLevel.HIGH, "Via header indicates Citrix"),
        ("ns_cachesessionid", r".+", WAFVendor.CITRIX, ConfidenceLevel.HIGH, "Citrix cache session cookie"),
        ("citrix_ns_id", r".+", WAFVendor.CITRIX, ConfidenceLevel.HIGH, "Citrix NS ID header"),
        ("x-ns-hit", r".+", WAFVendor.CITRIX, ConfidenceLevel.HIGH, "Citrix NS hit header"),

        # Barracuda
        ("barraid", r".+", WAFVendor.BARRACUDA, ConfidenceLevel.DEFINITIVE, "Barracuda ID cookie"),
        ("bnz-cid", r".+", WAFVendor.BARRACUDA, ConfidenceLevel.HIGH, "Barracuda CID header"),
        ("x-barracuda", r".+", WAFVendor.BARRACUDA, ConfidenceLevel.HIGH, "Barracuda header"),
        ("barra_counter_session", r".+", WAFVendor.BARRACUDA, ConfidenceLevel.HIGH, "Barracuda session cookie"),

        # Fortinet
        ("server", r"(?i)fortiweb|fortinet", WAFVendor.FORTINET, ConfidenceLevel.HIGH,
         "Server header indicates Fortinet"),
        ("fnrmt-cookie", r".+", WAFVendor.FORTINET, ConfidenceLevel.HIGH, "Fortinet remote cookie"),
        ("fortigateid", r".+", WAFVendor.FORTINET, ConfidenceLevel.HIGH, "Fortinet ID cookie"),

        # Sucuri
        ("x-sucuri-id", r".+", WAFVendor.SUCURI, ConfidenceLevel.DEFINITIVE, "Sucuri ID header"),
        ("x-sucuri-cache", r".+", WAFVendor.SUCURI, ConfidenceLevel.HIGH, "Sucuri cache header"),
        ("sucuri_cloudproxy_cookie", r".+", WAFVendor.SUCURI, ConfidenceLevel.DEFINITIVE, "Sucuri cloudproxy cookie"),

        # Wordfence
        ("x-wordfence-blocked", r".+", WAFVendor.WORDFENCE, ConfidenceLevel.DEFINITIVE, "Wordfence blocked header"),

        # Fastly
        ("x-fastly-request-id", r".+", WAFVendor.FASTLY, ConfidenceLevel.HIGH, "Fastly request ID header"),
        ("x-fastly-debug", r".+", WAFVendor.FASTLY, ConfidenceLevel.HIGH, "Fastly debug header"),
        ("x-served-by", r"(?i)cache-[a-z0-9]+", WAFVendor.FASTLY, ConfidenceLevel.MEDIUM, "Fastly cache server header"),

        # Radware
        ("x-rw-info", r".+", WAFVendor.RADWARE, ConfidenceLevel.HIGH, "Radware info header"),
        ("x-rw-block-reason", r".+", WAFVendor.RADWARE, ConfidenceLevel.HIGH, "Radware block reason"),
        ("_rwdid", r".+", WAFVendor.RADWARE, ConfidenceLevel.HIGH, "Radware DID cookie"),

        # Wallarm
        ("x-wallarm-blocked", r".+", WAFVendor.WALLARM, ConfidenceLevel.DEFINITIVE, "Wallarm blocked header"),
        ("x-wallarm-action", r".+", WAFVendor.WALLARM, ConfidenceLevel.HIGH, "Wallarm action header"),
        ("nginx-wallarm", r".+", WAFVendor.WALLARM, ConfidenceLevel.HIGH, "Wallarm nginx module"),

        # QRATOR
        ("x-qrator-id", r".+", WAFVendor.QRATOR, ConfidenceLevel.DEFINITIVE, "QRator ID header"),
        ("qrator_jsid", r".+", WAFVendor.QRATOR, ConfidenceLevel.HIGH, "QRator JS cookie"),

        # StackPath
        ("server", r"(?i)stackpath", WAFVendor.STACKPATH, ConfidenceLevel.HIGH, "Server header indicates StackPath"),
        ("x-sp-cache", r".+", WAFVendor.STACKPATH, ConfidenceLevel.HIGH, "StackPath cache header"),

        # Varnish
        ("x-varnish", r".+", WAFVendor.VARNISH, ConfidenceLevel.HIGH, "Varnish header"),
        ("x-varnish-cache", r".+", WAFVendor.VARNISH, ConfidenceLevel.HIGH, "Varnish cache header"),
        ("x-varnish-hits", r".+", WAFVendor.VARNISH, ConfidenceLevel.HIGH, "Varnish hits header"),

        # Sophos
        ("x-sophos-id", r".+", WAFVendor.SOPHOS, ConfidenceLevel.HIGH, "Sophos ID header"),
        ("sophos_session_id", r".+", WAFVendor.SOPHOS, ConfidenceLevel.HIGH, "Sophos session cookie"),

        # Zscaler
        ("x-zscaler-id", r".+", WAFVendor.ZSCALER, ConfidenceLevel.HIGH, "Zscaler ID header"),
        ("zscaler-cdn", r".+", WAFVendor.ZSCALER, ConfidenceLevel.HIGH, "Zscaler CDN header"),

        # Yundun (Alibaba Cloud)
        ("x-yd-waf-request-id", r".+", WAFVendor.YUNDUN, ConfidenceLevel.DEFINITIVE, "Yundun WAF request ID"),
        ("x-yd-cloud-trace-id", r".+", WAFVendor.YUNDUN, ConfidenceLevel.HIGH, "Yundun trace ID"),
        ("x-aliyun-waf-request-id", r".+", WAFVendor.YUNDUN, ConfidenceLevel.DEFINITIVE, "Aliyun WAF request ID"),
        ("x-acs-waf-trace-id", r".+", WAFVendor.YUNDUN, ConfidenceLevel.DEFINITIVE, "Aliyun ACS WAF trace"),
        ("server", r"(?i)yundun", WAFVendor.YUNDUN, ConfidenceLevel.HIGH, "Server header Yundun"),

        # Safeline (Chaitin Tech)
        ("x-safeline-request-id", r".+", WAFVendor.SAFELINE, ConfidenceLevel.DEFINITIVE, "Safeline request ID"),
        ("x-safeline-trace-id", r".+", WAFVendor.SAFELINE, ConfidenceLevel.DEFINITIVE, "Safeline trace ID"),
        ("x-chaitin-request-id", r".+", WAFVendor.SAFELINE, ConfidenceLevel.DEFINITIVE, "Chaitin request ID"),
        ("server", r"(?i)safeline", WAFVendor.SAFELINE, ConfidenceLevel.HIGH, "Server header Safeline"),

        # Generic WAF indicators
        ("x-waf-event", r".+", WAFVendor.UNKNOWN, ConfidenceLevel.MEDIUM, "Generic WAF event header"),
        ("x-waf-block", r".+", WAFVendor.UNKNOWN, ConfidenceLevel.MEDIUM, "Generic WAF block header"),
        ("x-waf-status", r".+", WAFVendor.UNKNOWN, ConfidenceLevel.MEDIUM, "Generic WAF status header"),
    ]

    # Cookie-based signatures: (cookie_name_pattern, vendor, confidence, description)
    COOKIE_SIGNATURES: List[Tuple[str, WAFVendor, ConfidenceLevel, str]] = [
        ("^__cfduid$", WAFVendor.CLOUDFLARE, ConfidenceLevel.DEFINITIVE, "Cloudflare __cfduid cookie"),
        ("^__cf_bm$", WAFVendor.CLOUDFLARE, ConfidenceLevel.DEFINITIVE, "Cloudflare bot management cookie"),
        ("^cf_clearance$", WAFVendor.CLOUDFLARE, ConfidenceLevel.DEFINITIVE, "Cloudflare clearance cookie"),
        ("^_cfduid$", WAFVendor.CLOUDFLARE, ConfidenceLevel.HIGH, "Cloudflare UID cookie variant"),
        ("^cf_ob_info$", WAFVendor.CLOUDFLARE, ConfidenceLevel.HIGH, "Cloudflare observer info cookie"),

        ("^akamai_\w+$", WAFVendor.AKAMAI, ConfidenceLevel.HIGH, "Akamai cookie pattern"),
        ("^_abck$", WAFVendor.AKAMAI, ConfidenceLevel.DEFINITIVE, "Akamai bot management cookie"),
        ("^ak_bmsc$", WAFVendor.AKAMAI_KONA, ConfidenceLevel.HIGH, "Akamai Kona BM cookie"),
        ("^bm_sz$", WAFVendor.AKAMAI_KONA, ConfidenceLevel.HIGH, "Akamai Kona BM size cookie"),

        ("^AWSALB\w*$", WAFVendor.AWS_WAF, ConfidenceLevel.HIGH, "AWS ALB cookie pattern"),
        ("^AWSALBCORS\w*$", WAFVendor.AWS_WAF, ConfidenceLevel.HIGH, "AWS ALB CORS cookie"),
        ("^awswaf\w*$", WAFVendor.AWS_WAF, ConfidenceLevel.HIGH, "AWS WAF cookie pattern"),

        ("^ARRAffinity\w*$", WAFVendor.AZURE_WAF, ConfidenceLevel.HIGH, "Azure ARR Affinity cookie"),

        ("^incap_ses_\w+$", WAFVendor.IMPERVA, ConfidenceLevel.DEFINITIVE, "Incapsula session cookie"),
        ("^visid_incap_\w+$", WAFVendor.IMPERVA, ConfidenceLevel.DEFINITIVE, "Incapsula visitor ID cookie"),
        ("^releases_visitor$", WAFVendor.IMPERVA, ConfidenceLevel.HIGH, "Imperva releases visitor cookie"),
        ("^x-visit-id$", WAFVendor.IMPERVA, ConfidenceLevel.HIGH, "Imperva visit ID cookie"),

        ("^F5_\w+$", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 cookie pattern"),
        ("^BIGipServer\w*$", WAFVendor.F5_ASM, ConfidenceLevel.DEFINITIVE, "F5 BIG-IP server cookie"),
        ("^LastMRH_Session$", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 MRH session cookie"),
        ("^MRHSHint$", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 MRH hint cookie"),
        ("^F5_fullWT$", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 full web tunnel cookie"),
        ("^persist_cookie$", WAFVendor.F5_ASM, ConfidenceLevel.MEDIUM, "F5 persistence cookie"),

        ("^ns_af_\w+$", WAFVendor.CITRIX, ConfidenceLevel.HIGH, "Citrix cookie pattern"),
        ("^citrix_ns_id$", WAFVendor.CITRIX, ConfidenceLevel.HIGH, "Citrix NS ID cookie"),
        ("^CITRIXNS_\w+$", WAFVendor.CITRIX, ConfidenceLevel.HIGH, "Citrix NS cookie pattern"),

        ("^barra_counter_session$", WAFVendor.BARRACUDA, ConfidenceLevel.DEFINITIVE, "Barracuda session cookie"),
        ("^BARRACUDA_\w+$", WAFVendor.BARRACUDA, ConfidenceLevel.HIGH, "Barracuda cookie pattern"),
        ("^barraid$", WAFVendor.BARRACUDA, ConfidenceLevel.DEFINITIVE, "Barracuda ID cookie"),

        ("^fortigateid$", WAFVendor.FORTINET, ConfidenceLevel.DEFINITIVE, "Fortinet ID cookie"),
        ("^FNWAB_\w+$", WAFVendor.FORTINET, ConfidenceLevel.HIGH, "Fortinet WAB cookie"),

        ("^sucuri_cloudproxy_\w+$", WAFVendor.SUCURI, ConfidenceLevel.DEFINITIVE, "Sucuri cloudproxy cookie"),

        ("^wordfence_verifiedHuman$", WAFVendor.WORDFENCE, ConfidenceLevel.DEFINITIVE, "Wordfence human verification"),

        ("^_rwdid$", WAFVendor.RADWARE, ConfidenceLevel.DEFINITIVE, "Radware DID cookie"),
        ("^_rwcsrf$", WAFVendor.RADWARE, ConfidenceLevel.HIGH, "Radware CSRF cookie"),

        ("^wallarm_\w+$", WAFVendor.WALLARM, ConfidenceLevel.HIGH, "Wallarm cookie pattern"),
        ("^ngw_\w+$", WAFVendor.WALLARM, ConfidenceLevel.HIGH, "Wallarm nginx cookie"),

        ("^qrator_jsid$", WAFVendor.QRATOR, ConfidenceLevel.DEFINITIVE, "QRator JS cookie"),
        ("^qrator_ssid$", WAFVendor.QRATOR, ConfidenceLevel.HIGH, "QRator session cookie"),

        ("^sp_\w+$", WAFVendor.STACKPATH, ConfidenceLevel.MEDIUM, "StackPath cookie pattern"),

        ("^SOPHOS_\w+$", WAFVendor.SOPHOS, ConfidenceLevel.HIGH, "Sophos cookie pattern"),
        ("^sophos_\w+$", WAFVendor.SOPHOS, ConfidenceLevel.HIGH, "Sophos cookie pattern (lowercase)"),

        ("^ZSCALER_\w+$", WAFVendor.ZSCALER, ConfidenceLevel.HIGH, "Zscaler cookie pattern"),

        ("^cprequestid$", WAFVendor.CHECK_POINT, ConfidenceLevel.HIGH, "Check Point request ID cookie"),
        ("^CISCO_FTD_", WAFVendor.CISCO_FTD, ConfidenceLevel.HIGH, "Cisco FTD cookie prefix"),
        ("^acs-waf-session-id$", WAFVendor.YUNDUN, ConfidenceLevel.DEFINITIVE, "Aliyun WAF session"),
        ("^sl-session$", WAFVendor.SAFELINE, ConfidenceLevel.HIGH, "Safeline session cookie"),
    ]

    # Body fingerprint signatures: (pattern, vendor, confidence, description)
    BODY_SIGNATURES: List[Tuple[str, WAFVendor, ConfidenceLevel, str]] = [
        # Cloudflare
        (r"(?i)attention required.*cloudflare", WAFVendor.CLOUDFLARE, ConfidenceLevel.DEFINITIVE,
         "Cloudflare attention page"),
        (r"(?i)cloudflare.*ray id", WAFVendor.CLOUDFLARE, ConfidenceLevel.DEFINITIVE, "Cloudflare Ray ID in body"),
        (r"(?i)cf-ray.*</", WAFVendor.CLOUDFLARE, ConfidenceLevel.DEFINITIVE, "CF-Ray in body"),
        (r"(?i)cloudflare.*challenge.*platform", WAFVendor.CLOUDFLARE, ConfidenceLevel.DEFINITIVE,
         "Cloudflare challenge platform"),
        (r"(?i)checking.*browser.*cloudflare", WAFVendor.CLOUDFLARE, ConfidenceLevel.DEFINITIVE,
         "Cloudflare browser check"),
        (r"(?i)cdn\.cloudflare\.com", WAFVendor.CLOUDFLARE, ConfidenceLevel.HIGH, "Cloudflare CDN domain in body"),
        (r"(?i)challenge-platform.*cloudflare", WAFVendor.CLOUDFLARE, ConfidenceLevel.HIGH,
         "Cloudflare challenge platform"),
        (r"(?i)cf-browser-verification", WAFVendor.CLOUDFLARE, ConfidenceLevel.HIGH, "Cloudflare browser verification"),
        (r"(?i)jschl_vc|jschl_answer", WAFVendor.CLOUDFLARE, ConfidenceLevel.HIGH, "Cloudflare JS challenge variables"),
        (r"(?i)turnstile.*cloudflare", WAFVendor.CLOUDFLARE, ConfidenceLevel.HIGH, "Cloudflare Turnstile"),

        # Akamai & Akamai Kona
        (r"(?i)akamai.*detected.*unusual", WAFVendor.AKAMAI, ConfidenceLevel.HIGH, "Akamai unusual activity detection"),
        (r"(?i)akamai.*blocked.*request", WAFVendor.AKAMAI, ConfidenceLevel.HIGH, "Akamai blocked request"),
        (r"(?i)access.*denied.*akamai", WAFVendor.AKAMAI, ConfidenceLevel.HIGH, "Akamai access denied"),
        (r"(?i)akamai.*gbot|bot.*manager", WAFVendor.AKAMAI, ConfidenceLevel.HIGH, "Akamai bot manager"),
        (r"(?i)_abck.*akamai", WAFVendor.AKAMAI, ConfidenceLevel.HIGH, "Akamai _abck in body"),
        (r"(?i)iecdn\d*\.akamaihd\.net", WAFVendor.AKAMAI, ConfidenceLevel.HIGH, "Akamai CDN domain"),
        (r"(?i)akamai.*kona.*client.*security", WAFVendor.AKAMAI_KONA, ConfidenceLevel.DEFINITIVE,
         "Akamai Kona Client Security"),
        (r"(?i)akamai.*astra", WAFVendor.AKAMAI_KONA, ConfidenceLevel.HIGH, "Akamai ASTRA bot protection"),

        # AWS WAF
        (r"(?i)aws.*waf.*blocked", WAFVendor.AWS_WAF, ConfidenceLevel.HIGH, "AWS WAF blocked message"),
        (r"(?i)request.*blocked.*aws", WAFVendor.AWS_WAF, ConfidenceLevel.HIGH, "AWS blocked request"),
        (r"(?i)awselb.*error", WAFVendor.AWS_WAF, ConfidenceLevel.MEDIUM, "AWS ELB error"),

        # Azure WAF
        (r"(?i)microsoft azure.*application gateway", WAFVendor.AZURE_WAF, ConfidenceLevel.DEFINITIVE,
         "Azure App Gateway WAF"),
        (r"(?i)request.*blocked.*azure", WAFVendor.AZURE_WAF, ConfidenceLevel.HIGH, "Azure blocked request"),
        (r"(?i)error.*403.*front door", WAFVendor.AZURE_WAF, ConfidenceLevel.HIGH, "Azure Front Door block"),
        (r"(?i)the requested url.*rejected.*azure", WAFVendor.AZURE_WAF, ConfidenceLevel.DEFINITIVE,
         "Azure URL rejected"),

        # Google Cloud Armor
        (r"(?i)blocked by cloud armor", WAFVendor.GOOGLE_CLOUD_ARMOR, ConfidenceLevel.DEFINITIVE,
         "Cloud Armor block message"),
        (r"(?i)google cloud platform.*error", WAFVendor.GOOGLE_CLOUD_ARMOR, ConfidenceLevel.HIGH, "GCP Error page"),
        (r"(?i)403 forbidden.*google", WAFVendor.GOOGLE_CLOUD_ARMOR, ConfidenceLevel.MEDIUM, "Google 403 block"),

        # Check Point
        (r"(?i)check point.*security gateway", WAFVendor.CHECK_POINT, ConfidenceLevel.DEFINITIVE,
         "Check Point Security Gateway"),
        (r"(?i)check point.*blocked", WAFVendor.CHECK_POINT, ConfidenceLevel.HIGH, "Check Point blocked"),
        (r"(?i)web application.*firewall.*check point", WAFVendor.CHECK_POINT, ConfidenceLevel.HIGH,
         "Check Point WAF reference"),

        # Cisco FTD
        (r"(?i)cisco.*firepower.*blocked", WAFVendor.CISCO_FTD, ConfidenceLevel.DEFINITIVE, "Cisco Firepower blocked"),
        (r"(?i)requested url was rejected.*cisco", WAFVendor.CISCO_FTD, ConfidenceLevel.DEFINITIVE,
         "Cisco FTD URL rejected"),
        (r"(?i)contact your system administrator.*cisco", WAFVendor.CISCO_FTD, ConfidenceLevel.HIGH,
         "Cisco FTD admin warning"),

        # Imperva
        (r"(?i)incapsula.*incident", WAFVendor.IMPERVA, ConfidenceLevel.DEFINITIVE, "Incapsula incident page"),
        (r"(?i)incapsula.*blocked", WAFVendor.IMPERVA, ConfidenceLevel.DEFINITIVE, "Incapsula blocked page"),
        (r"(?i)imperva.*shield", WAFVendor.IMPERVA, ConfidenceLevel.HIGH, "Imperva shield reference"),
        (r"(?i)incap_ses", WAFVendor.IMPERVA, ConfidenceLevel.HIGH, "Incapsula session reference"),
        (r"(?i)client.*blocked.*imperva", WAFVendor.IMPERVA, ConfidenceLevel.HIGH, "Imperva client blocked"),
        (r"(?i)visid_incap", WAFVendor.IMPERVA, ConfidenceLevel.HIGH, "Incapsula visid reference"),
        (r"(?i)imunify360", WAFVendor.IMPERVA, ConfidenceLevel.HIGH, "Imunify360 (Imperva)"),

        # ModSecurity
        (r"(?i)mod_security.*action", WAFVendor.MODSECURITY, ConfidenceLevel.HIGH, "ModSecurity action reference"),
        (r"(?i)modsecurity.*rule", WAFVendor.MODSECURITY, ConfidenceLevel.HIGH, "ModSecurity rule reference"),
        (r"(?i)access.*denied.*rule.*\d+", WAFVendor.MODSECURITY, ConfidenceLevel.MEDIUM, "Generic rule denial"),
        (r"(?i)rule.*id.*\d{4,}", WAFVendor.MODSECURITY, ConfidenceLevel.MEDIUM, "Rule ID pattern"),
        (r"(?i)OWASP.*CRS", WAFVendor.MODSECURITY, ConfidenceLevel.HIGH, "OWASP Core Rule Set"),
        (r"(?i)modsecurity.*web.*application.*firewall", WAFVendor.MODSECURITY, ConfidenceLevel.HIGH,
         "ModSecurity WAF name"),

        # F5
        (r"(?i)big-ip.*blocked", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 BIG-IP blocked"),
        (r"(?i)request.*denied.*f5", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 denied request"),
        (r"(?i)traffic.*management.*f5", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 traffic management"),
        (r"(?i)ASM.*blocked.*request", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 ASM block"),
        (r"(?i)F5.*Networks", WAFVendor.F5_ASM, ConfidenceLevel.HIGH, "F5 Networks reference"),
        (r"(?i)system.*unavailable.*bigip", WAFVendor.F5_ASM, ConfidenceLevel.MEDIUM, "BIG-IP unavailable"),

        # Citrix
        (r"(?i)citrix.*gateway.*error", WAFVendor.CITRIX, ConfidenceLevel.HIGH, "Citrix gateway error"),
        (r"(?i)citrix.*blocked", WAFVendor.CITRIX, ConfidenceLevel.HIGH, "Citrix blocked"),
        (r"(?i)netscaler.*error", WAFVendor.CITRIX, ConfidenceLevel.HIGH, "NetScaler error"),

        # Barracuda
        (r"(?i)barracuda.*blocked", WAFVendor.BARRACUDA, ConfidenceLevel.HIGH, "Barracuda blocked"),
        (r"(?i)barracuda.*networks", WAFVendor.BARRACUDA, ConfidenceLevel.HIGH, "Barracuda Networks reference"),
        (r"(?i)request.*blocked.*barracuda", WAFVendor.BARRACUDA, ConfidenceLevel.HIGH, "Barracuda request blocked"),
        (r"(?i)Message: Request blocked by Barracuda", WAFVendor.BARRACUDA, ConfidenceLevel.DEFINITIVE,
         "Barracuda block message"),

        # Fortinet
        (r"(?i)fortiweb.*blocked", WAFVendor.FORTINET, ConfidenceLevel.HIGH, "FortiWeb blocked"),
        (r"(?i)fortinet.*blocked", WAFVendor.FORTINET, ConfidenceLevel.HIGH, "Fortinet blocked"),
        (r"(?i)fortigate.*blocked", WAFVendor.FORTINET, ConfidenceLevel.HIGH, "FortiGate blocked"),

        # Sucuri
        (r"(?i)sucuri.*blocked", WAFVendor.SUCURI, ConfidenceLevel.HIGH, "Sucuri blocked"),
        (r"(?i)cloudproxy.*sucuri", WAFVendor.SUCURI, ConfidenceLevel.HIGH, "Sucuri cloudproxy"),
        (r"(?i)sucuri.*firewall", WAFVendor.SUCURI, ConfidenceLevel.HIGH, "Sucuri firewall"),
        (r"(?i)website.*firewall.*sucuri", WAFVendor.SUCURI, ConfidenceLevel.HIGH, "Sucuri website firewall"),

        # Wordfence
        (r"(?i)wordfence.*blocked", WAFVendor.WORDFENCE, ConfidenceLevel.HIGH, "Wordfence blocked"),
        (r"(?i)wordfence.*firewall", WAFVendor.WORDFENCE, ConfidenceLevel.HIGH, "Wordfence firewall"),
        (r"(?i)human.*verification.*wordfence", WAFVendor.WORDFENCE, ConfidenceLevel.HIGH,
         "Wordfence human verification"),

        # Radware
        (r"(?i)radware.*blocked", WAFVendor.RADWARE, ConfidenceLevel.HIGH, "Radware blocked"),
        (r"(?i)radware.*protection", WAFVendor.RADWARE, ConfidenceLevel.HIGH, "Radware protection"),

        # Wallarm
        (r"(?i)wallarm.*blocked", WAFVendor.WALLARM, ConfidenceLevel.HIGH, "Wallarm blocked"),
        (r"(?i)wallarm.*detected", WAFVendor.WALLARM, ConfidenceLevel.HIGH, "Wallarm detected"),
        (r"(?i)request.*wallarm", WAFVendor.WALLARM, ConfidenceLevel.MEDIUM, "Wallarm request reference"),

        # QRator
        (r"(?i)qrator.*blocked", WAFVendor.QRATOR, ConfidenceLevel.HIGH, "QRator blocked"),
        (r"(?i)qrator.*protection", WAFVendor.QRATOR, ConfidenceLevel.HIGH, "QRator protection"),

        # Yundun (Alibaba Cloud)
        (r"(?i)yundun.*web.*application.*firewall", WAFVendor.YUNDUN, ConfidenceLevel.DEFINITIVE,
         "Yundun WAF block page"),
        (r"(?i)error.*aliyun.*waf", WAFVendor.YUNDUN, ConfidenceLevel.HIGH, "Aliyun WAF error"),
        (r"(?i)malicious request.*yundun", WAFVendor.YUNDUN, ConfidenceLevel.HIGH, "Yundun malicious request"),
        (r"(?i)阿里云.*web应用防火墙", WAFVendor.YUNDUN, ConfidenceLevel.DEFINITIVE, "Yundun Chinese block page"),

        # Safeline (Chaitin Tech)
        (r"(?i)safeline.*intercepted", WAFVendor.SAFELINE, ConfidenceLevel.DEFINITIVE, "Safeline intercepted page"),
        (r"(?i)chaitin tech.*safeline", WAFVendor.SAFELINE, ConfidenceLevel.DEFINITIVE, "Chaitin Safeline block"),
        (r"(?i)长亭.*安全防护", WAFVendor.SAFELINE, ConfidenceLevel.DEFINITIVE, "Safeline Chinese block page"),

        # Generic patterns
        (r"(?i)web.*application.*firewall.*blocked", WAFVendor.UNKNOWN, ConfidenceLevel.MEDIUM, "Generic WAF blocked"),
        (r"(?i)request.*blocked.*security", WAFVendor.UNKNOWN, ConfidenceLevel.LOW, "Generic security block"),
        (r"(?i)suspicious.*request.*blocked", WAFVendor.UNKNOWN, ConfidenceLevel.LOW, "Generic suspicious block"),
        (r"(?i)detected.*malicious.*request", WAFVendor.UNKNOWN, ConfidenceLevel.LOW, "Generic malicious detection"),
        (r"(?i)security.*policy.*violation", WAFVendor.UNKNOWN, ConfidenceLevel.LOW, "Security policy violation"),
        (r"(?i)403.*forbidden.*waf", WAFVendor.UNKNOWN, ConfidenceLevel.LOW, "403 with WAF reference"),
    ]

    # Behavioral probes - safe payloads that trigger WAF without actual attacks
    BEHAVIORAL_PROBES: List[Tuple[str, str, Dict[str, Any]]] = [
        ("param", "' OR '1'='1", {"expected_block": True, "category": "sqli"}),
        ("param", "1; SELECT", {"expected_block": True, "category": "sqli"}),
        ("param", "1 UNION SELECT", {"expected_block": True, "category": "sqli"}),
        ("param", "<script>alert(1)</script>", {"expected_block": True, "category": "xss"}),
        ("param", "javascript:alert(1)", {"expected_block": True, "category": "xss"}),
        ("param", "<img src=x onerror=alert(1)>", {"expected_block": True, "category": "xss"}),
        ("path", "../../../etc/passwd", {"expected_block": True, "category": "lfi"}),
        ("path", "..\\..\\..\\windows\\system32", {"expected_block": True, "category": "lfi"}),
        ("param", "; ls -la", {"expected_block": True, "category": "rce"}),
        ("param", "| cat /etc/passwd", {"expected_block": True, "category": "rce"}),
        ("param", "http://127.0.0.1", {"expected_block": True, "category": "ssrf"}),
        ("param", "http://localhost", {"expected_block": True, "category": "ssrf"}),
    ]

    # Bypass strategies per vendor
    BYPASS_STRATEGIES: Dict[WAFVendor, List[str]] = {
        WAFVendor.CLOUDFLARE: [
            "use_headless_browser for JS challenges",
            "implement proper TLS fingerprint (JA3)",
            "solve Turnstile challenge programmatically",
            "maintain cf_clearance cookie across requests",
            "use HTTP/2 with proper SETTINGS frame",
            "respect rate limits strictly",
            "avoid automated user-agent patterns",
            "use residential proxy IPs",
        ],
        WAFVendor.AKAMAI: [
            "solve _abck sensor data challenge",
            "implement proper bot manager evasion",
            "use consistent TLS fingerprint",
            "maintain cookie jar across session",
            "mimic real browser frame ordering",
            "avoid rapid sequential requests",
            "implement proper HTTP/2 priorities",
        ],
        WAFVendor.AKAMAI_KONA: [
            "solve _abck and Akamai sensor data challenges (Polaris/Bot Manager)",
            "maintain consistent HTTP/2 SETTINGS and priority frames",
            "use consistent TLS fingerprinting; do not swap mid-session",
            "mimic real browser frame ordering exactly"
        ],
        WAFVendor.AWS_WAF: [
            "encode payloads with multiple layers",
            "use chunked transfer encoding",
            "vary parameter names",
            "use HTTP parameter pollution",
            "leverage AWS-specific bypasses",
            "test different regions/endpoints",
        ],
        WAFVendor.AZURE_WAF: [
            "Azure WAF (Front Door/App Gateway) is sensitive to encoding anomalies; use standard encoding",
            "bypass via HTTP/2 pseudo-header manipulation",
            "test payload fragmentation across multiple parameters",
            "Azure WAF has strict size limits; sometimes large payloads bypass length checks"
        ],
        WAFVendor.GOOGLE_CLOUD_ARMOR: [
            "Cloud Armor relies heavily on regex; use Unicode normalization tricks",
            "bypass via request smuggling if behind GCP Load Balancer",
            "test for IP allowlisting bypasses (X-Forwarded-For spoofing if misconfigured)"
        ],
        WAFVendor.CHECK_POINT: [
            "use encoding variations to bypass signature matching",
            "exploit HTTP parameter pollution",
            "test specific policy bypasses",
            "fragment payloads across headers and body"
        ],
        WAFVendor.CISCO_FTD: [
            "bypass via HTTP/2 pseudo-headers",
            "use parameter name obfuscation",
            "test FTD specific rule ordering gaps",
            "fragment payloads across multiple parameters"
        ],
        WAFVendor.IMPERVA: [
            "bypass X-IInfo validation",
            "handle Incapsula script challenges",
            "maintain proper cookie sequence",
            "use proper TLS fingerprinting",
            "vary request patterns",
        ],
        WAFVendor.MODSECURITY: [
            "use encoding chains (double URL encode)",
            "HTTP parameter pollution",
            "exploit rule ordering gaps",
            "use multipart form bypasses",
            "test specific CRS rule versions",
            "use Unicode normalization tricks",
        ],
        WAFVendor.F5_ASM: [
            "parse BIGipServer cookie for internal IPs",
            "use parameter name obfuscation",
            "test ASM policy bypass techniques",
            "vary HTTP methods",
            "use HTTP/2 pseudo-headers",
        ],
        WAFVendor.CITRIX: [
            "exploit NetScaler configuration gaps",
            "test URL decoding variations",
            "use HTTP smuggling techniques",
            "test specific policy bypasses",
        ],
        WAFVendor.BARRACUDA: [
            "use encoding variations",
            "test multipart boundaries",
            "exploit header parsing differences",
        ],
        WAFVendor.WORDFENCE: [
            "handle rate limiting carefully",
            "use proper cookie handling",
            "test firewall rule exclusions",
            "vary request patterns",
        ],
        WAFVendor.YUNDUN: [
            "often bypassed with double URL encoding",
            "test HTTP/1.1 vs HTTP/2 protocol discrepancies",
            "Yundun is highly sensitive to specific Chinese charset payloads; use standard Latin payloads first"
        ],
        WAFVendor.SAFELINE: [
            "Safeline uses advanced semantic analysis; avoid obvious syntax errors in payloads",
            "test JSON-based payloads with unusual whitespace formatting",
            "bypass via parameter pollution or array payloads (param[]=value)"
        ],
        WAFVendor.UNKNOWN: [
            "try general encoding chains",
            "test HTTP/2 specific bypasses",
            "use headless browser fallback",
            "implement rate limit adaptation",
        ],
    }


class WAFDetector:
    """
    WAF Detection Engine

    Analyzes HTTP responses to identify Web Application Firewall products
    and provides bypass strategy recommendations.
    """

    def __init__(self, http_client=None, options: Optional[Dict[str, Any]] = None):
        self.http_client = http_client
        self.signature_db = WAFSignatureDatabase()
        self.options = options or {}

        self.behavioral_probing = self.options.get("behavioral_probing", False)
        self.max_probes = self.options.get("max_probes", 5)
        self.probe_delay = self.options.get("probe_delay", 1.0)
        self.body_scan = self.options.get("body_scan", True)
        self.max_body_size = self.options.get("max_body_size", 100000)

        self._detection_cache: Dict[str, WAFDetectionResult] = {}
        self._probe_history: List[Dict[str, Any]] = []

    async def detect(self, response, url: str = "") -> WAFDetectionResult:
        result = WAFDetectionResult(
            detected=False,
            scan_metadata={"url": url, "timestamp": time.time()}
        )

        header_profiles = self._analyze_headers(response)
        cookie_profiles = self._analyze_cookies(response)
        body_profiles = self._analyze_body(response) if self.body_scan else []

        all_profiles = header_profiles + cookie_profiles + body_profiles

        if not all_profiles:
            result.recommendations.append("No WAF detected - target appears clean")
            return result

        vendor_profiles = self._consolidate_profiles(all_profiles)
        sorted_profiles = sorted(vendor_profiles.values(), key=lambda p: p.confidence.value, reverse=True)

        if sorted_profiles:
            result.detected = True
            result.primary_profile = sorted_profiles[0]
            result.secondary_profiles = sorted_profiles[1:]
            self._enrich_with_bypass_strategies(result)
            self._generate_recommendations(result)

        return result

    async def detect_with_probing(self, url: str, normal_response=None) -> WAFDetectionResult:
        if self.http_client is None:
            logger.warning("No HTTP client provided, falling back to static detection")
            return await self.detect(normal_response, url) if normal_response else WAFDetectionResult(
                detected=False, scan_metadata={"url": url, "error": "no_http_client"}
            )

        result = WAFDetectionResult(detected=False, scan_metadata={"url": url, "timestamp": time.time()})
        static_result = WAFDetectionResult(detected=False)

        if normal_response:
            static_result = await self.detect(normal_response, url)
            if static_result.detected:
                return static_result

        if self.behavioral_probing:
            behavioral_result = await self._perform_behavioral_probing(url)
            if behavioral_result.detected:
                if normal_response and static_result.detected:
                    self._merge_results(result, static_result, behavioral_result)
                else:
                    result = behavioral_result
                return result

        return static_result if normal_response else result

    def _analyze_headers(self, response) -> List[WAFProfile]:
        profiles = []
        headers = self._get_headers_dict(response)

        for header_name, pattern, vendor, confidence, description in self.signature_db.HEADER_SIGNATURES:
            header_value = headers.get(header_name.lower(), "")
            if header_value and re.search(pattern, header_value):
                profiles.append(WAFProfile(
                    vendor=vendor, confidence=confidence,
                    detection_methods=[DetectionMethod.HEADER],
                    detected_signatures=[f"{header_name}: {pattern}"],
                    characteristics={"header_name": header_name, "header_value": header_value[:100]},
                    raw_evidence=[(header_name, header_value[:200])]
                ))
        return profiles

    def _analyze_cookies(self, response) -> List[WAFProfile]:
        profiles = []
        cookies = self._get_cookies(response)

        for cookie_pattern, vendor, confidence, description in self.signature_db.COOKIE_SIGNATURES:
            for cookie_name in cookies:
                if re.match(cookie_pattern, cookie_name):
                    profiles.append(WAFProfile(
                        vendor=vendor, confidence=confidence,
                        detection_methods=[DetectionMethod.COOKIE],
                        detected_signatures=[f"cookie: {cookie_pattern}"],
                        characteristics={"cookie_name": cookie_name},
                        raw_evidence=[("set-cookie", cookie_name)]
                    ))
                    break
        return profiles

    def _analyze_body(self, response) -> List[WAFProfile]:
        profiles = []
        body = self._get_body(response)
        if not body: return profiles

        body_text = body[:self.max_body_size]
        for pattern, vendor, confidence, description in self.signature_db.BODY_SIGNATURES:
            match = re.search(pattern, body_text, re.IGNORECASE | re.DOTALL)
            if match:
                context = body_text[max(0, match.start() - 50):match.end() + 50]
                profiles.append(WAFProfile(
                    vendor=vendor, confidence=confidence,
                    detection_methods=[DetectionMethod.BODY_FINGERPRINT],
                    detected_signatures=[f"body: {pattern}"],
                    characteristics={"body_context": context[:200]},
                    raw_evidence=[("body_match", context[:200])]
                ))
        return profiles

    async def _perform_behavioral_probing(self, url: str) -> WAFDetectionResult:
        result = WAFDetectionResult(detected=False, scan_metadata={"url": url, "method": "behavioral"})
        parsed_url = urlparse(url)
        base_path = parsed_url.path or "/"
        query = parsed_url.query
        probes_sent = 0
        blocked_count = 0
        block_indicators = []

        for param_name, payload, probe_info in self.signature_db.BEHAVIORAL_PROBES:
            if probes_sent >= self.max_probes: break

            if probe_info["category"] == "lfi" and param_name == "path":
                probe_path = f"{base_path}{payload}"
                probe_url = f"{parsed_url.scheme}://{parsed_url.netloc}{probe_path}"
            else:
                separator = "&" if query else "?"
                probe_url = f"{parsed_url.scheme}://{parsed_url.netloc}{base_path}{separator}{param_name}={payload}"

            try:
                response = await self.http_client.get(probe_url)
                probes_sent += 1
                self._probe_history.append(
                    {"url": probe_url, "status": response.status_code, "category": probe_info["category"],
                     "timestamp": time.time()})

                if self._is_blocked_response(response):
                    blocked_count += 1
                    block_indicators.append({"category": probe_info["category"], "status": response.status_code,
                                             "evidence": self._extract_block_evidence(response)})
                    block_result = await self.detect(response, probe_url)
                    if block_result.detected and block_result.primary_profile:
                        block_result.primary_profile.detection_methods.append(DetectionMethod.BEHAVIORAL)
                        if not result.detected:
                            result = block_result
                        else:
                            result.primary_profile.detection_methods.extend(
                                block_result.primary_profile.detection_methods)

                if probes_sent < self.max_probes: await asyncio.sleep(self.probe_delay)
            except Exception as e:
                logger.debug(f"Probe failed: {e}")
                continue

        if blocked_count > 0 and not result.detected:
            block_ratio = blocked_count / probes_sent if probes_sent > 0 else 0
            if block_ratio > 0.5:
                result.detected = True
                result.primary_profile = WAFProfile(
                    vendor=WAFVendor.UNKNOWN, confidence=ConfidenceLevel.MEDIUM,
                    detection_methods=[DetectionMethod.BEHAVIORAL],
                    detected_signatures=["behavioral_blocking_detected"],
                    characteristics={"block_ratio": block_ratio, "probes_sent": probes_sent,
                                     "blocked_count": blocked_count,
                                     "blocked_categories": [b["category"] for b in block_indicators]},
                    raw_evidence=[(f"probe_{i}", str(b)) for i, b in enumerate(block_indicators)]
                )

        result.scan_metadata["probes_sent"] = probes_sent
        result.scan_metadata["blocked_count"] = blocked_count
        return result

    def _is_blocked_response(self, response) -> bool:
        if response.status_code in (403, 406, 429, 503): return True
        headers = self._get_headers_dict(response)
        body = self._get_body(response) or ""
        block_headers = ["x-waf-block", "x-waf-event", "x-waf-status", "x-modsecurity-rule-id", "x-wallarm-blocked",
                         "x-sucuri-id", "x-wordfence-blocked"]
        for header in block_headers:
            if header in headers: return True
        block_phrases = ["blocked", "denied", "forbidden", "security", "firewall", "detected", "malicious",
                         "suspicious"]
        for phrase in block_phrases:
            if phrase.lower() in body.lower()[:5000]: return True
        return False

    def _extract_block_evidence(self, response) -> Dict[str, Any]:
        evidence = {"status": response.status_code, "headers": {}, "body_snippet": ""}
        headers = self._get_headers_dict(response)
        for key, value in headers.items():
            if any(k in key.lower() for k in ["waf", "block", "security", "modsecurity", "firewall"]):
                evidence["headers"][key] = value[:200]
        body = self._get_body(response) or ""
        evidence["body_snippet"] = body[:500]
        return evidence

    def _consolidate_profiles(self, profiles: List[WAFProfile]) -> Dict[WAFVendor, WAFProfile]:
        consolidated = {}
        for profile in profiles:
            vendor = profile.vendor
            if vendor not in consolidated:
                consolidated[vendor] = WAFProfile(vendor=vendor, confidence=profile.confidence, detection_methods=[],
                                                  detected_signatures=[], raw_evidence=[])

            if profile.confidence.value > consolidated[vendor].confidence.value:
                consolidated[vendor].confidence = profile.confidence
            consolidated[vendor].detection_methods.extend(
                m for m in profile.detection_methods if m not in consolidated[vendor].detection_methods)
            consolidated[vendor].detected_signatures.extend(
                s for s in profile.detected_signatures if s not in consolidated[vendor].detected_signatures)
            consolidated[vendor].raw_evidence.extend(profile.raw_evidence)
            consolidated[vendor].characteristics.update(profile.characteristics)

        for profile in consolidated.values():
            if len(profile.detection_methods) >= 2 and profile.confidence.value < ConfidenceLevel.HIGH.value:
                profile.confidence = ConfidenceLevel.HIGH
            if len(profile.detection_methods) >= 3 and profile.confidence.value < ConfidenceLevel.DEFINITIVE.value:
                profile.confidence = ConfidenceLevel.DEFINITIVE
        return consolidated

    def _enrich_with_bypass_strategies(self, result: WAFDetectionResult):
        for profile in [result.primary_profile] + result.secondary_profiles:
            if profile and profile.vendor in self.signature_db.BYPASS_STRATEGIES:
                profile.bypass_strategies = self.signature_db.BYPASS_STRATEGIES[profile.vendor]

    def _generate_recommendations(self, result: WAFDetectionResult):
        if not result.primary_profile: return
        profile = result.primary_profile

        if profile.confidence.value >= ConfidenceLevel.HIGH.value:
            result.recommendations.append(
                f"High confidence {profile.vendor.value} detection - implement specific evasion strategies")
        else:
            result.recommendations.append(f"Possible {profile.vendor.value} WAF - verify with additional probing")

        if DetectionMethod.BEHAVIORAL in profile.detection_methods:
            result.recommendations.append("Behavioral blocking detected - use adaptive timing and payload encoding")
        if DetectionMethod.HEADER in profile.detection_methods:
            result.recommendations.append("WAF identified via headers - consider using header normalization")

        vendor_specific = {
            WAFVendor.CLOUDFLARE: "Cloudflare detected: JS challenge solving and TLS fingerprinting are critical",
            WAFVendor.AKAMAI: "Akamai detected: Bot manager sensor data must be properly generated",
            WAFVendor.AKAMAI_KONA: "Akamai Kona detected: Polaris sensor data generation is required",
            WAFVendor.MODSECURITY: "ModSecurity detected: OWASP CRS version identification can help find rule gaps",
            WAFVendor.YUNDUN: "Yundun detected: Double URL encoding and protocol discrepancies often succeed",
            WAFVendor.SAFELINE: "Safeline detected: Advanced semantic analysis requires clean syntax and parameter pollution",
        }

        if profile.vendor in vendor_specific:
            result.recommendations.append(vendor_specific[profile.vendor])

    def _merge_results(self, target: WAFDetectionResult, static: WAFDetectionResult, behavioral: WAFDetectionResult):
        target.detected = True
        target.scan_metadata["methods_used"] = ["static", "behavioral"]
        if static.primary_profile and static.primary_profile.confidence.value >= ConfidenceLevel.HIGH.value:
            target.primary_profile = static.primary_profile
        elif behavioral.primary_profile:
            target.primary_profile = behavioral.primary_profile
        else:
            target.primary_profile = static.primary_profile

        secondary_vendors = set()
        for profile in (static.secondary_profiles + behavioral.secondary_profiles):
            if profile.vendor not in secondary_vendors:
                target.secondary_profiles.append(profile)
                secondary_vendors.add(profile.vendor)

    def _get_headers_dict(self, response) -> Dict[str, str]:
        headers = {}
        if hasattr(response, "headers"):
            if hasattr(response.headers, "items"):
                for k, v in response.headers.items(): headers[k.lower()] = v
            elif isinstance(response.headers, dict):
                for k, v in response.headers.items(): headers[k.lower()] = str(v)
        return headers

    def _get_cookies(self, response) -> List[str]:
        cookies = []
        headers = self._get_headers_dict(response)
        for header_name, header_value in headers.items():
            if "cookie" in header_name:
                for cookie_str in header_value.split(","):
                    cookie_name = cookie_str.split("=")[0].strip()
                    if cookie_name: cookies.append(cookie_name)
        return cookies

    def _get_body(self, response) -> Optional[str]:
        if hasattr(response, "text"):
            return response.text
        elif hasattr(response, "body"):
            body = response.body
            return body.decode("utf-8", errors="ignore") if isinstance(body, bytes) else str(body)
        elif hasattr(response, "content"):
            content = response.content
            return content.decode("utf-8", errors="ignore") if isinstance(content, bytes) else str(content)
        return None

    def get_detection_summary(self, result: WAFDetectionResult) -> str:
        if not result.detected: return "No WAF detected"
        lines = [
            f"WAF Detected: {result.primary_profile.vendor.value}",
            f"Confidence: {result.primary_profile.confidence.name}",
            f"Detection Methods: {', '.join(m.value for m in result.primary_profile.detection_methods)}",
        ]
        if result.primary_profile.bypass_strategies:
            lines.append("\nRecommended Bypass Strategies:")
            for i, strategy in enumerate(result.primary_profile.bypass_strategies, 1):
                lines.append(f"  {i}. {strategy}")
        if result.secondary_profiles:
            lines.append("\nSecondary Detections:")
            for profile in result.secondary_profiles:
                lines.append(f"  - {profile.vendor.value} ({profile.confidence.name})")
        return "\n".join(lines)


async def quick_detect(response, url: str = "") -> WAFDetectionResult:
    """Quick WAF detection from a single response."""
    detector = WAFDetector()
    return await detector.detect(response, url)