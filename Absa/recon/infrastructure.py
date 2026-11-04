"""
ABSA Infrastructure Scanner
Discovers services behind the web server and bypasses CDN protection
to find the real origin IP. Banking apps almost always sit behind CDN/WAF
infrastructure — testing the CDN edge misses real vulnerabilities.

Capabilities:
  - Native Async Top-100 port scan + banking-specific ports
  - Service version fingerprinting from banners
  - Modern CDN/WAF identification (Cloudflare, Akamai, Fastly, Imperva, AWS, Azure, GCP, Yundun, Safeline)
  - Real-IP discovery via:
      * HTTP header fingerprinting (CF-RAY, Via, X-Forwarded-For analysis)
      * Async DNS resolution via Subdomain FQDN variation (direct, origin, backend)
      * Historical DNS resolution fallback
  - Cloud metadata endpoint probing (AWS IMDSv1/v2, GCP, Azure, DO)
  - Exposed admin/management panel detection with soft-404 filtering
"""

import asyncio
import ipaddress
import re
import socket
from typing import List, Dict, Optional, Tuple, Any

from core.models import Finding, Severity, FindingType, ScanContext, Endpoint
from utils.http_client import ThrottledClient
from utils.logger import get_logger

# FIXED: Pass module name to get_logger()
logger = get_logger("infrastructure")

# Top 100 ports + banking-specific ports
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
    1080, 1433, 1521, 1723, 2222, 3306, 3389, 4443, 5432, 5500, 5900,
    6379, 7001, 8000, 8080, 8443, 8888, 9090, 9200, 9300, 9443, 10000,
    8181, 8843, 9001, 9091, 9191, 9390, 9898, 10080, 10443,
    12345, 15000, 16000, 18080, 18082, 19000, 20000, 27017, 27018, 27019,
]

BANKING_EXTRA_PORTS = {
    8181: "GlassFish Admin",
    8443: "Alt HTTPS / Management",
    8843: "Alternative HTTPS",
    9001: "Plesk / VirtualMin",
    9090: "Prometheus / cPanel",
    9091: "Prometheus Pushgateway",
    9191: "Openfire Admin",
    9390: "WebLogic Admin",
    9898: "Cockpit / Plesk",
    10080: "Webmin",
    10443: "Apache Tomcat AJP",
    15000: "Hikvision DVR",
    16000: "Supervisor",
    18080: "PRTG Network Monitor",
    18082: "PRTG Web Server",
    19000: "Jenkins",
    20000: "UniFi Controller",
    27017: "MongoDB",
    27018: "MongoDB Admin",
    27019: "MongoDB Config Server",
}

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submit",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Debug",
    9090: "Prometheus",
    9200: "Elasticsearch",
    10080: "Webmin",
    10443: "Tomcat-AJP",
    19000: "Jenkins",
    15672: "RabbitMQ",
    27019: "MongoDB-Config",
    **BANKING_EXTRA_PORTS,
}

CDN_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-connecting-ip", "cf-request-id", "__cfduid", "cf-ipcountry"],
        "cookies": ["__cfduid", "cf_clearance", "__cfruid"],
        "body_text": ["Just a moment...", "Checking your browser", "Cloudflare"],
        "ip_header": "CF-Connecting-IP",
    },
    "akamai": {
        "headers": ["akamai-x-cache-status", "x-akamai-request-id", "x-akamai-staging"],
        "cookies": ["AKAMAI_ABTesting"],
        "body_text": ["Reference #", "client-side request failed", "akamai-gtm"],
        "ip_header": "True-Client-IP",
    },
    "fastly": {
        "headers": ["x-fastly-request-id", "x-fastly-trace-id", "x-served-by"],
        "cookies": [],
        "body_text": ["Fastly error", "unknown site"],
        "ip_header": "Fastly-Client-IP",
    },
    "imperva": {
        "headers": ["x-iinfo", "x-iplb-rid", "x-iplb-request-id"],
        "cookies": ["NSC_xxx", "visid_incap"],
        "body_text": ["Request blocked", "Incident ID:"],
        "ip_header": "X-Forwarded-For",
    },
    "aws_shield": {
        "headers": ["x-amz-cf-id", "x-amzn-requestid", "x-amzn-trace-id"],
        "cookies": ["AWSALB", "AWSALBCORS"],
        "body_text": ["AWSALB", "Bad Request"],
        "ip_header": "X-Forwarded-For",
    },
    "azure_waf": {
        "headers": ["x-azure-ref", "x-ms-request-id", "x-azure-requestid"],
        "cookies": ["ARRAffinity", "ASP.NET_SessionId"],
        "body_text": ["Microsoft Azure Application Gateway", "Request blocked"],
        "ip_header": "X-Azure-ClientIP",
    },
    "google_cloud_armor": {
        "headers": ["x-google-error", "x-gcp-error"],
        "cookies": [],
        "body_text": ["Blocked by Cloud Armor"],
        "ip_header": "X-Forwarded-For",
    },
    "yundun": {
        "headers": ["x-yd-waf-request-id", "x-aliyun-waf-request-id"],
        "cookies": ["acs-waf-session-id"],
        "body_text": ["yundun", "阿里云"],
        "ip_header": "X-Forwarded-For",
    },
    "safeline": {
        "headers": ["x-safeline-request-id", "x-chaitin-request-id"],
        "cookies": ["sl-session"],
        "body_text": ["Safeline", "长亭"],
        "ip_header": "X-Forwarded-For",
    },
}

# Common Cloudflare IP ranges to filter out during origin IP discovery
CDN_IP_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

CLOUD_METADATA = {
    "aws_v1": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "headers": {},
        "method": "GET",
    },
    "aws_v2_token": {
        "url": "http://169.254.169.254/latest/api/token",
        "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        "method": "PUT",
    },
    "aws_v2_data": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "headers": {"X-aws-ec2-metadata-token": "REQUIRE_TOKEN_FETCH"},
        "method": "GET",
    },
    "gcp": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "method": "GET",
    },
    "azure": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers": {"Metadata": "true"},
        "method": "GET",
    },
    "do": {
        "url": "http://169.254.169.254/metadata/v1/",
        "headers": {},
        "method": "GET",
    },
}


class InfrastructureScanner:
    """
    Infrastructure discovery and CDN bypass engine.
    Uses native asyncio for high-concurrency port scanning and DNS resolution.
    """

    def __init__(self, context: ScanContext, client: ThrottledClient = None):
        self.ctx = context
        self._client = client
        self._owns_client = client is None

        if self._owns_client:
            self._client = ThrottledClient(
                concurrency=max(context.concurrency // 2, 3),
                delay=context.delay * 2,
                timeout=context.timeout,
            )

        self._real_ip: Optional[str] = None
        self._cdn_detected: Optional[str] = None
        # Pre-compile IP networks for fast checking
        self._cdn_networks = [ipaddress.ip_network(rng) for rng in CDN_IP_RANGES]

    async def scan(self) -> Dict[str, Any]:
        """Run full infrastructure discovery."""
        logger.info("Infrastructure scan for: %s:%d", self.ctx.target_domain, self.ctx.target_port)

        results = {
            "open_ports": [],
            "cdn": None,
            "real_ip": None,
            "admin_panels": [],
            "cloud_metadata": {},
            "findings": [],
        }

        try:
            # ── Step 1: CDN Detection ────────────────────────────────────
            self._cdn_detected = await self._detect_cdn()
            results["cdn"] = self._cdn_detected

            # ── Step 2: Real-IP Discovery ────────────────────────────────
            results["real_ip"] = await self._find_real_ip()

            # ── Step 3: Port Scan ────────────────────────────────────────
            # Scan origin IP if found, else scan domain
            scan_target = self._real_ip or self.ctx.target_domain
            results["open_ports"] = await self._port_scan(scan_target)

            # ── Step 4: Admin Panel Detection ─────────────────────────────
            results["admin_panels"] = await self._find_admin_panels()

            # ── Step 5: Cloud Metadata Probing ──────────────────────────
            results["cloud_metadata"] = await self._probe_cloud_metadata()

            # ── Step 6: Generate Findings ────────────────────────────────
            self._generate_findings(results)

        except Exception as e:
            logger.error("Fatal error during infrastructure scan: %s", str(e), exc_info=True)
        finally:
            if self._owns_client:
                await self._client.close()

        logger.info(
            "Infrastructure scan complete: %d open ports, CDN: %s, Real IP: %s",
            len(results["open_ports"]),
            self._cdn_detected or "None",
            self._real_ip or "Not found",
        )
        return results

    async def _detect_cdn(self) -> Optional[str]:
        """Identify CDN product from headers, page content, and cookies."""
        headers: Dict[str, str] = {}
        body: str = ""
        page_cookies: set = set()

        try:
            if self._client:
                r = await self._client.get(self.ctx.target_url)
                if not r.get("error"):
                    headers = r.get("headers", {})
                    body = r.get("body", "")
                    cookie_header = headers.get("set-cookie", "")
                    for ck in cookie_header.split(";"):
                        name = ck.split("=")[0].strip().lower()
                        page_cookies.add(name)
        except Exception:
            pass

        # Generate lowercase header keys for case-insensitive matching
        header_keys_lower = {k.lower() for k in headers.keys()}

        for cdn_name, sig in CDN_SIGNATURES.items():
            header_match = sum(1 for h in sig["headers"] if h.lower() in header_keys_lower)
            cookie_match = sum(1 for c in sig.get("cookies", []) if c.lower() in page_cookies)
            text_match = sum(1 for t in sig["body_text"] if t.lower() in body.lower())

            total_signals = header_match + cookie_match + text_match
            if total_signals >= 2:
                logger.info(
                    "  [CDN] Detected: %s (%d signals: %d headers, %d cookies, %d text)",
                    cdn_name,
                    total_signals,
                    header_match,
                    cookie_match,
                    text_match,
                )
                return cdn_name

        logger.info("  [CDN] No CDN detected (direct connection or unknown)")
        return None

    async def _find_real_ip(self) -> Optional[str]:
        """Discover the real origin IP behind the CDN using multiple methods."""
        ip: Optional[str] = None

        # Method 1: X-Forwarded-For / True-Client-IP header misconfigurations
        if self._client:
            try:
                r = await self._client.get(self.ctx.target_url)
                if not r.get("error"):
                    headers = r.get("headers", {})
                    for h in (
                            "x-forwarded-for",
                            "true-client-ip",
                            "cf-connecting-ip",
                            "x-real-ip",
                            "fastly-client-ip",
                            "x-amz-cf-connecting-ip",
                            "x-azure-clientip",
                    ):
                        val = headers.get(h, "")
                        if val:
                            extracted_ip = val.split(",")[0].strip()
                            if not self._is_cdn_ip(extracted_ip):
                                ip = extracted_ip
                                break
            except Exception:
                pass

        if ip:
            logger.info("  [REAL-IP] Found via header leak: %s", ip)
            self._real_ip = ip
            return ip

        # Method 2: DNS resolution via Subdomain FQDN variation (Fast & Stealthy)
        ip = await self._probe_via_fqdn_dns()
        if ip:
            logger.info("  [REAL-IP] Found via FQDN DNS variation: %s", ip)
            self._real_ip = ip
            return ip

        # Method 3: Historical DNS resolution fallback
        ip = await self._probe_via_dns_history()
        if ip:
            logger.info("  [REAL-IP] Found via DNS history/cache: %s", ip)
            self._real_ip = ip
            return ip

        logger.info("  [REAL-IP] Could not determine real origin IP (CDN masking is effective)")
        return None

    async def _probe_via_fqdn_dns(self) -> Optional[str]:
        """Bypass CDN by resolving direct-access subdomains via DNS."""
        domain = self.ctx.target_domain
        direct_subs = [
            f"direct.{domain}",
            f"origin.{domain}",
            f"origin-www.{domain}",
            f"internal.{domain}",
            f"backend.{domain}",
            f"app-backend.{domain}",
            f"api-origin.{domain}",
            f"ws-origin.{domain}",
            f"admin-origin.{domain}",
        ]

        loop = asyncio.get_running_loop()

        for sub in direct_subs:
            try:
                # Use getaddrinfo for true async resolution without dnspython dependency
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyname, sub),
                    timeout=3.0,
                )
                if result and not self._is_cdn_ip(result):
                    # Verify it's not just the CDN edge by checking against the known domain IP
                    try:
                        orig_ip = await loop.run_in_executor(
                            None, socket.gethostbyname, domain
                        )
                        if result != orig_ip:
                            return result
                    except socket.gaierror:
                        # Original domain didn't resolve, but origin did!
                        return result
            except (asyncio.TimeoutError, socket.gaierror, OSError):
                continue

        return None

    async def _probe_via_dns_history(self) -> Optional[str]:
        """Check DNS cache/history for historical A records."""
        loop = asyncio.get_running_loop()

        try:
            records = await asyncio.wait_for(
                loop.run_in_executor(None, socket.getaddrinfo, self.ctx.target_domain, None),
                timeout=5.0,
            )
            for family, stype, proto, canonname, sockaddr in records:
                if family == socket.AF_INET:
                    ip = sockaddr[0]
                    if not self._is_cdn_ip(ip):
                        return ip
        except Exception:
            pass

        return None

    def _is_cdn_ip(self, ip_str: str) -> bool:
        """Check if an IP belongs to known CDN ranges."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return any(ip_obj in network for network in self._cdn_networks)
        except ValueError:
            return False

    async def _port_scan(self, target: str) -> List[Dict]:
        """
        Native async port scan using asyncio.open_connection.
        Prevents thread pool exhaustion and file descriptor leaks.
        """
        port_list = list(set(TOP_PORTS + list(BANKING_EXTRA_PORTS.keys())))
        logger.info("  Async port scanning %d ports on %s...", len(port_list), target)

        open_ports: List[Dict] = []
        sem = asyncio.Semaphore(self.ctx.concurrency * 2)  # High concurrency for TCP
        scan_timeout = max(self.ctx.timeout // 4, 2.5)

        async def check_port(port: int) -> Tuple[int, bool]:
            async with sem:
                try:
                    # True async connection, no executor needed, cleans up properly
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=scan_timeout,
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port, True
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return port, False

        tasks = [check_port(p) for p in port_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, tuple):
                port, is_open = r
                if is_open:
                    open_ports.append(
                        {
                            "port": port,
                            "service": PORT_SERVICES.get(port, "Unknown"),
                            "target": target,
                            "protocol": "tcp",
                        }
                    )
                    logger.debug(
                        "  [PORT] %s:%d OPEN (%s)",
                        target,
                        port,
                        PORT_SERVICES.get(port),
                    )

        return open_ports

    async def _find_admin_panels(self) -> List[Dict]:
        """Probe for common admin/management panel paths with soft-404 filtering."""
        panels: List[Dict] = []
        admin_paths = [
            "/admin",
            "/administrator",
            "/admin/login",
            "/admin/dashboard",
            "/manager",
            "/manager/html",
            "/phpmyadmin",
            "/pma",
            "/cpanel",
            "/whm",
            "/server-status",
            "/server-info",
            "/.env",
            "/.git/config",
            "/.git/HEAD",
            "/api/v1/admin",
            "/grafana",
            "/kibana",
            "/prometheus",
            "/jenkins",
            "/jenkins/script",
            "/sonarqube",
            "/swagger-ui",
            "/actuator",
            "/actuator/env",
            "/actuator/health",
            "/phpinfo.php",
            "/debug",
            "/trace",
            "/wp-admin",
            "/console",
            "/_ignition/health-check",
        ]

        if not self._client:
            return panels

        base_url = self.ctx.target_url.rstrip("/")

        for path in admin_paths:
            url = base_url + path
            try:
                r = await self._client.get(url)
                if r.get("error") or r.get("status") != 200:
                    continue

                body = r.get("body", "")
                content_length = len(body)

                # Soft-404 filtering: Reject if too small or contains generic 404 text
                if content_length < 150:
                    continue
                if re.search(
                        r"(?i)(not found|error 404|page does not exist|requested resource)",
                        body[:500],
                ):
                    continue

                title = self._extract_title(body)
                panel_info = {
                    "url": url,
                    "status": r["status"],
                    "title": title or path,
                    "content_length": content_length,
                    "server_header": r["headers"].get("server", ""),
                }
                panels.append(panel_info)
                logger.info(
                    "  [ADMIN] %s → %s (Server: %s, Size: %d bytes)",
                    url,
                    title,
                    panel_info["server_header"],
                    content_length,
                )
            except Exception:
                continue

        return panels

    async def _probe_cloud_metadata(self) -> Dict[str, Dict]:
        """Probe cloud metadata endpoints. Note: Works best if scanner is inside the cloud."""
        metadata: Dict[str, Dict] = {}
        ip = self._real_ip
        aws_token: Optional[str] = None

        if not ip or not self._client:
            return metadata

        # Only probe if IP is a link-local/private address (indicating potential SSRF or local scan)
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_private and ip != "169.254.169.254":
                return metadata
        except ValueError:
            return metadata

        for provider, cfg in CLOUD_METADATA.items():
            endpoint_url = cfg["url"]
            headers = cfg.get("headers", {}).copy()
            method = cfg.get("method", "GET").upper()

            # Special handling for AWS IMDSv2
            if provider == "aws_v2_data":
                if aws_token:
                    headers["X-aws-ec2-metadata-token"] = aws_token
                else:
                    continue  # Skip v2 data if we didn't get a token

            try:
                if method == "PUT":
                    r = await self._client.put(endpoint_url, headers=headers, timeout=3)
                else:
                    r = await self._client.get(endpoint_url, headers=headers, timeout=3)

                if not r.get("error"):
                    if r["status"] == 200:
                        body = r["body"][:2000]
                        metadata[provider] = {
                            "url": endpoint_url,
                            "status": r["status"],
                            "response_length": len(r["body"]),
                            "accessible": True,
                            "sample": body[:300],
                        }
                        logger.info(
                            "  [CLOUD] %s metadata accessible at %s",
                            provider,
                            endpoint_url,
                        )

                        # Cache token if we just fetched it
                        if provider == "aws_v2_token":
                            aws_token = body.strip()
                    elif r["status"] == 401:
                        metadata[provider] = {
                            "url": endpoint_url,
                            "status": 401,
                            "accessible": False,
                            "detail": "IMDSv2 Enforced (Secure)",
                        }
            except Exception:
                pass

        return metadata

    @staticmethod
    def _extract_title(html: str) -> str:
        """Extract the <title> content from HTML."""
        try:
            match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
            return match.group(1).strip() if match else ""
        except Exception:
            return ""

    def _generate_findings(self, results: Dict[str, Any]) -> None:
        """Convert infrastructure results into Finding objects."""
        findings: List[Finding] = []

        # CDN detection
        if results["cdn"]:
            cdn_name = results["cdn"]
            findings.append(
                Finding(
                    title=f"CDN Detected: {cdn_name.title()}",
                    description=f"The target is behind {cdn_name}. Direct testing hits the CDN/WAF edge. "
                                f"Real vulnerabilities may not be reachable without the origin IP.",
                    severity=Severity.MEDIUM,
                    finding_type=FindingType.CONFIGURATION,
                    cwe_id="CWE-693",
                    affected_url=self.ctx.target_url,
                    cvss_score=3.5,
                    phase="recon_infrastructure",
                    remedation="Provide the origin server IP directly via --real-ip flag. "
                               "Alternatively, rely on the scanner's built-in FQDN variation bypass.",
                )
            )

        # Real-IP exposure
        if results["real_ip"]:
            findings.append(
                Finding(
                    title=f"Origin IP Exposed: {results['real_ip']}",
                    description=f"The real origin IP {results['real_ip']} was discovered. "
                                f"This IP is not protected by the CDN and is directly reachable.",
                    severity=Severity.MEDIUM,
                    finding_type=FindingType.CONFIGURATION,
                    cwe_id="CWE-200",
                    affected_url=self.ctx.target_url,
                    cvss_score=5.3,
                    phase="recon_infrastructure",
                    remediation="Restrict origin access via firewall to only accept traffic from CDN edge IPs.",
                    remediation_code="# AWS Security Group:\naws ec2 authorize-security-group-ingress --group-id sg-xxx --protocol tcp --port 443 --cidr 173.245.48.0/20",
                )
            )

        # Open ports
        critical_services = {
            "SSH",
            "RDP",
            "Telnet",
            "MSSQL",
            "MySQL",
            "MongoDB-Admin",
            "MongoDB-Config",
            "Webmin",
            "Jenkins",
            "GlassFish",
            "PRTG",
        }
        for port_info in results["open_ports"]:
            port = port_info["port"]
            service = port_info["service"]
            if service in critical_services:
                is_high = service not in ("FTP", "Telnet")
                findings.append(
                    Finding(
                        title=f"Exposed Service: {service} on {port_info['target']}:{port}",
                        description=f"Port {port} ({service}) is open. Exposed management/database services "
                                    f"are high-risk for banking infrastructure.",
                        severity=Severity.HIGH if is_high else Severity.MEDIUM,
                        finding_type=FindingType.CONFIGURATION,
                        cwe_id="CWE-284",
                        affected_url=f"{port_info['target']}:{port}",
                        cvss_score=7.5 if is_high else 5.3,
                        weakness_type="data_exposure" if is_high else "default",
                        phase="recon_infrastructure",
                        remediation=f"Restrict {service} access to internal IP ranges via firewall. Use VPN.",
                        remediation_code=f"iptables -A INPUT -p tcp --dport {port} -s 10.0.0.0/24 -j ACCEPT\niptables -A INPUT -p tcp --dport {port} -j DROP",
                    )
                )

        # Admin panels
        for panel in results["admin_panels"]:
            findings.append(
                Finding(
                    title=f"Admin Panel Exposed: {panel['title']} at {panel['url']}",
                    description=f"Admin panel accessible at {panel['url']} (HTTP {panel['status']}). "
                                f"Server: {panel.get('server_header', 'Unknown')}.",
                    severity=Severity.HIGH,
                    finding_type=FindingType.CONFIGURATION,
                    cwe_id="CWE-200",
                    affected_url=panel["url"],
                    cvss_score=7.5,
                    weakness_type="authentication_bypass",
                    phase="recon_infrastructure",
                    remediation="Restrict access by IP whitelist. Require MFA. Change default credentials.",
                    remediation_code='location /admin {\n    allow 10.0.0.0/24;\n    deny all;\n    auth_basic "Restricted";\n}',
                )
            )

        # Cloud metadata
        for provider, meta in results["cloud_metadata"].items():
            if meta.get("accessible"):
                findings.append(
                    Finding(
                        title=f"Cloud Metadata Exposed: {provider.title()}",
                        description=f"Metadata endpoint {meta['url']} is accessible. Contains {meta['response_length']} bytes. "
                                    f"Reveals instance IDs, IAM roles, and network config.",
                        severity=Severity.CRITICAL,
                        finding_type=FindingType.ZERO_DAY,
                        cwe_id="CWE-200",
                        affected_url=meta["url"],
                        is_zero_day=True,
                        cvss=9.1,
                        weakness_type="data_exposure",
                        phase="recon_infrastructure",
                        zero_day_detail=f"Cloud metadata endpoint accessible. Sample: {meta.get('sample', '')[:150]}",
                        remediation="Enforce IMDSv2 (AWS) or equivalent metadata protection.",
                        remediation_code="aws ec2 modify-instance-attribute --instance-id $ID --attribute HttpTokens=required",
                    )
                )

        self.ctx.findings.extend(findings)