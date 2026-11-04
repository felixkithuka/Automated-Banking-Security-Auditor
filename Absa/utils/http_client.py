"""
ABSA Async HTTP Client — Stealth-Enabled
Rate-limited, proxy-rotating, fingerprint-mimicking async HTTP client.

Anti-Trace Enhancements:
  - Forced proxy routing (SOCKS5/HTTP) to mask origin IP
  - Browser-like TLS fingerprint randomization (defeats JA3/JA4)
  - Full header sanitization (strips tool-specific headers)
  - Cookie isolation per session (prevents cross-request correlation)
  - DNS-over-proxy (prevents DNS leaks outside the tunnel)
  - Randomized Accept-Encoding ordering (defeats header-order fingerprinting)
  - Trust env disabled (prevents system proxy leaks)
"""

import asyncio
import random
import ssl
import time
from typing import Dict, Any, Optional, List

import aiohttp
import certifi

from utils.logger import get_logger

logger = get_logger("http")


class ThrottledClient:
    """Stealth-enabled async HTTP client."""

    def __init__(self, concurrency=None, delay=None, timeout=None,
                 verify_ssl=True,
                 proxy_manager=None,
                 ua_rotator=None,
                 fingerprint_mimic=None,
                 timing_controller=None,
                 rotate_identity_every=50):
        """
        Initialize the stealth client.
        If proxy_manager is provided, it controls rotation.
        If proxy_url is set via set_proxy(), that specific proxy is used for all traffic.
        """
        try:
            import config
            self.concurrency = concurrency or config.DEFAULT_CONCURRENCY
            self.delay = delay or config.DEFAULT_DELAY
            self.timeout = timeout or config.DEFAULT_TIMEOUT
            self._strip_tool_headers = getattr(config, "STEALTH_STRIP_TOOL_HEADERS", False)
        except ImportError:
            self.concurrency = concurrency or 10
            self.delay = delay or 0.5
            self.timeout = timeout or 15
            self._strip_tool_headers = False

        self.verify_ssl = verify_ssl
        self._proxy_mgr = proxy_manager
        self._ua_rotator = ua_rotator
        self._fp_mimic = fingerprint_mimic
        self._timing = timing_controller
        self._rotate_every = rotate_identity_every

        # --- Interactive proxy mode (set by absa.py menu) ---
        self._forced_proxy_url: Optional[str] = None

        self._session: Optional[aiohttp.ClientSession] = None
        self._sem: Optional[asyncio.Semaphore] = None
        self._request_count = 0
        self._current_proxy_url: Optional[str] = None

    def set_proxy(self, proxy_url: str) -> None:
        """Force all traffic through a specific proxy URL."""
        self._forced_proxy_url = proxy_url
        logger.info("Forced proxy set: %s", proxy_url[:50] + "..." if len(proxy_url) > 50 else proxy_url)

    def _get_active_proxy_url(self) -> Optional[str]:
        """Return the proxy URL that should be used for the next connection."""
        if self._forced_proxy_url:
            return self._forced_proxy_url
        return self._current_proxy_url

    def _get_browser_headers(self) -> Dict[str, str]:
        """Generate browser-like headers, randomized to prevent fingerprinting."""
        if self._ua_rotator:
            headers = self._ua_rotator.get_headers()
        else:
            chrome_versions = ["120.0.0.0", "121.0.0.0", "122.0.0.0", "123.0.0.0"]
            platforms = [
                "(Windows NT 10.0; Win64; x64)",
                "(Macintosh; Intel Mac OS X 10_15_7)",
                "(X11; Linux x86_64)"
            ]

            selected_ver = random.choice(chrome_versions)
            selected_plat = random.choice(platforms)

            headers = {
                "User-Agent": f"Mozilla/5.0 {selected_plat} AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{selected_ver} Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": random.choice([
                    "en-US,en;q=0.9", "en-GB,en;q=0.9,en-US;q=0.8",
                    "en-US,en;q=0.9,fr;q=0.8"
                ]),
                "Accept-Encoding": self._randomize_accept_encoding(),
                "Sec-Ch-Ua": f'"Not_A Brand";v="8", "Chromium";v="{selected_ver.split(".")[0]}", "Google Chrome";v="{selected_ver.split(".")[0]}"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": f'"{selected_plat.split(";")[0].replace("(", "").strip()}"',
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            }

        # Strip tool-specific headers that reveal automation
        headers.pop("X-Forwarded-For", None)
        headers.pop("Via", None)
        headers.pop("Connection", None)  # Let aiohttp handle this
        return headers

    @staticmethod
    def _randomize_accept_encoding() -> str:
        """Randomize Accept-Encoding order to defeat header-order fingerprinting."""
        encodings = ["gzip", "deflate", "br", "zstd"]
        random.shuffle(encodings)
        return ", ".join(encodings[:random.randint(2, 4)])

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context with randomized cipher ordering to defeat JA3/JA4."""
        ctx = ssl.create_default_context(cafile=certifi.where())

        browser_ciphers = [
            "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-GCM-SHA256:"
            "DHE-RSA-AES256-GCM-SHA384",
            "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
        ]

        selected_ciphers = random.choice(browser_ciphers)

        if self._fp_mimic:
            try:
                selected_ciphers = self._fp_mimic.get_cipher_list()
            except Exception:
                pass

        try:
            ctx.set_ciphers(selected_ciphers)
        except ssl.SSLError:
            try:
                ctx.set_ciphers("DEFAULT:!aNULL:!eNULL:!MD5")
            except ssl.SSLError:
                pass

        return ctx

    async def _build_connector(self) -> aiohttp.TCPConnector:
        """Build a connector with proxy and stealth features."""
        proxy_url = self._get_active_proxy_url()
        connector_kwargs = {
            "limit": self.concurrency,
            "ssl": self._create_ssl_context() if self.verify_ssl else False,
        }

        if proxy_url:
            scheme = proxy_url.split("://")[0].lower() if "://" in proxy_url else "http"

            if scheme in ("socks5", "socks4"):
                try:
                    from aiohttp_socks import ProxyConnector, ProxyType
                    proxy_type = ProxyType.SOCKS5 if scheme == "socks5" else ProxyType.SOCKS4
                    proxy_addr = proxy_url.split("://")[1]
                    connector = ProxyConnector(
                        proxy_type=proxy_type,
                        host=proxy_addr.split(":")[0],
                        port=int(proxy_addr.split(":")[1]),
                        ssl=self._create_ssl_context() if self.verify_ssl else False,
                        limit=self.concurrency,
                    )
                    self._current_proxy_url = proxy_url
                    logger.debug("Using SOCKS proxy: %s", proxy_addr)
                    return connector
                except ImportError:
                    logger.warning("aiohttp-socks not installed, SOCKS proxy ignored. Install with: pip install aiohttp-socks")
                except Exception as e:
                    logger.error("SOCKS proxy setup failed: %s", e)

            self._current_proxy_url = proxy_url
            logger.debug("Using HTTP proxy: %s", proxy_url)

        return aiohttp.TCPConnector(**connector_kwargs)

    async def _ensure_session(self):
        """Create or recreate the session, rotating identity as needed."""
        need_new = (
            self._session is None or
            self._session.closed or
            (self._rotate_every > 0 and
             self._request_count > 0 and
             self._request_count % self._rotate_every == 0)
        )

        if need_new:
            if self._session and not self._session.closed:
                await self._session.close()

            connector = await self._build_connector()
            headers = self._get_browser_headers()

            if self._fp_mimic and self._strip_tool_headers:
                try:
                    headers = self._fp_mimic.strip_tool_headers(headers)
                except Exception:
                    pass

            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)

            session_kwargs = {
                "timeout": timeout_obj,
                "connector": connector,
                "headers": headers,
                "trust_env": False,  # CRITICAL: Prevent system proxy leaks
                "cookie_jar": aiohttp.DummyCookieJar(),  # Isolate cookies between sessions
            }

            active_proxy = self._get_active_proxy_url()
            if active_proxy and active_proxy.startswith("http"):
                session_kwargs["proxy"] = active_proxy

            self._session = aiohttp.ClientSession(**session_kwargs)

            if self._rotate_every > 0 and self._request_count > 0:
                try:
                    if self._ua_rotator:
                        self._ua_rotator.rotate()
                except Exception:
                    pass
                try:
                    if self._fp_mimic:
                        self._fp_mimic.rotate()
                except Exception:
                    pass
                logger.debug("Session rotated (request #%d)", self._request_count)

            self._sem = asyncio.Semaphore(self.concurrency)

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _throttle(self):
        """Apply timing jitter to mimic human browsing patterns."""
        if self._timing:
            try:
                await self._timing.wait()
            except Exception:
                await asyncio.sleep(self.delay * random.uniform(0.5, 1.5))
        else:
            if self.delay > 0:
                jitter = self.delay * random.uniform(0.5, 1.5)
                await asyncio.sleep(jitter)

    async def _handle_proxy_failure(self, error_str: str):
        """Mark proxy as bad if the error indicates a proxy failure."""
        if self._proxy_mgr and not self._forced_proxy_url:
            current = self._current_proxy_url
            if current:
                failure_keywords = ("refused", "reset", "timed out", "unreachable", "tunnel")
                if any(kw in error_str.lower() for kw in failure_keywords):
                    try:
                        await self._proxy_mgr.mark_bad(current)
                    except Exception:
                        pass

    async def request(self, method, url, **kw) -> Dict[str, Any]:
        await self._ensure_session()
        async with self._sem:
            await self._throttle()
            self._request_count += 1
            t0 = time.monotonic()

            r = {
                "status": 0, "headers": {}, "body": "", "time_ms": 0.0,
                "error": None, "proxy_used": self._get_active_proxy_url()
            }

            try:
                kw.setdefault("allow_redirects", False)
                kw.setdefault("ssl", self.verify_ssl)
                kw.setdefault("auto_decompress", True)

                async with self._session.request(method, url, **kw) as resp:
                    r["status"] = resp.status
                    r["headers"] = dict(resp.headers)
                    body_text = await resp.text(errors="replace")
                    r["body"] = body_text[:500000]

            except asyncio.TimeoutError:
                r["error"] = "timeout"
                await self._handle_proxy_failure("timeout")
            except aiohttp.ClientError as e:
                r["error"] = str(e)
                await self._handle_proxy_failure(str(e))
            except Exception as e:
                r["error"] = f"unexpected: {e}"

            r["time_ms"] = (time.monotonic() - t0) * 1000

            # Adaptive timing based on server response time
            if self._timing and not r["error"]:
                try:
                    self._timing.adaptive_delay(r["time_ms"])
                except Exception:
                    pass

            return r

    async def get(self, url, **kw):
        return await self.request("GET", url, **kw)

    async def post(self, url, **kw):
        return await self.request("POST", url, **kw)

    async def put(self, url, **kw):
        return await self.request("PUT", url, **kw)

    async def head(self, url, **kw):
        return await self.request("HEAD", url, **kw)

    async def options(self, url, **kw):
        return await self.request("OPTIONS", url, **kw)

    @property
    def request_count(self):
        return self._request_count

    def get_stealth_info(self) -> dict:
        """Return current stealth status for logging."""
        info = {"requests": self._request_count}
        proxy = self._get_active_proxy_url()
        info["proxy"] = proxy or "direct (NO PROXY — TRAFFIC NOT MASKED)"
        if self._proxy_mgr:
            try:
                info["proxy_pool"] = f"{self._proxy_mgr.active_count}/{self._proxy_mgr.pool_size}"
            except Exception:
                pass
        if self._ua_rotator:
            try:
                info["ua_type"] = self._ua_rotator.current_type
                info["ua"] = self._ua_rotator.get_user_agent()[:60]
            except Exception:
                info["ua"] = "randomized"
        if self._timing:
            try:
                info["timing"] = self._timing.stats
            except Exception:
                pass
        return info