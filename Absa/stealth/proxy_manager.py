"""
ABSA Proxy Manager
Manages proxy rotation to mask the tester's origin IP.
Supports SOCKS5, SOCKS4, and HTTP/HTTPS proxies loaded from
file or supplied individually. Rotates automatically after
a configurable number of requests to distribute traffic
across multiple exit nodes.
"""

import asyncio
import random
import time
from typing import Optional, List, Tuple
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger("stealth.proxy")


class ProxyManager:
    """
    Rotating proxy pool manager.

    Loads proxies from a file (one per line) or accepts a single proxy.
    Automatically rotates after N requests. Supports:
      - socks5://user:pass@host:port
      - socks4://host:port
      - http://user:pass@host:port
      - https://host:port
    """

    def __init__(self, proxy_url: str = None, proxy_file: str = None,
                 max_per_proxy: int = 100):
        self.max_per_proxy = max_per_proxy
        self.proxies: List[dict] = []
        self._current_index = 0
        self._request_count = 0
        self._bad_proxies: set = set()
        self._lock = asyncio.Lock()

        if proxy_url:
            self._add_proxy(proxy_url)
        if proxy_file:
            self._load_file(proxy_file)

        random.shuffle(self.proxies)
        logger.info("Proxy pool initialized: %d proxy(ies)", len(self.proxies))

    def _add_proxy(self, url: str):
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme not in ("socks5", "socks4", "http", "https"):
            logger.warning("Unsupported proxy scheme: %s — skipping", scheme)
            return
        proxy = {
            "url": url,
            "scheme": scheme,
            "host": parsed.hostname or "",
            "port": parsed.port or (1080 if "socks" in scheme else 8080),
            "username": parsed.username or None,
            "password": parsed.password or None,
        }
        if proxy not in self.proxies:
            self.proxies.append(proxy)

    def _load_file(self, filepath: str):
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._add_proxy(line)
        except FileNotFoundError:
            logger.warning("Proxy file not found: %s", filepath)
        except Exception as e:
            logger.error("Error loading proxy file: %s", e)

    async def get_proxy(self) -> Optional[dict]:
        """
        Get the next proxy from the pool, rotating after max requests.
        Returns None if no proxies are configured (direct connection).
        """
        if not self.proxies:
            return None

        async with self._lock:
            self._request_count += 1

            if self._request_count >= self.max_per_proxy:
                self._request_count = 0
                self._current_index = (self._current_index + 1) % len(self.proxies)
                # Skip known-bad proxies
                attempts = 0
                while (self.proxies[self._current_index]["url"] in self._bad_proxies
                       and attempts < len(self.proxies)):
                    self._current_index = (self._current_index + 1) % len(self.proxies)
                    attempts += 1

            proxy = self.proxies[self._current_index]
            return proxy

    async def mark_bad(self, proxy_url: str):
        """Mark a proxy as non-functional so it gets skipped."""
        self._bad_proxies.add(proxy_url)
        logger.debug("Proxy marked as bad: %s", proxy_url)

    async def mark_good(self, proxy_url: str):
        """Remove a proxy from the bad list (if it recovers)."""
        self._bad_proxies.discard(proxy_url)

    @property
    def pool_size(self) -> int:
        return len(self.proxies)

    @property
    def active_count(self) -> int:
        return len(self.proxies) - len(self._bad_proxies)

    @property
    def current_proxy_url(self) -> str:
        if self.proxies:
            return self.proxies[self._current_index]["url"]
        return "direct"


def build_aiohttp_proxy(proxy: dict) -> str:
    """Convert a proxy dict to the URL format aiohttp-socks expects."""
    if proxy is None:
        return None
    return proxy["url"]