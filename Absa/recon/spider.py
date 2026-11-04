"""
ABSA Endpoint Spider — Phase A Rewrite
Accepts an optional shared ThrottledClient. When provided, all crawl
requests flow through the shared stealth pipeline (proxy, UA, timing).
BFS crawler with form extraction, JS endpoint parsing, robots.txt respect.
"""

import asyncio
import re
from collections import deque
from typing import List, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse

from bs4 import BeautifulSoup

from core.models import Endpoint, ScanContext
from utils.http_client import ThrottledClient
from utils.helpers import extract_forms, extract_js_endpoints
from utils.logger import get_logger
import config

logger = get_logger("recon.spider")


class EndpointSpider:
    def __init__(self, context: ScanContext, client: ThrottledClient = None):
        self.ctx = context
        self._client = client
        self._owns_client = client is None
        if self._owns_client:
            self._client = ThrottledClient(
                concurrency=context.concurrency,
                delay=context.delay,
                timeout=context.timeout,
            )
        self.visited: Set[str] = set()
        self.endpoints: List[Endpoint] = []

    async def crawl(self) -> List[Endpoint]:
        logger.info("Spider starting: %s (depth=%d, max=%d)",
                     self.ctx.target_url,
                     config.RECON_CRAWL_MAX_DEPTH,
                     config.RECON_CRAWL_MAX_PAGES)
        queue = deque([(self.ctx.target_url, 0)])
        disallowed = await self._robots()

        while queue and len(self.visited) < config.RECON_CRAWL_MAX_PAGES:
            url, depth = queue.popleft()
            if url in self.visited or depth > config.RECON_CRAWL_MAX_DEPTH:
                continue
            if self._disallowed(url, disallowed) and config.RECON_CRAWL_RESPECT_ROBOTS:
                continue
            if self._excluded(url):
                continue
            self.visited.add(url)
            r = await self._client.get(url)
            if r["error"] or r["status"] not in (200, 201, 301, 302, 303, 307, 308):
                continue
            if r["status"] in (301, 302, 303, 307, 308):
                loc = r["headers"].get("location", "")
                if loc:
                    redir = urljoin(url, loc)
                    if redir not in self.visited:
                        queue.append((redir, depth))
                continue
            body, ct = r["body"], r["headers"].get("content-type", "")
            if "text/html" not in ct:
                self.endpoints.append(Endpoint(
                    url=url, method="GET", status_code=r["status"],
                    content_type=ct, discovery_source="crawl"
                ))
                continue

            for link in self._links(body, url):
                if link not in self.visited:
                    queue.append((link, depth + 1))

            for form in extract_forms(body):
                fu = urljoin(url, form["action"]) if form["action"] else url
                params = [i["name"] for i in form["inputs"] if i["name"]]
                is_login = any(
                    kw in " ".join(i["name"].lower() for i in form["inputs"])
                    for kw in ("login", "user", "email", "password", "signin")
                )
                self.endpoints.append(Endpoint(
                    url=fu, method=form["method"], status_code=r["status"],
                    content_type=ct, parameters=params, forms=[form],
                    discovery_source="form", is_login=is_login
                ))

            if config.RECON_JS_PARSE:
                for jep in extract_js_endpoints(body):
                    full = urljoin(url, jep)
                    if full not in self.visited:
                        self.endpoints.append(Endpoint(
                            url=full, method="GET", discovery_source="js_parse",
                            is_api=any(p in full for p in ("/api/", "/v1/", "/v2/", "/graphql"))
                        ))
                        queue.append((full, depth + 1))

            params = list(parse_qs(urlparse(url).query).keys())
            self.endpoints.append(Endpoint(
                url=url, method="GET", status_code=r["status"],
                content_type=ct, parameters=params, discovery_source="crawl"
            ))
            if len(self.visited) % 25 == 0:
                logger.info("  Crawled %d pages, %d endpoints...",
                             len(self.visited), len(self.endpoints))

        if self._owns_client:
            await self._client.close()

        seen = set()
        unique = []
        for ep in self.endpoints:
            k = f"{ep.method}:{ep.url}"
            if k not in seen:
                seen.add(k)
                unique.append(ep)
        logger.info("Spider done: %d pages, %d endpoints", len(self.visited), len(unique))
        return unique

    async def _robots(self):
        disallowed = []
        r = await self._client.get(
            f"{self.ctx.target_scheme}://{self.ctx.target_domain}/robots.txt"
        )
        if r["error"] or r["status"] != 200:
            return disallowed
        for line in r["body"].splitlines():
            l = line.strip()
            if l.lower().startswith("disallow:"):
                p = l.split(":", 1)[1].strip()
                if p:
                    disallowed.append(p)
        return disallowed

    def _disallowed(self, url, paths):
        p = urlparse(url).path
        return any(p.startswith(dp) for dp in paths)

    @staticmethod
    def _excluded(url):
        p = urlparse(url).path.lower()
        return any(p.endswith(e) for e in config.RECON_EXCLUDE_EXTENSIONS)

    @staticmethod
    def _links(html, base):
        soup = BeautifulSoup(html, "lxml")
        bd = urlparse(base).hostname or ""
        links = []
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full = urljoin(base, href)
            if urlparse(full).hostname == bd:
                p = urlparse(full)
                clean = (f"{p.scheme}://{p.netloc}{p.path}"
                         + (f"?{p.query}" if p.query else ""))
                links.append(clean)
        return links