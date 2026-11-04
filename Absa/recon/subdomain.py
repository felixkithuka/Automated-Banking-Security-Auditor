"""
ABSA Subdomain Enumerator — Phase A Rewrite
Accepts an optional shared ThrottledClient. When provided, uses it for
all HTTP requests (proxy/identity/timing flow through shared client).
When not provided, creates its own client and manages its lifecycle.
Sources: Certificate Transparency (crt.sh), controlled DNS brute-force.
"""

import asyncio
import re
import dns.resolver
from typing import List, Optional

from core.models import Subdomain, ScanContext
from utils.http_client import ThrottledClient
from utils.logger import get_logger
import config

logger = get_logger("recon.subdomain")


class SubdomainEnumerator:
    def __init__(self, context: ScanContext, client: ThrottledClient = None):
        self.ctx = context
        # Use shared client if provided, otherwise create own
        self._client = client
        self._owns_client = client is None
        if self._owns_client:
            self._client = ThrottledClient(
                concurrency=5, delay=0.2, timeout=config.DEFAULT_TIMEOUT
            )
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = config.RECON_DNS_RESOLVERS
        self.resolver.timeout = 5
        self.resolver.lifetime = 8

    async def enumerate(self) -> List[Subdomain]:
        logger.info("Enumerating subdomains for: %s", self.ctx.target_domain)
        results = []
        ct = await self._ct()
        results.extend(ct)
        logger.info("  CT logs: %d", len(ct))
        dns = await self._dns_brute()
        results.extend(dns)
        logger.info("  DNS brute: %d", len(dns))
        seen = set()
        unique = []
        for s in results:
            if s.fqdn not in seen:
                seen.add(s.fqdn)
                unique.append(s)
        # Only close if we own the client
        if self._owns_client:
            await self._client.close()
        return unique

    async def _ct(self):
        subs = []
        url = f"https://crt.sh/?q=%.{self.ctx.target_domain}&output=json"
        try:
            r = await self._client.get(url)
            if r["error"] or r["status"] != 200:
                return subs
            import json
            entries = json.loads(r["body"])
            pat = re.compile(
                r'^(?:[\w-]+\.)?' + re.escape(self.ctx.target_domain) + r'$', re.I
            )
            for e in entries:
                for name in e.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if pat.match(name):
                        subs.append(Subdomain(fqdn=name.lower(), source="crtsh"))
        except Exception as e:
            logger.debug("CT error: %s", e)
        return subs

    async def _dns_brute(self):
        subs = []
        domain = self.ctx.target_domain
        sem = asyncio.Semaphore(10)

        async def resolve(prefix):
            fqdn = f"{prefix}.{domain}"
            try:
                async with sem:
                    loop = asyncio.get_event_loop()
                    ans = await loop.run_in_executor(
                        None, lambda: list(self.resolver.resolve(fqdn, "A"))
                    )
                    return Subdomain(
                        fqdn=fqdn,
                        ip_addresses=[str(a) for a in ans],
                        source="dns_bruteforce",
                    )
            except Exception:
                return None

        tasks = [resolve(w) for w in config.BANKING_SUBDOMAIN_WORDLIST]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Subdomain):
                subs.append(r)
        return subs