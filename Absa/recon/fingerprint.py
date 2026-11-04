"""
ABSA Technology Fingerprinter — Phase A Rewrite
Accepts an optional shared ThrottledClient. When provided, uses it for
the homepage fetch (stealth flows through shared client).
Identifies web servers, frameworks, JS libs, CMS, cookie misconfigurations.
Produces Technology objects with CPE identifiers for CVE correlation.
"""

import re
from typing import List, Optional
from bs4 import BeautifulSoup

from core.models import Technology, ScanContext
from utils.http_client import ThrottledClient
from utils.logger import get_logger
import config

logger = get_logger("recon.fingerprint")

HEADER_SIGS = {
    "server": [
        (r"apache/([\d.]+)", "Apache HTTP Server", "web_server", "a:apache:http_server"),
        (r"nginx/([\d.]+)", "Nginx", "web_server", "a:nginx:nginx"),
        (r"Microsoft-IIS/([\d.]+)", "Microsoft IIS", "web_server", "a:microsoft:iis"),
        (r"LiteSpeed", "LiteSpeed", "web_server", ""),
        (r"openresty/([\d.]+)", "OpenResty", "web_server", "a:openresty:openresty"),
        (r"Caddy", "Caddy", "web_server", ""),
        (r"cloudflare", "Cloudflare", "cdn", ""),
        (r"Apache-Coyote/([\d.]+)", "Apache Tomcat", "app_server", "a:apache:tomcat"),
        (r"Jetty\(?([\d.]+)?\)?", "Eclipse Jetty", "app_server", "a:eclipse:jetty"),
    ],
    "x-powered-by": [
        (r"Express", "Express.js", "framework", ""),
        (r"PHP/([\d.]+)", "PHP", "language", "a:php:php"),
        (r"ASP\.NET", "ASP.NET", "framework", "a:microsoft:asp.net"),
        (r"Next\.js", "Next.js", "framework", ""),
        (r"Django/([\d.]+)", "Django", "framework", "a:djangoproject:django"),
        (r"Flask", "Flask", "framework", "a:pallets:flask"),
        (r"Ruby on Rails", "Ruby on Rails", "framework", "a:rubyonrails:rails"),
    ],
    "x-aspnet-version": [(r"([\d.]+)", "ASP.NET", "framework", "a:microsoft:asp.net")],
    "x-drupal-cache": [(r".*", "Drupal", "cms", "a:drupal:drupal")],
    "x-generator": [
        (r"WordPress ([\d.]+)", "WordPress", "cms", "a:wordpress:wordpress"),
        (r"Joomla! ([\d.]+)", "Joomla", "cms", "a:joomla:joomla%"),
        (r"Drupal ([\d.]+)", "Drupal", "cms", "a:drupal:drupal"),
        (r"TYPO3", "TYPO3", "cms", "a:typo3:typo3"),
        (r"Hugo", "Hugo", "static_site", ""),
    ],
}

BODY_SIGS = [
    (r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']WordPress ([\d.]+)', "WordPress", "cms", "a:wordpress:wordpress"),
    (r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']Joomla! ([\d.]+)', "Joomla", "cms", "a:joomla:joomla%"),
    (r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']Drupal ([\d.]+)', "Drupal", "cms", "a:drupal:drupal"),
    (r'wp-content', "WordPress", "cms", "a:wordpress:wordpress"),
    (r'wp-includes', "WordPress", "cms", "a:wordpress:wordpress"),
    (r'/sites/default/', "Drupal", "cms", "a:drupal:drupal"),
    (r'content="Magento', "Magento", "ecommerce", "a:magento:magento"),
    (r'Shopify\.theme', "Shopify", "ecommerce", ""),
    (r'csrf-token', "Laravel", "framework", "a:laravel:laravel"),
    (r'csrfmiddlewaretoken', "Django", "framework", "a:djangoproject:django"),
    (r'__RequestVerificationToken', "ASP.NET", "framework", "a:microsoft:asp.net"),
    (r'angular\.module\(', "AngularJS", "js_lib", ""),
    (r'ng-version=', "Angular", "js_lib", ""),
    (r'__NEXT_DATA__', "Next.js", "framework", ""),
    (r'__NUXT__', "Nuxt.js", "framework", ""),
    (r'react-dom', "React", "js_lib", ""),
    (r'vue\.js|vue\.min\.js', "Vue.js", "js_lib", ""),
    (r'jQuery\s*v?([\d.]+)', "jQuery", "js_lib", ""),
    (r'bootstrap\.min\.css', "Bootstrap", "css_lib", ""),
    (r'tailwind\.css', "Tailwind CSS", "css_lib", ""),
    (r'Spring Boot', "Spring Boot", "framework", "a:vmware:spring_boot"),
]


class TechnologyFingerprinter:
    def __init__(self, context: ScanContext, client: ThrottledClient = None):
        self.ctx = context
        self._client = client
        self._owns_client = client is None
        if self._owns_client:
            self._client = ThrottledClient(
                concurrency=3, delay=self.ctx.delay, timeout=self.ctx.timeout
            )

    async def fingerprint(self) -> List[Technology]:
        logger.info("Fingerprinting: %s", self.ctx.target_url)
        techs = []
        r = await self._client.get(self.ctx.target_url)
        if r["error"]:
            if self._owns_client:
                await self._client.close()
            return techs
        headers, body = r["headers"], r["body"]

        for hn, sigs in HEADER_SIGS.items():
            hv = headers.get(hn, "")
            for pat, name, cat, cpe_pre in sigs:
                m = re.search(pat, hv, re.I)
                if m:
                    ver = m.group(1) if m.lastindex else None
                    cpe = self._cpe(cpe_pre, ver)
                    if not self._dup(techs, name, ver):
                        techs.append(Technology(
                            name=name, version=ver, category=cat, cpe=cpe,
                            confidence=0.95, source=f"header:{hn}"
                        ))
                        logger.debug("  [HDR] %s %s", name, ver or "")

        for pat, name, cat, cpe_pre in BODY_SIGS:
            m = re.search(pat, body, re.I)
            if m:
                ver = m.group(1) if m.lastindex else None
                cpe = self._cpe(cpe_pre, ver)
                if not self._dup(techs, name, ver):
                    techs.append(Technology(
                        name=name, version=ver, category=cat, cpe=cpe,
                        confidence=0.8, source="body"
                    ))

        ck = headers.get("set-cookie", "")
        if ck:
            if "httponly" not in ck.lower():
                techs.append(Technology(name="Missing HttpOnly Cookie Flag", category="cookie_config", confidence=1.0, source="cookie"))
            if "secure" not in ck.lower():
                techs.append(Technology(name="Missing Secure Cookie Flag", category="cookie_config", confidence=1.0, source="cookie"))
            if "samesite" not in ck.lower():
                techs.append(Technology(name="Missing SameSite Attribute", category="cookie_config", confidence=1.0, source="cookie"))

        soup = BeautifulSoup(body, "lxml")
        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "")
            for lp, ln in config.FINGERPRINT_JS_LIBRARIES.items():
                if re.search(lp, src, re.I) and not self._dup(techs, ln, None):
                    techs.append(Technology(name=ln, category="js_lib", confidence=0.75, source="js_src"))

        if self._owns_client:
            await self._client.close()
        return techs

    @staticmethod
    def _cpe(pre, ver):
        if not pre:
            return None
        if ver:
            return f"cpe:2.3:{pre}:{ver}:*:*:*:*:*:*:*"
        return f"cpe:2.3:{pre}:*:*:*:*:*:*:*:*"

    @staticmethod
    def _dup(techs, name, ver):
        return any(t.name == name and (t.version == ver or ver is None) for t in techs)