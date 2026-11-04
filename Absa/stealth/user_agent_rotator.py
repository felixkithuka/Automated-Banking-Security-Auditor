"""
ABSA User-Agent Rotator
Rotates User-Agent strings to avoid creating a recognizable fingerprint.
Includes profiles for mimicking search engine bots, real browsers,
and mixed rotation. Also manages companion headers (Accept, Accept-Language,
Accept-Encoding, Sec-Fetch-*, etc.) to create consistent browser profiles.
"""

import random
from typing import Optional, Tuple

from utils.logger import get_logger

logger = get_logger("stealth.ua")

BOT_PROFILES = [
    {
        "user_agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
        "extra_headers": {
            "From": "googlebot(at)googlebot.com",
        },
    },
    {
        "user_agent": "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate",
        "extra_headers": {},
    },
    {
        "user_agent": "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
        "accept": "text/html,application/xml;q=0.9,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate",
        "extra_headers": {},
    },
    {
        "user_agent": "Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate",
        "extra_headers": {},
    },
    {
        "user_agent": "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_language": "zh-CN,zh;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate",
        "extra_headers": {},
    },
    {
        "user_agent": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate",
        "extra_headers": {},
    },
    {
        "user_agent": "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_language": "ru-RU,ru;q=0.9,en;q=0.8",
        "accept_encoding": "gzip, deflate",
        "extra_headers": {},
    },
]

BROWSER_PROFILES = [
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
        "sec_ch_ua": '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "sec_fetch_dest": "document",
        "sec_fetch_mode": "navigate",
        "sec_fetch_site": "none",
        "sec_fetch_user": "?1",
        "upgrade_insecure_requests": "1",
        "extra_headers": {},
    },
    {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
        "sec_ch_ua": '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"macOS"',
        "sec_fetch_dest": "document",
        "sec_fetch_mode": "navigate",
        "sec_fetch_site": "none",
        "sec_fetch_user": "?1",
        "upgrade_insecure_requests": "1",
        "extra_headers": {},
    },
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.5",
        "accept_encoding": "gzip, deflate, br",
        "sec_fetch_dest": "document",
        "sec_fetch_mode": "navigate",
        "sec_fetch_site": "none",
        "sec_fetch_user": "?1",
        "upgrade_insecure_requests": "1",
        "extra_headers": {},
    },
    {
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
        "sec_fetch_dest": "document",
        "sec_fetch_mode": "navigate",
        "sec_fetch_site": "none",
        "sec_fetch_user": "?1",
        "upgrade_insecure_requests": "1",
        "extra_headers": {},
    },
    {
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept_language": "en-US,en;q=0.9",
        "accept_encoding": "gzip, deflate, br",
        "sec_ch_ua": '"Microsoft Edge";v="121", "Not(A:Brand";v="99", "Chromium";v="121"',
        "sec_ch_ua_mobile": "?0",
        "sec_ch_ua_platform": '"Windows"',
        "sec_fetch_dest": "document",
        "sec_fetch_mode": "navigate",
        "sec_fetch_site": "none",
        "sec_fetch_user": "?1",
        "upgrade_insecure_requests": "1",
        "extra_headers": {},
    },
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.9,fr;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8", "fr-FR,fr;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8", "pt-BR,pt;q=0.9,en;q=0.8",
]


class UserAgentRotator:
    """
    Rotates User-Agent and companion headers based on selected profile.

    Profiles:
      - bot: Mimics search engine crawlers (Googlebot, Bingbot, etc.)
      - browser: Mimics real desktop browsers (Chrome, Firefox, Safari, Edge)
      - mixed: Randomly selects between bot and browser profiles
      - custom: Loads from file (JSON format)
    """

    def __init__(self, profile: str = "bot"):
        self.profile = profile
        self._profiles = []
        self._current = None
        self._rotation_count = 0

        if profile == "bot":
            self._profiles = BOT_PROFILES
        elif profile == "browser":
            self._profiles = BROWSER_PROFILES
        elif profile == "mixed":
            self._profiles = BOT_PROFILES + BROWSER_PROFILES
        else:
            self._profiles = BROWSER_PROFILES

        self._rotate()

    def _rotate(self):
        self._current = random.choice(self._profiles)
        # Randomize Accept-Language independently for additional diversity
        self._current["accept_language"] = random.choice(ACCEPT_LANGUAGES)
        self._rotation_count += 1

    def get_headers(self) -> dict:
        """
        Return a complete set of HTTP headers mimicking the current profile.
        Call rotate() periodically to change identity.
        """
        p = self._current
        headers = {
            "User-Agent": p["user_agent"],
            "Accept": p["accept"],
            "Accept-Language": p["accept_language"],
            "Accept-Encoding": p["accept_encoding"],
        }
        for key in ("sec_ch_ua", "sec_ch_ua_mobile", "sec_ch_ua_platform",
                     "sec_fetch_dest", "sec_fetch_mode", "sec_fetch_site",
                     "sec_fetch_user", "upgrade_insecure_requests"):
            if key in p:
                clean_key = key.replace("_", "-").title().replace("-", "-")
                headers[key] = p[key]
        headers.update(p.get("extra_headers", {}))
        return headers

    def rotate(self):
        """Switch to a new random profile."""
        self._rotate()
        logger.debug("Rotated identity: %s...",
                     self._current["user_agent"][:50])

    def get_user_agent(self) -> str:
        return self._current["user_agent"]

    @property
    def profile_count(self) -> int:
        return len(self._profiles)

    @property
    def current_type(self) -> str:
        ua = self._current["user_agent"].lower()
        if any(bot in ua for bot in ["bot", "slurp", "spider", "crawl", "externalhit"]):
            return "bot"
        return "browser"