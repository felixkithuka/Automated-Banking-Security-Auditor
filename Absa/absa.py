#!/usr/bin/env python3
"""
A.B.S.A - Advanced Breach & Security Assessment Framework
Main Entry Point — Main Menu Loop with Auto PDF Generation

Usage:
    python absa.py -u https://target.com
    python absa.py                                    # Interactive target input
"""

import asyncio
import argparse
import inspect
import os
import random
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# =============================================================================
# Safe Constructor Helper
# =============================================================================

def safe_kwargs(cls: type, provided: dict) -> dict:
    """Filter provided kwargs to only those accepted by the target class."""
    import dataclasses
    if dataclasses.is_dataclass(cls):
        return provided
    if hasattr(cls, "model_fields"):
        allowed = set(cls.model_fields.keys())
        return {k: v for k, v in provided.items() if k in allowed}
    if hasattr(cls, "__fields__"):
        allowed = set(cls.__fields__.keys())
        return {k: v for k, v in provided.items() if k in allowed}
    try:
        sig = inspect.signature(cls.__init__)
        allowed = set(sig.parameters.keys()) - {"self"}
        return {k: v for k, v in provided.items() if k in allowed}
    except (ValueError, TypeError):
        return {}


# =============================================================================
# Proxy Loader
# =============================================================================

PROXY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxies.txt")


def load_proxy_list(filepath: str = PROXY_FILE) -> List[str]:
    """
    Load proxies from the proxies.txt file.
    Returns a list of valid proxy URL strings.
    """
    if not os.path.exists(filepath):
        return []

    proxies = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "://" in line and ":" in line.split("://")[1]:
                proxies.append(line)

    return proxies


def categorize_proxies(proxy_list: List[str]) -> Dict[str, List[str]]:
    """Split proxy list into HTTP and SOCKS5 categories."""
    categories = {"http": [], "socks5": []}
    for proxy in proxy_list:
        scheme = proxy.split("://")[0].lower()
        if scheme in categories:
            categories[scheme].append(proxy)
        else:
            categories["http"].append(proxy)
    return categories


def proxy_prompt(proxy_list: List[str]) -> Optional[str]:
    """
    Interactive proxy selection menu.
    Returns the selected proxy URL string, or None if declined.
    """
    if not proxy_list:
        console.print("[bold red][-] No proxies found in proxies.txt[/bold red]")
        return None

    categories = categorize_proxies(proxy_list)

    console.print()
    console.print(Panel.fit(
        f"[bold cyan]Loaded {len(proxy_list)} proxies[/bold cyan] "
        f"({len(categories['http'])} HTTP, {len(categories['socks5'])} SOCKS5)",
        border_style="cyan",
    ))

    use_proxy = Prompt.ask(
        "[bold yellow]Route traffic through a proxy to mask your IP?[/bold yellow]",
        choices=["y", "n", "Y", "N"],
        default="y",
    )

    if use_proxy.lower() != "y":
        console.print("[bold red][!][/bold red] Proceeding WITHOUT proxy — your real IP will be visible to the target.")
        console.print("[dim]    Press Ctrl+C now if this is not intended.[/dim]")
        time.sleep(1.5)
        return None

    console.print()
    console.print("[bold]Select proxy type:[/bold]")
    console.print("  [bold white]1[/bold white]  HTTP Proxy (faster, less anonymous)")
    console.print("  [bold white]2[/bold white]  SOCKS5 Proxy (slower, more anonymous)")
    console.print("  [bold white]3[/bold white]  Random from all proxies")

    type_choice = Prompt.ask(
        "[bold cyan]Choice[/bold cyan]",
        choices=["1", "2", "3"],
        default="3",
    )

    if type_choice == "1":
        pool = categories["http"]
        if not pool:
            console.print("[red]No HTTP proxies available[/red]")
            return None
    elif type_choice == "2":
        pool = categories["socks5"]
        if not pool:
            console.print("[red]No SOCKS5 proxies available[/red]")
            return None
    else:
        pool = proxy_list

    sample_size = min(5, len(pool))
    sample = random.sample(pool, sample_size)
    console.print(f"\n[dim]Sample from pool ({len(pool)} total):[/dim]")
    for i, p in enumerate(sample, 1):
        scheme = p.split("://")[0].upper()
        addr = p.split("://")[1]
        console.print(f"  [dim]{i}. [{scheme}] {addr}[/dim]")
    if len(pool) > sample_size:
        console.print(f"  [dim]... and {len(pool) - sample_size} more[/dim]")

    console.print()
    console.print("  [bold white]r[/bold white]  Select random proxy from pool")
    console.print("  [bold white]s[/bold white]  Select specific proxy by number")

    pick_choice = Prompt.ask(
        "[bold cyan]Pick method[/bold cyan]",
        choices=["r", "s", "R", "S"],
        default="r",
    )

    if pick_choice.lower() == "s":
        try:
            num = int(Prompt.ask(f"[bold cyan]Enter proxy number (1-{len(pool)})[/bold cyan]"))
            if 1 <= num <= len(pool):
                selected = pool[num - 1]
            else:
                console.print(f"[red]Out of range. Selecting random.[/red]")
                selected = random.choice(pool)
        except (ValueError, EOFError):
            selected = random.choice(pool)
    else:
        selected = random.choice(pool)

    scheme = selected.split("://")[0].upper()
    addr = selected.split("://")[1]
    console.print()
    console.print(Panel.fit(
        f"[bold green][+] Using proxy: [{scheme}] {addr}[/bold green]\n"
        f"[dim]All scan traffic will be routed through this proxy.[/dim]\n"
        f"[dim]Your real IP will be hidden from the target.[/dim]",
        border_style="green",
    ))

    return selected


# =============================================================================
# Module Availability Detection
# =============================================================================

CORE_AVAILABLE = False
RECON_AVAILABLE = False
STEALTH_AVAILABLE = False
SCANNER_AVAILABLE = False
ZERODAY_AVAILABLE = False
BROWSER_AVAILABLE = False
ENTERPRISE_REPORTING_AVAILABLE = False
REPORTING_AVAILABLE = False

try:
    from core.models import ScanContext, Finding, Severity, FindingType
    from utils.http_client import ThrottledClient
    from utils.logger import get_logger

    CORE_AVAILABLE = True
except ImportError as e:
    print(f"[!] Core import failed: {e}")

if CORE_AVAILABLE:
    try:
        from recon.infrastructure import InfrastructureScanner

        RECON_AVAILABLE = True
    except ImportError:
        pass
    try:
        from stealth.waf_detector import WAFDetector
        from stealth.timing import AdaptiveTimingController

        STEALTH_AVAILABLE = True
    except ImportError:
        pass
    try:
        from scanner.auth_advanced import AuthAdvancedScanner
        from scanner.api_advanced import APIAdvancedScanner

        SCANNER_AVAILABLE = True
    except ImportError:
        pass
    try:
        from zeroday.engine import ZeroDayEngine
        from zeroday.financial import FinancialLogicScanner
        from zeroday.smuggling import SmugglingScanner

        ZERODAY_AVAILABLE = True
    except ImportError as e:
        print(f"[!] Zero-Day import failed: {e}")
    try:
        from browser.dom_xss import DOMXSSScanner
        from browser.postmessage import PostMessageScanner
        from browser.sw_cache import SWCacheScanner
        from browser.cors_bypass import CORSBypassScanner

        BROWSER_AVAILABLE = True
    except ImportError as e:
        print(f"[!] Browser Dynamics import failed: {e}")
    try:
        from core.reporting.enterprise import EnterpriseReporter

        ENTERPRISE_REPORTING_AVAILABLE = True
    except ImportError as e:
        print(f"[!] Enterprise Reporting import failed: {e}")

if CORE_AVAILABLE:
    try:
        from reporting.pdf_generator import PDFGenerator

        REPORTING_AVAILABLE = True
    except ImportError as e:
        print(f"[!] Reporting import failed: {e}")

console = Console()

BANNER = r"""
[bold red]
    █████╗   .   ██████╗   .   ███████╗   .   █████╗
   ██╔══██╗  .  ██╔══██╗  .  ██╔════╝  .  ██╔══██╗
   ███████║  .  ██████╔╝  .  ███████╗   .  ███████║
   ██╔══██║  .  ██╔══██╗  .  ╚════██║  .  ██╔══██║
   ██║  ██║  .  ██████╔╝  .  ███████║  .  ██║  ██║
   ╚═╝  ╚═╝  .  ╚═════╝   .  ╚══════╝  .  ╚═╝  ╚═╝
[/bold red]
[dim]              Advanced Breach & Security Assessment Framework[/dim]
"""

MAIN_MENU = """
[bold cyan]╔═════════════════════════════════════════════════════════╗
║                  A.B.S.A  —  Main Menu                      ║
╠═════════════════════════════════════════════════════════╣
║                                                            ║
║   [bold white]1[/bold white]  Reconnaissance & Infrastructure               ║
║   [bold white]2[/bold white]  Stealth & WAF Detection                     ║
║   [bold white]3[/bold white]  Vulnerability Scanner                        ║
║   [bold white]4[/bold white]  Zero-Day Simulation                         ║
║   [bold white]5[/bold white]  Client-Side & Browser Dynamics             ║
║   [bold white]6[/bold white]  Enterprise Reporting & Collaboration        ║
║   [bold white]7[/bold white]  Run All Phases                             ║
║   [bold red]0[/bold red]  Exit                                             ║
║                                                            ║
╚═════════════════════════════════════════════════════════╝[/bold cyan]
"""


# =============================================================================
# CLI Parser
# =============================================================================

def parse_args() -> Optional[argparse.Namespace]:
    parser = argparse.ArgumentParser(
        prog="absa.py",
        description="A.B.S.A - Advanced Breach & Security Assessment Framework",
    )
    parser.add_argument("-u", "--url", type=str, default=None,
                        help="Target URL (e.g., https://example.com)")
    parser.add_argument("--proxy", type=str, default=None,
                        help="Proxy URL (e.g., socks5://1.2.3.4:4145)")
    parser.add_argument("--real-ip", type=str, default=None,
                        help="Origin IP for Infrastructure scan")
    parser.add_argument("--jwt-token", type=str, default=None,
                        help="JWT token for Auth scanning")
    parser.add_argument("--graphql-url", type=str, default=None,
                        help="GraphQL endpoint URL")
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--impersonate", type=str, default="chrome120")
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("-v", "--verbose", action="store_true", default=False)
    parser.add_argument("--no-pdf", action="store_true", default=False,
                        help="Disable auto PDF generation after each phase")

    args = parser.parse_args()

    if args.url:
        url = args.url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        args.url = url.rstrip("/")
        return args

    return None


# =============================================================================
# Module Status
# =============================================================================

def print_module_status() -> None:
    modules = [
        ("Core Engine", CORE_AVAILABLE),
        ("Reconnaissance", RECON_AVAILABLE),
        ("Stealth & Evasion", STEALTH_AVAILABLE),
        ("Vulnerability Scanner", SCANNER_AVAILABLE),
        ("Zero-Day Engine", ZERODAY_AVAILABLE),
        ("Browser Dynamics", BROWSER_AVAILABLE),
        ("Enterprise Reporting", ENTERPRISE_REPORTING_AVAILABLE),
        ("PDF Reporting", REPORTING_AVAILABLE),
    ]
    table = Table(title="Module Status", width=55)
    table.add_column("Module", style="white")
    table.add_column("Status", justify="center")

    for name, ok in modules:
        if ok:
            table.add_row(name, "[green]● LOADED[/green]")
        else:
            table.add_row(name, "[red]○ MISSING[/red]")

    console.print(table)


# =============================================================================
# Session
# =============================================================================

class ScanSession:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.context: Optional[ScanContext] = None
        self.client: Optional[ThrottledClient] = None
        self.all_findings: List[Finding] = []
        self.target_url: str = args.url
        self.reports_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "reports"
        )
        self._logger = None
        self.selected_proxy: Optional[str] = None

    @property
    def logger(self):
        if self._logger is None:
            from utils.logger import get_logger
            self._logger = get_logger("session")
        return self._logger

    def initialize(self) -> bool:
        if not CORE_AVAILABLE:
            console.print("[bold red][-] Core modules missing. Cannot start.[/bold red]")
            return False

        try:
            domain = self.target_url.replace("https://", "").replace("http://", "").split("/")[0]
            if ":" in domain:
                domain = domain.split(":")[0]

            ctx_raw = {
                "target_url": self.target_url,
                "target_domain": domain,
                "target_port": 443 if "https" in self.target_url else 80,
                "concurrency": self.args.concurrency,
                "delay": self.args.delay,
                "timeout": self.args.timeout,
            }
            self.context = ScanContext(**safe_kwargs(ScanContext, ctx_raw))

            cli_raw = {
                "concurrency": self.args.concurrency,
                "delay": self.args.delay,
                "timeout": self.args.timeout,
            }
            self.client = ThrottledClient(**safe_kwargs(ThrottledClient, cli_raw))

            if self.selected_proxy:
                self.client.set_proxy(self.selected_proxy)

            return True

        except Exception as e:
            console.print(f"[bold red][-] Init failed: {e}[/bold red]")
            if self.args.verbose:
                import traceback
                traceback.print_exc()
            return False

    def collect_findings(self):
        if self.context and hasattr(self.context, "findings"):
            existing_titles = {f.title for f in self.all_findings}
            new_count = 0
            for f in self.context.findings:
                if f.title not in existing_titles:
                    self.all_findings.append(f)
                    existing_titles.add(f.title)
                    new_count += 1
            if new_count > 0:
                self.logger.debug("Collected %d new findings (total: %d)",
                                  new_count, len(self.all_findings))

    async def close(self):
        if self.client:
            await self.client.close()
            self.client = None

    def generate_pdf(self, phase_name: str) -> Optional[str]:
        if self.args.no_pdf:
            return None
        if not REPORTING_AVAILABLE:
            console.print("[dim][*] PDF module not available — skipping report.[/dim]")
            return None
        if not self.all_findings:
            console.print("[dim][*] No findings to report yet.[/dim]")
            return None

        try:
            os.makedirs(self.reports_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{phase_name}_{timestamp}.pdf"
            filepath = os.path.join(self.reports_dir, filename)

            generator = PDFGenerator(context=self.context)
            result_path = generator.generate(
                findings=self.all_findings,
                context=self.context,
                output_path=filepath,
            )
            console.print(f"\n[green][+][/green] PDF saved: [bold]{result_path}[/bold]")
            return result_path

        except Exception as e:
            console.print(f"[red][-] PDF generation failed: {e}[/red]")
            if self.args.verbose:
                import traceback
                traceback.print_exc()
            return None

    def print_findings_summary(self) -> None:
        if not self.all_findings:
            console.print("[dim]  No findings yet.[/dim]")
            return

        counts: Dict[str, int] = {}
        for f in self.all_findings:
            name = f.severity.name if hasattr(f.severity, "name") else str(f.severity)
            counts[name] = counts.get(name, 0) + 1

        cmap = {
            "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
            "LOW": "dim", "INFO": "dim",
        }
        parts = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = counts.get(sev, 0)
            if c:
                parts.append(f"[{cmap[sev]}]{sev}: {c}[/{cmap[sev]}]")
        console.print(
            "  " + " | ".join(parts)
            + f"  [dim](total: {len(self.all_findings)})[/dim]"
        )


# =============================================================================
# Phase Runners
# =============================================================================

async def run_recon(session: ScanSession) -> bool:
    if not RECON_AVAILABLE:
        console.print("[yellow][!][/yellow] Recon module not available.")
        return False

    console.print(Panel.fit(
        "[bold cyan][*] Phase 1: Reconnaissance & Infrastructure[/bold cyan]",
        border_style="cyan",
    ))
    try:
        raw = {"context": session.context, "client": session.client}
        scanner = InfrastructureScanner(**safe_kwargs(InfrastructureScanner, raw))
        results = await scanner.scan()
        session.collect_findings()

        table = Table(title="Infrastructure Summary", width=90)
        table.add_column("Category", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("CDN", str(results.get("cdn") or "None"))
        table.add_row("Real IP", str(results.get("real_ip") or "Not found"))

        open_ports = results.get("open_ports", [])
        port_str = ", ".join(str(p["port"]) for p in open_ports) if open_ports else "None"
        table.add_row("Open Ports", port_str)
        table.add_row("Admin Panels", str(len(results.get("admin_panels", []))))

        cloud_meta = results.get("cloud_metadata", {})
        cloud_exposed = any(v.get("accessible") for v in cloud_meta.values()) if cloud_meta else False
        table.add_row(
            "Cloud Metadata",
            "[red]EXPOSED[/red]" if cloud_exposed else "[green]Secure[/green]",
        )
        console.print(table)
        return True

    except Exception as e:
        console.print(f"[red][-] Recon failed: {e}[/red]")
        if session.args.verbose:
            import traceback
            traceback.print_exc()
        return False


async def run_stealth(session: ScanSession) -> bool:
    if not STEALTH_AVAILABLE:
        console.print("[yellow][!][/yellow] Stealth module not available.")
        return False

    console.print(Panel.fit(
        "[bold cyan][*] Phase 2: WAF Detection & Evasion Setup[/bold cyan]",
        border_style="cyan",
    ))
    try:
        waf = WAFDetector(http_client=session.client)
        resp = await session.client.get(session.context.target_url)
        result = await waf.detect(resp, session.context.target_url)

        if result.detected and result.primary_profile:
            p = result.primary_profile
            console.print(
                f"[bold red][!][/bold red] WAF: {p.vendor.value} "
                f"(Confidence: {p.confidence.name})"
            )
            if p.bypass_strategies:
                t = Table(title="Bypass Strategies")
                t.add_column("#", style="cyan", justify="right")
                t.add_column("Strategy", style="green")
                for i, s in enumerate(p.bypass_strategies, 1):
                    t.add_row(str(i), s)
                console.print(t)

            console.print("[*] Initializing Adaptive Timing Controller...")
            timer = AdaptiveTimingController(http_client=session.client)
            await timer.initialize(session.context.target_url, waf_profile=p)
            stats = timer.get_status()
            console.print(f"[green][+][/green] Safe delay: {stats['adaptive_delay']:.2f}s")
        else:
            console.print("[green][+][/green] No WAF detected.")
        return True

    except Exception as e:
        console.print(f"[red][-] Stealth failed: {e}[/red]")
        if session.args.verbose:
            import traceback
            traceback.print_exc()
        return False


async def run_scanner(session: ScanSession) -> bool:
    if not SCANNER_AVAILABLE:
        console.print("[yellow][!][/yellow] Vulnerability Scanner module not available.")
        return False

    console.print(Panel.fit(
        "[bold cyan][*] Phase 3: Vulnerability Scanner (Auth + API)[/bold cyan]",
        border_style="cyan",
    ))
    try:
        base_url = session.context.target_url

        auth_config = {
            "jwt_token": session.args.jwt_token,
            "enumerate_usernames": ["admin", "test", "root", "administrator"],
            "login_endpoint": f"{base_url}/login",
            "test_defaults": False,
        }
        auth_config = {k: v for k, v in auth_config.items() if v is not None}

        if auth_config:
            console.print("  [dim][*] Running Auth Advanced...[/dim]")
            auth_scanner = AuthAdvancedScanner(session.context, session.client)
            auth_findings = await auth_scanner.run(auth_config)
            session.collect_findings()
            if auth_findings:
                console.print(f"  [green][+][/green] Auth: {len(auth_findings)} finding(s)")

        api_config = {
            "graphql_endpoint": session.args.graphql_url,
            "test_websockets": True,
            "test_rate_limits": True,
        }
        api_config = {k: v for k, v in api_config.items() if v is not None}

        console.print("  [dim][*] Running API Advanced...[/dim]")
        api_scanner = APIAdvancedScanner(session.context, session.client)
        api_findings = await api_scanner.run(api_config)
        session.collect_findings()
        if api_findings:
            console.print(f"  [green][+][/green] API: {len(api_findings)} finding(s)")

        return True

    except Exception as e:
        console.print(f"[red][-] Scanner failed: {e}[/red]")
        if session.args.verbose:
            import traceback
            traceback.print_exc()
        return False


async def run_zeroday(session: ScanSession) -> bool:
    if not ZERODAY_AVAILABLE:
        console.print("[yellow][!][/yellow] Zero-Day module not available.")
        return False

    console.print(Panel.fit(
        "[bold red][*] Phase 4: Aggressive Zero-Day Simulation & Exploitation[/bold red]",
        border_style="red",
    ))
    try:
        base_url = session.context.target_url

        console.print("  [dim][*] Initializing Zero-Day Engine...[/dim]")
        zd_engine = ZeroDayEngine(session.context, session.client)

        zd_config = {
            "convert_endpoint": f"{base_url}/api/currency/convert",
            "tx_endpoint": f"{base_url}/api/transfer",
            "auth_headers": {"Authorization": f"Bearer {session.args.jwt_token}"} if session.args.jwt_token else None,
        }
        zd_config = {k: v for k, v in zd_config.items() if v is not None}

        await zd_engine.run(zd_config)
        session.collect_findings()

        return True

    except Exception as e:
        console.print(f"[red][-] Zero-Day failed: {e}[/red]")
        if session.args.verbose:
            import traceback
            traceback.print_exc()
        return False


async def run_browser_dynamics(session: ScanSession) -> bool:
    if not BROWSER_AVAILABLE:
        console.print("[yellow][!][/yellow] Browser Dynamics module not available.")
        return False

    console.print(Panel.fit(
        "[bold magenta][*] Phase 5: Advanced Client-Side & Browser Dynamics[/bold magenta]",
        border_style="magenta",
    ))
    try:
        console.print("  [dim][*] Running DOM XSS AST Parser...[/dim]")
        dom_scanner = DOMXSSScanner(session.context, session.client)
        dom_findings = await dom_scanner.run()
        session.collect_findings()
        if dom_findings:
            console.print(f"  [green][+][/green] DOM XSS: {len(dom_findings)} finding(s)")

        console.print("  [dim][*] Running PostMessage Exploits...[/dim]")
        pm_scanner = PostMessageScanner(session.context, session.client)
        pm_findings = await pm_scanner.run()
        session.collect_findings()
        if pm_findings:
            console.print(f"  [green][+][/green] PostMessage: {len(pm_findings)} finding(s)")

        console.print("  [dim][*] Running Service Worker Poisoning...[/dim]")
        sw_scanner = SWCacheScanner(session.context, session.client)
        sw_findings = await sw_scanner.run()
        session.collect_findings()
        if sw_findings:
            console.print(f"  [green][+][/green] SW Cache: {len(sw_findings)} finding(s)")

        console.print("  [dim][*] Running Advanced CORS Bypasses...[/dim]")
        cors_scanner = CORSBypassScanner(session.context, session.client)
        cors_findings = await cors_scanner.run()
        session.collect_findings()
        if cors_findings:
            console.print(f"  [green][+][/green] CORS: {len(cors_findings)} finding(s)")

        return True

    except Exception as e:
        console.print(f"[red][-] Browser Dynamics failed: {e}[/red]")
        if session.args.verbose:
            import traceback
            traceback.print_exc()
        return False


async def run_enterprise_reporting(session: ScanSession) -> bool:
    if not ENTERPRISE_REPORTING_AVAILABLE:
        console.print("[yellow][!][/yellow] Enterprise Reporting module not available.")
        return False

    console.print(Panel.fit(
        "[bold blue][*] Phase 6: Enterprise Reporting & Collaboration[/bold blue]",
        border_style="blue",
    ))
    try:
        if not session.all_findings:
            console.print("  [dim][*] No findings to report. Run scans first.[/dim]")
            return True

        console.print("  [dim][*] Generating Executive Metrics & Workflows...[/dim]")
        reporter = EnterpriseReporter(session.context)

        metrics = reporter.calculate_executive_metrics()

        metric_table = Table(title="Executive Risk Metrics", width=60)
        metric_table.add_column("Metric", style="white")
        metric_table.add_column("Value", justify="center", style="bold")

        # Safely resolve markup colors based on the score to avoid Rich parsing crashes
        risk_score = metrics["risk_score"]
        if risk_score > 30:
            score_markup = f"[bold red]{risk_score}[/bold red]"
        elif risk_score > 10:
            score_markup = f"[bold yellow]{risk_score}[/bold yellow]"
        else:
            score_markup = f"[bold green]{risk_score}[/bold green]"

        metric_table.add_row("Overall Risk Score (0-100)", score_markup)
        metric_table.add_row("Status", metrics["status"])
        metric_table.add_row("Total Vulnerabilities", str(metrics["total_vulnerabilities"]))
        metric_table.add_row("Exploitable Zero-Days", str(metrics["exploitable_zero_days"]))
        metric_table.add_row("Est. Remediation Effort", f"{metrics['remediation_effort_days']} Days")
        console.print(metric_table)

        workflow = reporter.generate_remediation_workflow()
        console.print("\n[bold]Remediation Roadmap:[/bold]")
        for phase, tasks in workflow.items():
            console.print(f"  [cyan]{phase}[/cyan] - {len(tasks)} task(s)")
            for task in tasks[:3]:
                console.print(f"    [dim]- {task}[/dim]")
            if len(tasks) > 3:
                console.print(f"    [dim]- ... and {len(tasks) - 3} more[/dim]")

        json_output = reporter.export_json()
        json_path = os.path.join(session.reports_dir, "enterprise_metrics.json")
        os.makedirs(session.reports_dir, exist_ok=True)
        with open(json_path, "w") as f:
            f.write(json_output)
        console.print(f"\n[green][+][/green] Enterprise JSON exported: [bold]{json_path}[/bold]")

        return True

    except Exception as e:
        # Cast string explicitly to ensure no stray objects break the Rich console parser
        console.print(f"[red][-] Enterprise Reporting failed: {str(e)}[/red]")
        if session.args.verbose:
            import traceback
            traceback.print_exc()
        return False


# =============================================================================
# Main Loop
# =============================================================================

async def main_loop(session: ScanSession):
    phase_runners = {
        "1": ("recon", run_recon),
        "2": ("stealth", run_stealth),
        "3": ("scanner", run_scanner),
        "4": ("zeroday", run_zeroday),
        "5": ("browser", run_browser_dynamics),
        "6": ("enterprise", run_enterprise_reporting),
    }

    while True:
        console.print()
        console.print(MAIN_MENU)

        console.print(f"  [dim]Target: {session.target_url}[/dim]")

        proxy_info = session.client.get_stealth_info() if session.client else {}
        proxy_str = proxy_info.get("proxy", "N/A")
        if proxy_str and proxy_str != "direct (NO PROXY — TRAFFIC NOT MASKED)":
            console.print(f"  [dim]Proxy: [green]{proxy_str}[/green][/dim]")
        else:
            console.print(f"  [dim]Proxy: [bold red]{proxy_str}[/bold red][/dim]")

        console.print("  ", end="")
        session.print_findings_summary()
        console.print()

        try:
            choice = Prompt.ask(
                "[bold cyan]Select option[/bold cyan]",
                choices=["0", "1", "2", "3", "4", "5", "6", "7"],
                default="1",
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Cancelled.[/dim]")
            break

        if choice == "0":
            console.print("\n[dim]Exiting A.B.S.A. Goodbye.[/dim]")
            break

        start = time.time()

        if choice == "7":
            console.print(Panel.fit(
                "[bold yellow][*] Running ALL phases sequentially...[/bold yellow]",
                border_style="yellow",
            ))
            for key in ["1", "2", "3", "4", "5", "6"]:
                phase_name, runner = phase_runners[key]
                console.print()
                ok = await runner(session)
                if not ok:
                    console.print(
                        f"[yellow][!][/yellow] {phase_name} phase failed or skipped, continuing..."
                    )

            elapsed = time.time() - start
            console.print(f"\n[dim]All phases completed in {elapsed:.1f}s[/dim]")
            session.generate_pdf("all_phases")

        else:
            phase_name, runner = phase_runners[choice]
            console.print()
            ok = await runner(session)

            elapsed = time.time() - start
            console.print(f"\n[dim]Phase completed in {elapsed:.1f}s[/dim]")

            if ok and phase_name != "enterprise":
                session.generate_pdf(phase_name)

        console.print()


# =============================================================================
# Entry Point
# =============================================================================

async def main():
    console.print(BANNER)
    console.print()

    args = parse_args()

    if args is None:
        try:
            url = Prompt.ask("[bold cyan]Enter target URL[/bold cyan]")
            if not url.strip():
                console.print("[red]No URL provided. Exiting.[/red]")
                return
            url = url.strip()
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            url = url.rstrip("/")

            args = argparse.Namespace(
                url=url,
                proxy=None,
                real_ip=None,
                jwt_token=None,
                graphql_url=None,
                concurrency=20,
                delay=0.5,
                timeout=15,
                impersonate="chrome120",
                retries=2,
                verbose=False,
                no_pdf=False,
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Cancelled.[/dim]")
            return

    if args.verbose:
        import logging
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
        try:
            from utils.logger import set_global_level
            set_global_level("DEBUG")
        except ImportError:
            pass

    print_module_status()
    console.print()

    if not CORE_AVAILABLE:
        console.print(Panel.fit(
            "[bold red]Core modules failed to load.[/bold red]\n"
            "[dim]Check: core/models.py, utils/http_client.py, utils/logger.py[/dim]",
            title="Fatal Error",
            border_style="red",
        ))
        return

    if not REPORTING_AVAILABLE:
        console.print(Panel.fit(
            "[bold yellow]PDF Reporting module not available.[/bold yellow]\n"
            "[dim]Check: reporting/pdf_generator.py, reporting/report_builder.py[/dim]",
            title="Warning",
            border_style="yellow",
        ))
        console.print()

    # =========================================================================
    # PROXY SELECTION
    # =========================================================================
    selected_proxy = None

    if args.proxy:
        selected_proxy = args.proxy
        console.print(Panel.fit(
            f"[bold green][+] CLI proxy: {selected_proxy}[/bold green]",
            border_style="green",
        ))
    else:
        proxy_list = load_proxy_list()
        if proxy_list:
            selected_proxy = proxy_prompt(proxy_list)
        else:
            console.print()
            console.print(Panel.fit(
                "[bold yellow][!] No proxies.txt found or file is empty.[/bold yellow]\n"
                "[dim]Traffic will be sent from your real IP.[/dim]\n"
                "[dim]Create proxies.txt in the ABSA root directory to enable proxy routing.[/dim]",
                border_style="yellow",
            ))

    session = ScanSession(args)
    session.selected_proxy = selected_proxy

    if not session.initialize():
        return

    config_lines = [
        f"[bold]Target:[/bold] {session.target_url}",
        f"[bold]Concurrency:[/bold] {args.concurrency} | "
        f"[bold]Delay:[/bold] {args.delay}s | "
        f"[bold]Timeout:[/bold] {args.timeout}s",
    ]

    if session.selected_proxy:
        scheme = session.selected_proxy.split("://")[0].upper()
        addr = session.selected_proxy.split("://")[1]
        config_lines.append(f"[bold green]Proxy:[/bold green] [{scheme}] {addr}")
    else:
        config_lines.append(f"[bold red]Proxy:[/bold red] NONE — Real IP exposed")

    if args.real_ip:
        config_lines.append(f"[bold]Real IP:[/bold] {args.real_ip}")
    if args.jwt_token:
        config_lines.append(f"[bold]JWT Token:[/bold] {args.jwt_token[:20]}...")
    if args.graphql_url:
        config_lines.append(f"[bold]GraphQL:[/bold] {args.graphql_url}")

    console.print(Panel(
        "\n".join(config_lines),
        title="[cyan]Session Initialized[/cyan]",
        border_style="cyan",
    ))

    try:
        await main_loop(session)
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted. Exiting.[/dim]")
    finally:
        await session.close()


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())