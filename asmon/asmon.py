#!/usr/bin/env python3
"""
asmon.py — Attack Surface Monitor CLI.

Entry point. Owns argument parsing, orchestration flow, and exit codes.
All heavy logic lives in the asmon package modules.

Usage examples:
    # Full passive scan with Shodan enrichment
    python -m asmon.asmon --target tesla.com --mode passive --shodan

    # Scan + diff against last snapshot
    python -m asmon.asmon --target tesla.com --shodan --diff

    # Scan + diff + AI summary, JSON output
    python -m asmon.asmon --target tesla.com --shodan --diff --ai-summary --output json

    # List all stored snapshots for a target
    python -m asmon.asmon --target tesla.com --list

Exit codes:
    0  — success, no changes (or no diff requested)
    1  — success, changes detected (when --diff is used)
    2  — user error (bad args, missing key)
    3  — runtime error (API failure, I/O error)
"""

import sys
import argparse
import uuid
import logging

# ---------------------------------------------------------------------------
# Imports — all absolute from asmon package
# ---------------------------------------------------------------------------
from asmon import config
from asmon.config import setup_logging
from asmon.models import Snapshot, HostRecord
from asmon.storage.snapshots import SnapshotStore
from asmon.discovery import PassiveDiscovery
from asmon.shodan import ShodanClient
from asmon.diff import compute_diff
from asmon.output import render_diff, render_snapshot_summary

logger: logging.Logger  # set after setup_logging()


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="asmon",
        description="Attack Surface Monitor — passive discovery and change detection.",
        epilog="All scanning is passive. No packets are sent to the target network.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # --- Required context ---
    parser.add_argument("--target", default=None,
                        help="Domain, URL, or organisation name to monitor.")
    parser.add_argument("--targets", default=None,
                        help="Path to targets.yaml for multi-target scanning. "
                             "Overrides --target.")

    # --- Mode ---
    parser.add_argument("--mode", choices=["passive"], default="passive",
                        help="Scan mode. Currently only 'passive' is supported.")

    # --- Data sources ---
    parser.add_argument("--shodan", action="store_true",
                        help="Enrich results using Shodan.")
    parser.add_argument("--shodan-key", default=None,
                        help="Shodan API key. Overrides SHODAN_API_KEY env var.")

    # --- Diff ---
    parser.add_argument("--diff", action="store_true",
                        help="Compare current scan against the previous snapshot.")
    parser.add_argument("--baseline", default=None,
                        help="Snapshot ID to use as baseline (default: most recent).")

    # --- AI ---
    parser.add_argument("--ai-summary", action="store_true",
                        help="Generate an AI-assisted summary of changes (requires --diff).")
    parser.add_argument("--ai-key", default=None,
                        help="AI provider API key. Overrides ASMON_AI_API_KEY.")
    parser.add_argument("--ai-provider", choices=["openai", "anthropic"], default=None,
                        help="AI provider to use.")
    parser.add_argument("--ai-model", default=None,
                        help="Model name (e.g. gpt-4o-mini, claude-haiku-3).")

    # --- Output ---
    parser.add_argument("--output", choices=["text", "json"], default="text",
                        help="Output format.")
    parser.add_argument("--report", choices=["html", "pdf"], default=None,
                        help="Generate an HTML or PDF report after scanning.")

    # --- Listing ---
    parser.add_argument("--list", action="store_true",
                        help="List all stored snapshots for the target and exit.")

    # --- Active Scanning ---
    active_group = parser.add_argument_group(
        "active scanning (AUTHORIZATION REQUIRED)",
        "These options enable direct network probing. "
        "Only use on assets you own or have written authorization to test."
    )
    active_group.add_argument(
        "--active",
        action="store_true",
        help="Enable active scanning (port scan + banner grab). REQUIRES AUTHORIZATION."
    )
    active_group.add_argument(
        "--active-ports",
        default="top100",
        help="Port range to scan. Options: 'top100', '1-65535', or '22,80,443'. Default: top100"
    )
    active_group.add_argument(
        "--active-rate-limit",
        type=int,
        default=100,
        help="Max connections per second. Default: 100"
    )
    active_group.add_argument(
        "--active-timeout",
        type=int,
        default=3,
        help="Connection timeout in seconds. Default: 3"
    )
    active_group.add_argument(
        "--active-cve-check",
        action="store_true",
        help="Correlate detected services with CVE database (metadata only, no exploits)."
    )

    # --- Web Risk Analysis ---
    web_group = parser.add_argument_group(
        "web risk analysis",
        "Passive HTTP observation for security exposure signals. "
        "Uses only HEAD/GET requests — no payloads, no fuzzing."
    )
    web_group.add_argument(
        "--web-risk",
        action="store_true",
        help="Enable web risk signal detection (headers, cookies, exposed endpoints)."
    )
    web_group.add_argument(
        "--web-risk-timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds. Default: 10"
    )
    web_group.add_argument(
        "--web-risk-no-endpoints",
        action="store_true",
        help="Skip checking for exposed sensitive endpoints."
    )

    # --- Vulnerability Scanning ---
    vuln_group = parser.add_argument_group(
        "vulnerability scanning (AUTHORIZATION REQUIRED)",
        "Active security testing modules. Sends payloads to detect vulnerabilities. "
        "ONLY use on systems you have explicit authorization to test."
    )
    vuln_group.add_argument(
        "--vuln-scan",
        action="store_true",
        help="Enable vulnerability scanning modules. REQUIRES AUTHORIZATION."
    )
    vuln_group.add_argument(
        "--vuln-modules",
        default=None,
        help="Comma-separated list of modules to run (default: all). "
             "Options: ssl_analysis,endpoint_discovery,subdomain_takeover,"
             "sqli_detection,xss_detection,lfi_detection,rce_detection,oob_detection"
    )
    vuln_group.add_argument(
        "--vuln-rate-limit",
        type=int,
        default=10,
        help="Max requests per second for vuln scanning. Default: 10"
    )
    vuln_group.add_argument(
        "--vuln-timeout",
        type=int,
        default=10,
        help="Request timeout for vuln scanning. Default: 10"
    )
    vuln_group.add_argument(
        "--callback-url",
        default=None,
        help="OOB callback server URL for blind vulnerability detection."
    )
    vuln_group.add_argument(
        "--vuln-skip-warning",
        action="store_true",
        help="Skip authorization warning prompt (for automation)."
    )
    vuln_group.add_argument(
        "--vuln-url",
        action="append",
        default=[],
        help="Specific URL(s) with parameters to test (can be used multiple times). "
             "Example: --vuln-url 'http://example.com/page?id=1'"
    )
    vuln_group.add_argument(
        "--vuln-crawl",
        action="store_true",
        help="Crawl the target to discover URLs with parameters for testing."
    )
    vuln_group.add_argument(
        "--vuln-crawl-depth",
        type=int,
        default=3,
        help="Maximum crawl depth for URL discovery. Default: 3"
    )
    vuln_group.add_argument(
        "--vuln-crawl-pages",
        type=int,
        default=50,
        help="Maximum pages to crawl. Default: 50"
    )

    # --- Slack Alerting ---
    alert_group = parser.add_argument_group(
        "slack alerting",
        "Send change notifications to Slack. "
        "Alerts are filtered to meaningful changes and deduplicated automatically."
    )
    alert_group.add_argument(
        "--slack-webhook",
        default=None,
        help="Slack incoming webhook URL. Requires --diff. "
             "Env var: ASMON_SLACK_WEBHOOK."
    )

    # --- Scheduling ---
    sched_group = parser.add_argument_group(
        "scheduling",
        "Run scans repeatedly on a fixed interval. "
        "Ctrl+C stops gracefully after the current cycle."
    )
    sched_group.add_argument(
        "--schedule",
        type=int,
        default=None,
        metavar="MINUTES",
        help="Re-run the scan every N minutes (e.g. --schedule 360 for every 6 hours)."
    )
    sched_group.add_argument(
        "--max-cycles",
        type=int,
        default=0,
        help="Stop after N cycles (default: 0 = unlimited)."
    )

    # --- Retention ---
    retain_group = parser.add_argument_group(
        "snapshot retention",
        "Automatically clean up old snapshots to save disk space. "
        "Runs after each scan completes."
    )
    retain_group.add_argument(
        "--retain",
        type=int,
        default=0,
        metavar="N",
        help="Keep only the N most recent snapshots per target (0 = unlimited)."
    )
    retain_group.add_argument(
        "--retain-days",
        type=int,
        default=0,
        metavar="DAYS",
        help="Delete snapshots older than N days (0 = unlimited). "
             "The most recent snapshot is always kept."
    )
    retain_group.add_argument(
        "--storage-info",
        action="store_true",
        help="Show snapshot storage usage and exit."
    )

    # --- Dashboard ---
    dash_group = parser.add_argument_group(
        "web dashboard",
        "Launch the ASMON web UI. No login required."
    )
    dash_group.add_argument(
        "--dashboard",
        action="store_true",
        help="Start the web dashboard on http://localhost:8000"
    )
    dash_group.add_argument(
        "--dashboard-host",
        default="0.0.0.0",
        help="Dashboard bind address. Default: 0.0.0.0"
    )
    dash_group.add_argument(
        "--dashboard-port",
        type=int,
        default=8000,
        help="Dashboard port. Default: 8000"
    )

    # --- Misc ---
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        default=None, help="Override log level.")
    parser.add_argument("--clean", action="store_true",
                        help="Delete the snapshot created during this run after output is printed.")

    return parser


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _create_basic_host(ip: str, hostnames: list[str] | None = None) -> HostRecord:
    """
    Create a minimal host record from discovered IP without Shodan enrichment.
    Used when Shodan is disabled or enrichment fails.
    """
    return HostRecord(
        ip=ip,
        hostnames=hostnames or [],
        services=[],
        source="discovery",
        shodan_enriched=False,
    )


def _build_ip_to_hostnames(disc_results: dict) -> dict[str, list[str]]:
    """
    Build a mapping from IP → list of hostnames from discovery results.
    This ensures we preserve hostname info even without Shodan.
    """
    ip_to_hostnames: dict[str, list[str]] = {}
    for hostname, ips in disc_results.get("resolved", {}).items():
        for ip in ips:
            if ip not in ip_to_hostnames:
                ip_to_hostnames[ip] = []
            if hostname not in ip_to_hostnames[ip]:
                ip_to_hostnames[ip].append(hostname)
    return ip_to_hostnames


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def main() -> int:
    """
    Main flow:
      1. Parse args, set up logging.
      2. If --list, print snapshots and exit.
      3. Run passive discovery (always).
      4. If --shodan, enrich discovered IPs via Shodan.
      5. Build and persist a new Snapshot.
      6. If --diff, load baseline and compute diff.
      7. If --ai-summary, run AI analysis on the diff.
      8. Print output.

    Returns an exit code (see module docstring).
    """
    global logger
    parser = build_parser()
    args = parser.parse_args()

    # Logging
    setup_logging(args.log_level)
    logger = logging.getLogger("asmon")

    # --- Dashboard mode (early exit) ---
    if args.dashboard:
        try:
            import uvicorn
            from asmon.dashboard.app import app
        except ImportError as exc:
            logger.error("Dashboard requires: pip install fastapi uvicorn[standard]")
            return 2
        print(f"\n  ASMON Dashboard: http://localhost:{args.dashboard_port}\n")
        uvicorn.run(app, host=args.dashboard_host, port=args.dashboard_port)
        return 0

    # --- Storage info (early exit) ---
    if args.storage_info:
        store = SnapshotStore(config.SNAPSHOT_DIR)
        usage = store.disk_usage()
        print(f"\n  Snapshot storage: {config.SNAPSHOT_DIR}")
        print(f"  Files: {usage['total_files']}  |  Size: {usage['total_mb']} MB  |  Targets: {usage['targets']}")
        for target in store.list_targets():
            count = len(list(config.SNAPSHOT_DIR.glob(f"{store._safe_target_name(target)}_*.json")))
            print(f"    {target}: {count} snapshot(s)")
        print()
        return 0

    # --- Multi-target mode (early branch) ---
    if args.targets:
        from asmon.targets import load_targets
        from asmon.orchestrator import run_targets
        import os

        try:
            target_configs = load_targets(args.targets)
        except (FileNotFoundError, ValueError, ImportError) as exc:
            logger.error(str(exc))
            return 2

        slack_webhook = getattr(args, 'slack_webhook', None) or os.environ.get("ASMON_SLACK_WEBHOOK")

        def _multi_scan() -> int:
            results = run_targets(
                target_configs,
                slack_webhook=slack_webhook,
                output_fmt=args.output,
                report_fmt=args.report,
                retain=args.retain,
                retain_days=args.retain_days,
            )
            has_changes = any(r.diff and r.diff.changes for r in results)
            has_errors = any(r.error for r in results)
            if has_errors:
                return 3
            return 1 if has_changes else 0

        # Wrap in scheduler if --schedule is set
        if args.schedule:
            from asmon.scheduler import run_scheduled
            return run_scheduled(_multi_scan, args.schedule, args.max_cycles)

        return _multi_scan()

    # --- Single-target mode (original flow) ---
    if not args.target:
        parser.error("--target or --targets is required")

    # Storage
    store = SnapshotStore(config.SNAPSHOT_DIR)

    # --- --list mode (early exit) ---
    if args.list:
        return _handle_list(store, args.target)

    # --- Schedule wrapper for single-target mode ---
    if args.schedule:
        from asmon.scheduler import run_scheduled
        def _single_scan() -> int:
            return _run_single_scan(args, store)
        return run_scheduled(_single_scan, args.schedule, args.max_cycles)

    return _run_single_scan(args, store)


def _run_single_scan(args, store) -> int:
    """Run one full single-target scan cycle. Extracted for scheduler reuse."""

    # --- Discovery phase ---
    logger.info("Starting scan for target: %s", args.target)
    discovery = PassiveDiscovery()

    try:
        disc_results = discovery.discover(args.target)
    except ValueError as exc:
        logger.error("Invalid target: %s", exc)
        return 2

    discovered_ips: list[str] = disc_results["unique_ips"]
    logger.info("Passive discovery: %d subdomains, %d IPs",
                len(disc_results["subdomains"]), len(discovered_ips))

    # --- Build IP→hostname mapping from discovery ---
    ip_to_hostnames = _build_ip_to_hostnames(disc_results)

    # --- Shodan enrichment ---
    hosts = []
    if args.shodan:
        shodan_key = args.shodan_key or config.SHODAN_API_KEY
        try:
            shodan = ShodanClient(api_key=shodan_key)
        except ValueError as exc:
            logger.error(str(exc))
            return 2

        # Strategy: if we have <= 50 IPs, look up each individually.
        # Otherwise, do a domain search (more efficient for large surfaces).
        root_domain = disc_results["root_domain"]

        if len(discovered_ips) <= 50:
            logger.info("Enriching %d IPs individually via Shodan.", len(discovered_ips))
            for ip in discovered_ips:
                try:
                    host = shodan.host_details(ip)
                    if host:
                        # Merge discovered hostnames with Shodan data
                        for hn in ip_to_hostnames.get(ip, []):
                            if hn not in host.hostnames:
                                host.hostnames.append(hn)
                        hosts.append(host)
                    else:
                        # No Shodan data available - create basic record
                        hosts.append(_create_basic_host(ip, ip_to_hostnames.get(ip, [])))
                except Exception as exc:
                    logger.warning("Shodan lookup failed for %s: %s", ip, exc)
                    # Preserve discovery data even when enrichment fails
                    hosts.append(_create_basic_host(ip, ip_to_hostnames.get(ip, [])))
        else:
            logger.info("Running Shodan domain search for %s", root_domain)
            try:
                hosts = shodan.search_domain(root_domain)
                # Shodan domain search may miss some discovered IPs
                # Add any discovered IPs not in Shodan results as basic records
                shodan_ips = {h.ip for h in hosts}
                for ip in discovered_ips:
                    if ip not in shodan_ips:
                        logger.debug("IP %s not in Shodan results, adding as basic record", ip)
                        hosts.append(_create_basic_host(ip, ip_to_hostnames.get(ip, [])))
            except Exception as exc:
                logger.warning("Shodan search failed: %s", exc)
                # Fallback: create basic records for all discovered IPs
                logger.info("Using discovery data without Shodan enrichment")
                hosts = [_create_basic_host(ip, ip_to_hostnames.get(ip, [])) for ip in discovered_ips]
    else:
        logger.info("Shodan not enabled. Creating records from passive discovery.")
        hosts = [_create_basic_host(ip, ip_to_hostnames.get(ip, [])) for ip in discovered_ips]

    # --- InternetDB enrichment (free, always-on) ---
    if hosts:
        from asmon.internetdb import InternetDBClient
        try:
            idb = InternetDBClient()
            idb_stats = idb.enrich_hosts(hosts)
            logger.info(
                "InternetDB: +%d ports, +%d CVEs across %d/%d hosts",
                idb_stats["new_ports_added"],
                idb_stats["new_cves_added"],
                idb_stats["enriched"],
                idb_stats["queried"],
            )
        except Exception as exc:
            logger.warning("InternetDB enrichment failed (non-fatal): %s", exc)

    # --- CISA KEV enrichment (free, always-on) ---
    # Cross-references CVEs with actively exploited vulnerabilities catalog
    has_cves = any(len(h.cves) > 0 for h in hosts)
    if hosts and has_cves:
        from asmon.cisa_kev import CISAKEVClient
        try:
            kev = CISAKEVClient()
            kev_stats = kev.enrich_hosts(hosts)
            if kev_stats["kev_matches"] > 0:
                logger.warning(
                    "CISA KEV: %d CVE(s) are ACTIVELY EXPLOITED in the wild!",
                    kev_stats["kev_matches"],
                )
            if kev_stats["ransomware_linked"] > 0:
                logger.warning(
                    "CISA KEV: %d CVE(s) linked to RANSOMWARE campaigns!",
                    kev_stats["ransomware_linked"],
                )
        except Exception as exc:
            logger.warning("CISA KEV enrichment failed (non-fatal): %s", exc)

    # --- EPSS enrichment (free, always-on) ---
    # Adds exploitation probability scores to CVEs
    has_cves = any(len(h.cves) > 0 for h in hosts)
    if hosts and has_cves:
        from asmon.epss import EPSSClient
        try:
            epss = EPSSClient()
            epss_stats = epss.enrich_hosts(hosts)
            if epss_stats["high_risk_cves"] > 0:
                logger.warning(
                    "EPSS: %d CVE(s) have >=70%% exploitation probability in next 30 days",
                    epss_stats["high_risk_cves"],
                )
        except Exception as exc:
            logger.warning("EPSS enrichment failed (non-fatal): %s", exc)

    # --- DNS security checks (free, always-on) ---
    # Checks SPF, DMARC, DNSSEC, CAA records on the root domain
    if hosts:
        from asmon.dns_security import DNSSecurityChecker
        try:
            dns_checker = DNSSecurityChecker()
            root_domain = disc_results["root_domain"]
            dns_signals = dns_checker.check(root_domain)
            if dns_signals:
                logger.info("DNS security: %d finding(s) for %s", len(dns_signals), root_domain)
                # Attach DNS findings to the first host as web risk signals
                from asmon.models import WebRiskReport
                dns_report = WebRiskReport(
                    host=root_domain,
                    port=53,
                    url=f"dns://{root_domain}",
                    signals=dns_signals,
                    http_accessible=False,
                    https_accessible=False,
                )
                hosts[0].web_risks.append(dns_report)
        except Exception as exc:
            logger.warning("DNS security check failed (non-fatal): %s", exc)

    # --- Active scanning (NEW) ---
    if args.active:
        logger.warning("ACTIVE SCANNING ENABLED - Ensure you have authorization to scan these targets")

        from asmon.active.scanner import ActiveScanner, merge_active_results

        scanner = ActiveScanner(
            port_spec=args.active_ports,
            rate_limit=args.active_rate_limit,
            timeout=args.active_timeout,
            enable_cve_check=args.active_cve_check,
        )

        logger.info("Starting active scan on %d hosts", len(hosts))
        for host in hosts:
            try:
                active_data = scanner.scan_host(host.ip)
                merge_active_results(host, active_data)
            except Exception as exc:
                logger.warning("Active scan failed for %s: %s", host.ip, exc)

    # --- Web risk analysis ---
    if args.web_risk:
        logger.info("Web risk analysis enabled - using passive HTTP observation")

        from asmon.web.analyzer import WebRiskAnalyzer, merge_web_risk_results

        web_analyzer = WebRiskAnalyzer(
            timeout=args.web_risk_timeout,
            check_endpoints=not args.web_risk_no_endpoints,
        )

        logger.info("Starting web risk scan on %d hosts", len(hosts))
        for host in hosts:
            try:
                # Determine which ports to scan for web services
                web_ports = []

                # Check services for HTTP/HTTPS ports
                for svc in host.services:
                    if svc.port in (80, 443, 8080, 8443, 8000, 8888) or \
                       (svc.service_name and svc.service_name.lower() in ("http", "https")):
                        web_ports.append(svc.port)

                # Default to 443 and 80 if no services detected
                if not web_ports:
                    web_ports = [443, 80]

                # Use first hostname if available, otherwise IP
                hostname = host.hostnames[0] if host.hostnames else None

                reports = []
                for port in set(web_ports):
                    try:
                        report = web_analyzer.analyze(host.ip, port=port, hostname=hostname)
                        if report.signals:  # Only add if we found something
                            reports.append(report)
                    except Exception as port_exc:
                        logger.debug("Web risk scan failed for %s:%d: %s", host.ip, port, port_exc)

                merge_web_risk_results(host, reports)

            except Exception as exc:
                logger.warning("Web risk scan failed for %s: %s", host.ip, exc)

    # --- Vulnerability scanning ---
    if args.vuln_scan:
        logger.warning("VULNERABILITY SCANNING ENABLED - Ensure you have authorization")

        from asmon.modules.orchestrator import ModuleOrchestrator
        from asmon.modules.crawler import WebCrawler, form_to_url

        # Parse module list
        modules_to_run = None
        if args.vuln_modules:
            modules_to_run = [m.strip() for m in args.vuln_modules.split(",")]

        orchestrator = ModuleOrchestrator(
            rate_limit=args.vuln_rate_limit,
            timeout=args.vuln_timeout,
            callback_url=args.callback_url,
            show_warning=not args.vuln_skip_warning,
        )

        # Collect URLs to test
        urls_to_test: list[str] = []

        # Add manually specified URLs
        if args.vuln_url:
            urls_to_test.extend(args.vuln_url)
            logger.info("Added %d manually specified URLs", len(args.vuln_url))

        # Crawl to discover URLs with parameters
        if args.vuln_crawl:
            crawler = WebCrawler(
                max_pages=args.vuln_crawl_pages,
                max_depth=args.vuln_crawl_depth,
                timeout=args.vuln_timeout,
                rate_limit=args.vuln_rate_limit,
            )

            for host in hosts:
                hostname = host.hostnames[0] if host.hostnames else None
                base_url = f"https://{hostname or host.ip}"

                logger.info("Crawling %s for injectable URLs...", base_url)
                try:
                    result = crawler.crawl(base_url)
                    urls_to_test.extend(result.urls_with_params)

                    # Convert forms to testable URLs
                    for form in result.forms:
                        form_url = form_to_url(form)
                        if form_url:
                            urls_to_test.append(form_url)

                    logger.info("Discovered %d URLs with parameters, %d forms",
                               len(result.urls_with_params), len(result.forms))
                except Exception as crawl_exc:
                    logger.warning("Crawl failed for %s: %s", base_url, crawl_exc)

        # Deduplicate URLs
        urls_to_test = list(set(urls_to_test))

        if not urls_to_test:
            logger.warning(
                "No URLs with parameters found! Use --vuln-crawl to discover URLs, "
                "or --vuln-url to specify URLs manually. "
                "Example: --vuln-url 'http://example.com/page?id=1'"
            )

        logger.info("Testing %d URLs for vulnerabilities", len(urls_to_test))

        # Run vuln scan on each URL
        all_findings = []
        for url in urls_to_test:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host_ip = parsed.netloc.split(":")[0]

                target_spec = {
                    "host": host_ip,
                    "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                    "url": url,
                    "hostname": parsed.netloc.split(":")[0],
                    "subdomains": [],
                }

                findings = orchestrator.run_modules(
                    target_spec,
                    modules=modules_to_run,
                    skip_warning=True,
                )
                all_findings.extend(findings)

            except Exception as exc:
                logger.warning("Vulnerability scan failed for %s: %s", url, exc)

        # Also run non-injection modules (ssl_analysis, subdomain_takeover, endpoint_discovery) on hosts
        non_injection_modules = ["ssl_analysis", "subdomain_takeover", "endpoint_discovery"]
        if not modules_to_run or any(m in non_injection_modules for m in (modules_to_run or [])):
            logger.info("Running host-level security modules on %d hosts", len(hosts))

        for host in hosts:
            try:
                hostname = host.hostnames[0] if host.hostnames else None
                base_url = f"https://{hostname or host.ip}"

                target_spec = {
                    "host": host.ip,
                    "port": 443,
                    "url": base_url,
                    "hostname": hostname,
                    "subdomains": host.hostnames,
                }

                # Only run host-level modules here
                host_modules = [m for m in (modules_to_run or non_injection_modules) if m in non_injection_modules]
                if host_modules:
                    findings = orchestrator.run_modules(
                        target_spec,
                        modules=host_modules,
                        skip_warning=True,
                    )
                    all_findings.extend(findings)

                # Store findings in host record
                host.vuln_findings = [f.model_dump() for f in all_findings if f.host == host.ip]
                host.vuln_scanned = True

            except Exception as exc:
                logger.warning("Host-level scan failed for %s: %s", host.ip, exc)

        logger.info("Vulnerability scan complete: %d total findings", len(all_findings))

    # --- Compute risk score ---
    from asmon.scoring import compute_risk_score
    risk_score = compute_risk_score(
        Snapshot(
            snapshot_id="temp",
            target=args.target,
            hosts=hosts,
        )
    )

    # --- Build snapshot ---
    snapshot = Snapshot(
        snapshot_id=str(uuid.uuid4()),
        target=args.target,
        hosts=hosts,
        metadata={
            "mode": args.mode,
            "shodan_enabled": args.shodan,
            "subdomains_discovered": len(disc_results["subdomains"]),
            "ips_discovered": len(discovered_ips),
        },
        active_scan_enabled=args.active,
        web_risk_enabled=args.web_risk,
        vuln_scan_enabled=args.vuln_scan,
        risk_score=risk_score,
    )

    saved_path = store.save(snapshot)
    logger.info("Snapshot saved: %s", saved_path)

    # Print snapshot summary
    print(render_snapshot_summary(snapshot))

    # --- Diff phase ---
    exit_code = 0
    diff_result = None
    if args.diff:
        # Load baseline
        if args.baseline:
            baseline = store.get(args.baseline)
            if not baseline:
                logger.error("Baseline snapshot not found: %s", args.baseline)
                return 2
        else:
            # Get the snapshot before the one we just saved
            all_snaps = store.list_snapshots(args.target)
            if len(all_snaps) < 2:
                print("\n  No previous snapshot to diff against. Run again to establish a baseline.\n")
            else:
                baseline = all_snaps[1]  # [0] is the one we just saved

                diff = compute_diff(baseline, snapshot)
                diff_result = diff
                print(render_diff(diff, fmt=args.output))

                # --- Slack alerting ---
                import os
                slack_webhook = getattr(args, 'slack_webhook', None) or os.environ.get("ASMON_SLACK_WEBHOOK")
                if slack_webhook and diff.changes:
                    try:
                        from asmon.alerters.slack import SlackAlerter
                        alerter = SlackAlerter(webhook_url=slack_webhook)
                        alerter.send(
                            diff=diff,
                            snapshot_id=snapshot.snapshot_id,
                            baseline_id=baseline.snapshot_id,
                        )
                    except Exception as exc:
                        logger.warning("Slack alerting failed (non-fatal): %s", exc)

                # --- AI summary ---
                if args.ai_summary:
                    if args.output == "json":
                        # In JSON mode, append AI analysis as a separate top-level block
                        import json
                        from asmon.analysis import analyse_diff
                        analysis = analyse_diff(
                            diff,
                            api_key=args.ai_key,
                            provider=args.ai_provider,
                            model=args.ai_model,
                        )
                        output = {
                            "diff": diff.model_dump(),
                            "ai_analysis": analysis.model_dump(),
                        }
                        print(json.dumps(output, indent=2, default=str))
                    else:
                        from asmon.analysis import analyse_diff, render_analysis
                        analysis = analyse_diff(
                            diff,
                            api_key=args.ai_key,
                            provider=args.ai_provider,
                            model=args.ai_model,
                        )
                        print(render_analysis(analysis))

                # Exit code: 1 if changes were detected
                exit_code = 1 if diff.changes else 0

    # --- Report generation ---
    if args.report:
        from asmon.report import save_html_report, save_pdf_report
        try:
            if args.report == "pdf":
                report_path = save_pdf_report(snapshot, diff=diff_result)
            else:
                report_path = save_html_report(snapshot, diff=diff_result)
            print(f"\n  Report saved: {report_path}\n")
        except Exception as exc:
            logger.warning("Report generation failed: %s", exc)

    # --- Retention policy ---
    if args.retain > 0 or args.retain_days > 0:
        deleted = store.enforce_retention(
            args.target, keep=args.retain, max_age_days=args.retain_days,
        )
        if deleted > 0:
            print(f"  Retention: cleaned up {deleted} old snapshot(s)")

    # --- Cleanup phase (after all output) ---
    if args.clean:
        try:
            if saved_path.exists():
                saved_path.unlink()
                logger.info("Cleaned up snapshot: %s", saved_path)
        except Exception as exc:
            logger.warning("Failed to clean up snapshot: %s", exc)

    return exit_code


# ---------------------------------------------------------------------------
# Sub-handlers
# ---------------------------------------------------------------------------

def _handle_list(store: SnapshotStore, target: str) -> int:
    """Print all snapshots for a target."""
    snapshots = store.list_snapshots(target)
    if not snapshots:
        print(f"\n  No snapshots found for '{target}'.\n")
        return 0

    print(f"\n  Snapshots for '{target}':\n")
    for snap in snapshots:
        print(f"    {render_snapshot_summary(snap)}\n")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    sys.exit(main())
