"""
orchestrator.py — Multi-target scan runner.

Takes a list of TargetConfig objects and runs the full ASMON pipeline
for each one sequentially.  Each target gets its own snapshot and diff.

Design decisions:
  - Sequential execution (no threading) — simpler, respects API rate limits.
  - One failure never stops the rest — each target is isolated.
  - Returns a summary dict so the caller can print/alert on aggregate results.
  - Reuses the same enrichment pipeline as single-target mode.
"""

import uuid
import logging
from datetime import datetime, timezone

from asmon import config
from asmon.models import Snapshot, WebRiskReport
from asmon.storage.snapshots import SnapshotStore
from asmon.discovery import PassiveDiscovery
from asmon.diff import compute_diff
from asmon.output import render_diff, render_snapshot_summary
from asmon.targets import TargetConfig

logger = logging.getLogger("asmon.orchestrator")


# ------------------------------------------------------------------
# Per-target result
# ------------------------------------------------------------------

class TargetResult:
    """Holds the outcome of scanning a single target."""

    def __init__(self, target: TargetConfig):
        self.target = target
        self.snapshot: Snapshot | None = None
        self.diff = None
        self.error: str | None = None
        self.stats: dict = {}


# ------------------------------------------------------------------
# Orchestrator
# ------------------------------------------------------------------

def run_targets(
    targets: list[TargetConfig],
    slack_webhook: str | None = None,
    output_fmt: str = "text",
    report_fmt: str | None = None,
    retain: int = 0,
    retain_days: int = 0,
) -> list[TargetResult]:
    """
    Run the full ASMON pipeline for each target.

    Returns a list of TargetResult objects (one per target).
    """
    store = SnapshotStore(config.SNAPSHOT_DIR)
    discovery = PassiveDiscovery()
    results: list[TargetResult] = []

    total = len(targets)
    for idx, tc in enumerate(targets, 1):
        result = TargetResult(tc)
        label = tc.label or tc.domain
        logger.info("=" * 60)
        logger.info("[%d/%d] Scanning: %s", idx, total, label)
        logger.info("=" * 60)

        try:
            _run_single(tc, store, discovery, result, slack_webhook, output_fmt)
        except Exception as exc:
            result.error = str(exc)
            logger.error("Target %s failed: %s", tc.domain, exc)

        # Generate per-target report
        if report_fmt and result.snapshot:
            try:
                from asmon.report import save_html_report, save_pdf_report
                if report_fmt == "pdf":
                    rpath = save_pdf_report(result.snapshot, diff=result.diff)
                else:
                    rpath = save_html_report(result.snapshot, diff=result.diff)
                print(f"  Report saved: {rpath}")
            except Exception as exc:
                logger.warning("Report generation failed for %s: %s", tc.domain, exc)

        results.append(result)

    # --- Retention policy ---
    if retain > 0 or retain_days > 0:
        total_deleted = store.enforce_retention_all(keep=retain, max_age_days=retain_days)
        if total_deleted > 0:
            print(f"  Retention: cleaned up {total_deleted} old snapshot(s)")

    # Print aggregate summary
    _print_summary(results)
    return results


# ------------------------------------------------------------------
# Single-target pipeline (mirrors asmon.py main flow)
# ------------------------------------------------------------------

def _run_single(
    tc: TargetConfig,
    store: SnapshotStore,
    discovery: PassiveDiscovery,
    result: TargetResult,
    slack_webhook: str | None,
    output_fmt: str,
) -> None:
    """Run full pipeline for one target. Populates result in place."""

    # --- Discovery ---
    disc_results = discovery.discover(tc.domain)
    discovered_ips: list[str] = disc_results["unique_ips"]
    logger.info("Discovery: %d subdomains, %d IPs", len(disc_results["subdomains"]), len(discovered_ips))

    ip_to_hostnames: dict[str, list[str]] = {}
    for hostname, ips in disc_results.get("resolved", {}).items():
        for ip in ips:
            if ip not in ip_to_hostnames:
                ip_to_hostnames[ip] = []
            if hostname not in ip_to_hostnames[ip]:
                ip_to_hostnames[ip].append(hostname)

    # --- Shodan enrichment ---
    from asmon.models import HostRecord
    hosts = []

    if tc.shodan:
        shodan_key = config.SHODAN_API_KEY
        if shodan_key:
            from asmon.shodan import ShodanClient
            try:
                shodan = ShodanClient(api_key=shodan_key)
                root_domain = disc_results["root_domain"]
                if len(discovered_ips) <= 50:
                    for ip in discovered_ips:
                        try:
                            host = shodan.host_details(ip)
                            if host:
                                for hn in ip_to_hostnames.get(ip, []):
                                    if hn not in host.hostnames:
                                        host.hostnames.append(hn)
                                hosts.append(host)
                            else:
                                hosts.append(_basic_host(ip, ip_to_hostnames.get(ip, [])))
                        except Exception as exc:
                            logger.warning("Shodan lookup failed for %s: %s", ip, exc)
                            hosts.append(_basic_host(ip, ip_to_hostnames.get(ip, [])))
                else:
                    hosts = shodan.search_domain(root_domain)
                    shodan_ips = {h.ip for h in hosts}
                    for ip in discovered_ips:
                        if ip not in shodan_ips:
                            hosts.append(_basic_host(ip, ip_to_hostnames.get(ip, [])))
            except Exception as exc:
                logger.warning("Shodan failed for %s: %s", tc.domain, exc)
                hosts = [_basic_host(ip, ip_to_hostnames.get(ip, [])) for ip in discovered_ips]
        else:
            logger.warning("Shodan enabled for %s but no API key set", tc.domain)
            hosts = [_basic_host(ip, ip_to_hostnames.get(ip, [])) for ip in discovered_ips]
    else:
        hosts = [_basic_host(ip, ip_to_hostnames.get(ip, [])) for ip in discovered_ips]

    # --- InternetDB enrichment ---
    if hosts:
        from asmon.internetdb import InternetDBClient
        try:
            idb = InternetDBClient()
            idb_stats = idb.enrich_hosts(hosts)
            result.stats["internetdb"] = idb_stats
        except Exception as exc:
            logger.warning("InternetDB failed (non-fatal): %s", exc)

    # --- CISA KEV ---
    has_cves = any(len(h.cves) > 0 for h in hosts)
    if hosts and has_cves:
        from asmon.cisa_kev import CISAKEVClient
        try:
            kev = CISAKEVClient()
            kev_stats = kev.enrich_hosts(hosts)
            result.stats["cisa_kev"] = kev_stats
            if kev_stats["kev_matches"] > 0:
                logger.warning("CISA KEV: %d actively exploited CVE(s)!", kev_stats["kev_matches"])
        except Exception as exc:
            logger.warning("CISA KEV failed (non-fatal): %s", exc)

    # --- EPSS ---
    has_cves = any(len(h.cves) > 0 for h in hosts)
    if hosts and has_cves:
        from asmon.epss import EPSSClient
        try:
            epss = EPSSClient()
            epss_stats = epss.enrich_hosts(hosts)
            result.stats["epss"] = epss_stats
        except Exception as exc:
            logger.warning("EPSS failed (non-fatal): %s", exc)

    # --- DNS security ---
    if hosts:
        from asmon.dns_security import DNSSecurityChecker
        try:
            dns_checker = DNSSecurityChecker()
            root_domain = disc_results["root_domain"]
            dns_signals = dns_checker.check(root_domain)
            if dns_signals:
                dns_report = WebRiskReport(
                    host=root_domain, port=53,
                    url=f"dns://{root_domain}",
                    signals=dns_signals,
                    http_accessible=False, https_accessible=False,
                )
                hosts[0].web_risks.append(dns_report)
        except Exception as exc:
            logger.warning("DNS security failed (non-fatal): %s", exc)

    # --- Risk scoring ---
    from asmon.scoring import compute_risk_score
    risk_score = compute_risk_score(
        Snapshot(snapshot_id="temp", target=tc.domain, hosts=hosts)
    )

    # --- Save snapshot ---
    snapshot = Snapshot(
        snapshot_id=str(uuid.uuid4()),
        target=tc.domain,
        hosts=hosts,
        metadata={
            "mode": "passive",
            "shodan_enabled": tc.shodan,
            "label": tc.label,
            "tags": tc.tags,
            "subdomains_discovered": len(disc_results["subdomains"]),
            "ips_discovered": len(discovered_ips),
        },
        risk_score=risk_score,
    )

    store.save(snapshot)
    result.snapshot = snapshot
    print(render_snapshot_summary(snapshot))

    # --- Diff ---
    if tc.diff:
        all_snaps = store.list_snapshots(tc.domain)
        if len(all_snaps) >= 2:
            baseline = all_snaps[1]  # [0] is the one we just saved
            diff = compute_diff(baseline, snapshot)
            result.diff = diff
            print(render_diff(diff, fmt=output_fmt))

            # Slack alerting
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
                    logger.warning("Slack alert failed for %s: %s", tc.domain, exc)
        else:
            logger.info("No previous snapshot for %s — baseline established", tc.domain)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _basic_host(ip: str, hostnames: list[str] | None = None):
    from asmon.models import HostRecord
    return HostRecord(
        ip=ip, hostnames=hostnames or [],
        services=[], source="discovery", shodan_enriched=False,
    )


def _print_summary(results: list[TargetResult]) -> None:
    """Print aggregate summary across all targets."""
    ok = sum(1 for r in results if r.error is None)
    failed = sum(1 for r in results if r.error is not None)
    total_hosts = sum(len(r.snapshot.hosts) for r in results if r.snapshot)
    total_cves = sum(
        len(c.cves) for r in results if r.snapshot for c in r.snapshot.hosts
    )
    changes = sum(
        len(r.diff.changes) for r in results if r.diff
    )

    print(f"\n{'=' * 60}")
    print(f"ASMON Multi-Target Summary")
    print(f"{'=' * 60}")
    print(f"  Targets scanned: {ok}/{ok + failed}")
    if failed:
        print(f"  Failed: {failed}")
        for r in results:
            if r.error:
                print(f"    - {r.target.domain}: {r.error}")
    print(f"  Total hosts: {total_hosts}")
    print(f"  Total CVEs: {total_cves}")
    print(f"  Total changes: {changes}")

    # Risk breakdown
    for r in results:
        if r.snapshot and r.snapshot.risk_score:
            score = r.snapshot.risk_score
            label = r.target.label or r.target.domain
            print(f"  {label}: {score.score}/100 ({score.level.upper()})")

    print(f"{'=' * 60}\n")
