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
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Imports — all absolute from asmon package
# ---------------------------------------------------------------------------
from asmon import config
from asmon.config import setup_logging
from asmon.models import Snapshot
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
    parser.add_argument("--target", required=True,
                        help="Domain, URL, or organisation name to monitor.")

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

    # --- Listing ---
    parser.add_argument("--list", action="store_true",
                        help="List all stored snapshots for the target and exit.")

    # --- Misc ---
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        default=None, help="Override log level.")

    return parser


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

    # Storage
    store = SnapshotStore(config.SNAPSHOT_DIR)

    # --- --list mode (early exit) ---
    if args.list:
        return _handle_list(store, args.target)

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
                        hosts.append(host)
                except Exception as exc:
                    logger.warning("Shodan lookup failed for %s: %s", ip, exc)
        else:
            logger.info("Running Shodan domain search for %s", root_domain)
            try:
                hosts = shodan.search_domain(root_domain)
            except Exception as exc:
                logger.error("Shodan search failed: %s", exc)
                return 3
    else:
        logger.info("Shodan not enabled. Use --shodan to enrich results.")

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
    )

    saved_path = store.save(snapshot)
    logger.info("Snapshot saved: %s", saved_path)

    # Print snapshot summary
    print(render_snapshot_summary(snapshot))

    # --- Diff phase ---
    if not args.diff:
        return 0

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
            return 0
        baseline = all_snaps[1]  # [0] is the one we just saved

    diff = compute_diff(baseline, snapshot)
    print(render_diff(diff, fmt=args.output))

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
    return 1 if diff.changes else 0


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
