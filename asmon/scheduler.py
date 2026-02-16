"""
scheduler.py — Repeat scans on a fixed interval.

Wraps the orchestrator (multi-target) or single-target main flow and
re-runs it every N minutes.  Designed for long-running background use:

    # Scan every 6 hours
    python -m asmon.asmon --targets targets.yaml --schedule 360

    # Single target every hour
    python -m asmon.asmon --target example.com --diff --schedule 60

Behaviour:
  - First scan runs immediately on start.
  - After each cycle, sleeps for the configured interval.
  - Ctrl+C stops gracefully after the current cycle finishes (or during sleep).
  - Each cycle is independent — one failure doesn't stop the loop.
  - Logs cycle number, next-run time, and per-cycle duration.

No external cron/task-scheduler dependency — pure Python, single process.
For production deployments, wrapping this in a systemd service or Docker
container is recommended (documented in README).
"""

import time
import signal
import logging
from datetime import datetime, timezone, timedelta
from typing import Callable

logger = logging.getLogger("asmon.scheduler")

# Graceful shutdown flag
_shutdown_requested = False


def _handle_signal(signum, frame):
    """Signal handler for graceful shutdown."""
    global _shutdown_requested
    _shutdown_requested = True
    logger.info("Shutdown requested (signal %d) — finishing current cycle", signum)


def run_scheduled(
    scan_fn: Callable[[], int],
    interval_minutes: int,
    max_cycles: int = 0,
) -> int:
    """
    Run scan_fn repeatedly on a fixed interval.

    Args:
        scan_fn:          Callable that runs one full scan cycle. Returns exit code.
        interval_minutes: Minutes between the START of each cycle.
        max_cycles:       Stop after N cycles (0 = unlimited).

    Returns:
        0 on clean shutdown, 3 if all cycles failed.
    """
    global _shutdown_requested
    _shutdown_requested = False

    # Register signal handlers for graceful shutdown
    original_sigint = signal.getsignal(signal.SIGINT)
    original_sigterm = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    interval_sec = interval_minutes * 60
    cycle = 0
    failures = 0

    logger.info(
        "Scheduler started: interval=%d min, max_cycles=%s",
        interval_minutes,
        max_cycles if max_cycles > 0 else "unlimited",
    )

    try:
        while not _shutdown_requested:
            cycle += 1

            if max_cycles > 0 and cycle > max_cycles:
                logger.info("Reached max cycles (%d) — stopping", max_cycles)
                break

            # --- Run one scan cycle ---
            cycle_start = time.monotonic()
            now = datetime.now(timezone.utc)
            logger.info("=" * 60)
            logger.info(
                "Cycle %d started at %s UTC",
                cycle,
                now.strftime("%Y-%m-%d %H:%M:%S"),
            )
            logger.info("=" * 60)

            try:
                exit_code = scan_fn()
                if exit_code >= 3:
                    failures += 1
                    logger.error("Cycle %d finished with error (exit %d)", cycle, exit_code)
                else:
                    logger.info("Cycle %d finished (exit %d)", cycle, exit_code)
            except Exception as exc:
                failures += 1
                logger.error("Cycle %d crashed: %s", cycle, exc)

            cycle_duration = time.monotonic() - cycle_start
            logger.info("Cycle %d took %.1f seconds", cycle, cycle_duration)

            # --- Check if we should stop ---
            if max_cycles > 0 and cycle >= max_cycles:
                break
            if _shutdown_requested:
                break

            # --- Sleep until next cycle ---
            sleep_sec = max(0, interval_sec - cycle_duration)
            next_run = datetime.now(timezone.utc) + timedelta(seconds=sleep_sec)
            logger.info(
                "Next scan at %s UTC (sleeping %.0f min)",
                next_run.strftime("%H:%M:%S"),
                sleep_sec / 60,
            )

            # Sleep in small chunks so we can respond to shutdown quickly
            sleep_end = time.monotonic() + sleep_sec
            while time.monotonic() < sleep_end and not _shutdown_requested:
                remaining = sleep_end - time.monotonic()
                time.sleep(min(remaining, 5.0))  # wake every 5s to check signal

    finally:
        # Restore original signal handlers
        signal.signal(signal.SIGINT, original_sigint)
        signal.signal(signal.SIGTERM, original_sigterm)

    logger.info("Scheduler stopped after %d cycle(s) (%d failures)", cycle, failures)

    if cycle > 0 and failures == cycle:
        return 3  # all cycles failed
    return 0
