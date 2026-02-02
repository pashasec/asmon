"""
core/output.py — Diff and snapshot rendering.

Two output modes:
  - text: Terminal-friendly, coloured (when tty), grouped by change type.
  - json: Machine-readable, full fidelity. Suitable for piping or storage.

Colours are stripped automatically when stdout is not a TTY.
"""

import json
import sys
import os
from asmon.models import SurfaceDiff, Snapshot


# ---------------------------------------------------------------------------
# ANSI colour helpers (stripped when not a TTY)
# ---------------------------------------------------------------------------

def _is_tty() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class _Colour:
    """Lazy colour codes. Empty strings when not a TTY."""
    def __init__(self):
        if _is_tty():
            self.RED    = "\033[31m"
            self.GREEN  = "\033[32m"
            self.YELLOW = "\033[33m"
            self.CYAN   = "\033[36m"
            self.BOLD   = "\033[1m"
            self.DIM    = "\033[2m"
            self.RESET  = "\033[0m"
        else:
            self.RED = self.GREEN = self.YELLOW = ""
            self.CYAN = self.BOLD = self.DIM = self.RESET = ""

C = _Colour()


# ---------------------------------------------------------------------------
# Diff output
# ---------------------------------------------------------------------------

def render_diff(diff: SurfaceDiff, fmt: str = "text") -> str:
    """
    Render a SurfaceDiff.
    fmt: "text" (human) or "json" (machine).
    """
    if fmt == "json":
        return diff.model_dump_json(indent=2)
    return _render_diff_text(diff)


def _render_diff_text(diff: SurfaceDiff) -> str:
    lines: list[str] = []

    # Header
    lines.append(f"\n{C.BOLD}{'─' * 70}{C.RESET}")
    lines.append(f"{C.BOLD}Attack Surface Diff — {diff.target}{C.RESET}")
    lines.append(f"{C.DIM}Baseline: {diff.baseline_captured_at.strftime('%Y-%m-%d %H:%M UTC')}  "
                 f"({diff.baseline_id[:8]}){C.RESET}")
    lines.append(f"{C.DIM}Current:  {diff.current_captured_at.strftime('%Y-%m-%d %H:%M UTC')}  "
                 f"({diff.current_id[:8]}){C.RESET}")
    lines.append(f"{C.BOLD}{'─' * 70}{C.RESET}\n")

    # Summary line
    summary_parts: list[str] = []
    if diff.added_count:
        summary_parts.append(f"{C.GREEN}+{diff.added_count} added{C.RESET}")
    if diff.removed_count:
        summary_parts.append(f"{C.RED}-{diff.removed_count} removed{C.RESET}")
    if diff.changed_count:
        summary_parts.append(f"{C.YELLOW}~{diff.changed_count} changed{C.RESET}")
    if not summary_parts:
        summary_parts.append(f"{C.DIM}No changes detected.{C.RESET}")

    lines.append("  " + "  |  ".join(summary_parts))
    lines.append("")

    if not diff.changes:
        return "\n".join(lines)

    # Group by change_type for readability
    for change_type, colour, label in [
        ("added",   C.GREEN,  "ADDED"),
        ("removed", C.RED,    "REMOVED"),
        ("changed", C.YELLOW, "CHANGED"),
    ]:
        group = [c for c in diff.changes if c.change_type == change_type]
        if not group:
            continue

        lines.append(f"  {colour}{C.BOLD}[{label}]{C.RESET}")
        for change in group:
            entity_tag = f"[{change.entity_type}]"
            port_suffix = f":{change.port}" if change.port else ""
            lines.append(f"    {colour}•{C.RESET} {C.BOLD}{change.ip}{port_suffix}{C.RESET}  "
                         f"{C.DIM}{entity_tag}{C.RESET}  {change.detail}")
        lines.append("")

    lines.append(f"{C.BOLD}{'─' * 70}{C.RESET}\n")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Snapshot summary (for --list or quick overview)
# ---------------------------------------------------------------------------

def render_snapshot_summary(snapshot: Snapshot) -> str:
    """One-paragraph summary of a snapshot."""
    host_count = len(snapshot.hosts)
    total_services = sum(len(h.services) for h in snapshot.hosts)
    unique_ports = set()
    for h in snapshot.hosts:
        for s in h.services:
            unique_ports.add(s.port)

    lines = [
        f"{C.BOLD}Snapshot {snapshot.snapshot_id[:8]}{C.RESET}  "
        f"— {snapshot.target}  "
        f"@ {snapshot.captured_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"  Hosts: {host_count}  |  Services: {total_services}  |  "
        f"Unique ports: {len(unique_ports)}  ({', '.join(str(p) for p in sorted(unique_ports)[:15])})",
    ]
    return "\n".join(lines)
