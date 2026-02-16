"""
messages.py — Build Slack Block Kit payloads from filtered alerts.

Each message follows a strict format:
  - Header with emoji + target name
  - Per-finding blocks: severity tag, asset, what changed, action
  - Footer with scan metadata

Designed for Slack incoming webhooks (no Bot token needed).
"""

from datetime import datetime, timezone

# Severity → visual treatment
_SEV_EMOJI = {
    "critical": "\U0001f534",   # red circle
    "high":     "\U0001f7e0",   # orange circle
    "medium":   "\U0001f7e1",   # yellow circle
    "low":      "\U0001f535",   # blue circle
    "info":     "\u26aa",       # white circle
}

_SEV_LABEL = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}


def build_slack_payload(
    target: str,
    alerts: list[dict],
    snapshot_id: str,
    baseline_id: str | None = None,
) -> dict:
    """
    Build a complete Slack message payload from a list of alert dicts
    (as returned by filters.filter_diff / filters.classify_alert).

    Returns a dict ready to POST to a Slack webhook.
    Returns None if alerts list is empty.
    """
    if not alerts:
        return None

    blocks: list[dict] = []

    # ── Header ────────────────────────────────────────────────────────
    highest = _highest_severity(alerts)
    emoji = _SEV_EMOJI.get(highest, "\u26a0\ufe0f")

    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"{emoji} ASMON Alert: {target}",
            "emoji": True,
        },
    })

    # ── Summary line ──────────────────────────────────────────────────
    counts = _count_by_severity(alerts)
    summary_parts = []
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev, 0) > 0:
            summary_parts.append(f"{_SEV_EMOJI[sev]} {counts[sev]} {_SEV_LABEL[sev]}")

    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*{len(alerts)} finding(s)* detected   {'  '.join(summary_parts)}",
        },
    })

    blocks.append({"type": "divider"})

    # ── Per-alert blocks (cap at 8 to stay within Slack's 50-block limit) ─
    shown = alerts[:8]
    for alert in shown:
        blocks.append(_alert_block(alert))

    if len(alerts) > 8:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"_… and {len(alerts) - 8} more finding(s). Check full report._",
            },
        })

    blocks.append({"type": "divider"})

    # ── Footer ────────────────────────────────────────────────────────
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    footer_parts = [f"Snapshot `{snapshot_id[:8]}`"]
    if baseline_id:
        footer_parts.append(f"Baseline `{baseline_id[:8]}`")
    footer_parts.append(ts)

    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": " | ".join(footer_parts)},
        ],
    })

    return {
        "blocks": blocks,
        # Fallback text for clients that don't render blocks
        "text": f"{emoji} ASMON Alert: {target} — {len(alerts)} finding(s)",
    }


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _alert_block(alert: dict) -> dict:
    """One Slack section block for a single alert."""
    sev = alert.get("severity", "info")
    emoji = _SEV_EMOJI.get(sev, "\u26aa")
    label = _SEV_LABEL.get(sev, "INFO")

    ip = alert.get("ip", "?")
    port = alert.get("port")
    asset = f"`{ip}:{port}`" if port else f"`{ip}`"

    title = alert.get("title", "Change detected")
    detail = alert.get("detail", "")
    action = alert.get("action", "")

    # Truncate detail to keep messages compact
    if len(detail) > 120:
        detail = detail[:117] + "..."

    text = f"{emoji} *{label}* — {title}\n"
    text += f"Asset: {asset}\n"
    text += f"{detail}\n"
    if action:
        text += f"_\u2192 {action}_"

    return {
        "type": "section",
        "text": {"type": "mrkdwn", "text": text},
    }


def _highest_severity(alerts: list[dict]) -> str:
    """Return the highest severity present in the list."""
    order = ["critical", "high", "medium", "low", "info"]
    for sev in order:
        if any(a.get("severity") == sev for a in alerts):
            return sev
    return "info"


def _count_by_severity(alerts: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for a in alerts:
        sev = a.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
