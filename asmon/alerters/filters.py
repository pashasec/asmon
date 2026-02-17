"""
filters.py — Decide which changes are worth alerting on.

Goal: zero noise.  Only fire an alert when a human should actually look.

Rules applied (in order):
  1. New host discovered                              → always alert
  2. New service on a HIGH-RISK port                  → always alert
  3. New CVE with severity critical or high            → always alert
  4. New web-risk signal with severity high            → always alert
  5. Service removed / CVE fixed                       → info-level only
  6. Minor metadata changes (banner, version bumps)   → suppress
"""

import logging
from asmon.models import SurfaceDiff, AssetChange

logger = logging.getLogger("asmon.alerters.filters")

# Ports that are dangerous when exposed to the internet
HIGH_RISK_PORTS: set[int] = {
    22,     # SSH
    23,     # Telnet
    135,    # MS-RPC
    139,    # NetBIOS
    445,    # SMB
    1433,   # MSSQL
    1521,   # Oracle
    3306,   # MySQL
    3389,   # RDP
    5432,   # PostgreSQL
    5900,   # VNC
    5984,   # CouchDB
    6379,   # Redis
    8080,   # HTTP alt / admin panels
    8443,   # HTTPS alt
    8888,   # Dev servers / Jupyter
    9200,   # Elasticsearch
    11211,  # Memcached
    27017,  # MongoDB
    50070,  # Hadoop NameNode
}


def classify_alert(change: AssetChange) -> dict | None:
    """
    Evaluate a single AssetChange and return an alert dict if it warrants
    a Slack notification, or None to suppress it.

    Returned dict shape:
        {
            "ip": str,
            "port": int | None,
            "title": str,           # one-line headline
            "detail": str,          # fuller explanation
            "severity": str,        # critical / high / medium / low / info
            "alert_type": str,      # new_host / new_service / new_cve / ...
            "action": str,          # recommended next step (1 sentence)
        }
    """
    ct = change.change_type   # added / removed / changed
    et = change.entity_type   # host / service / ssl_cert / cve / web_risk

    # ── New host ──────────────────────────────────────────────────────
    if ct == "added" and et == "host":
        return {
            "ip": change.ip,
            "port": None,
            "title": "New asset discovered",
            "detail": change.detail,
            "severity": "high",
            "alert_type": "new_host",
            "action": "Verify ownership and check for unauthorised exposure.",
        }

    # ── New service ───────────────────────────────────────────────────
    if ct == "added" and et == "service":
        port = change.port or 0
        svc_name = _extract_service_name(change)

        if port in HIGH_RISK_PORTS:
            return {
                "ip": change.ip,
                "port": port,
                "title": f"High-risk port {port} ({svc_name}) now open",
                "detail": change.detail,
                "severity": "critical" if port in (3306, 5432, 6379, 27017, 3389) else "high",
                "alert_type": "new_service",
                "action": _service_action(port, svc_name),
            }

        # Non-high-risk new service — still worth noting
        return {
            "ip": change.ip,
            "port": port,
            "title": f"New service on port {port} ({svc_name})",
            "detail": change.detail,
            "severity": "medium",
            "alert_type": "new_service",
            "action": "Review whether this service should be publicly accessible.",
        }

    # ── New CVE ───────────────────────────────────────────────────────
    if ct == "added" and et == "cve":
        sev = change.severity or "medium"
        if sev in ("critical", "high"):
            return {
                "ip": change.ip,
                "port": change.port,
                "title": f"{sev.upper()} CVE detected",
                "detail": change.detail,
                "severity": sev,
                "alert_type": "new_cve",
                "action": "Check patch availability and apply as soon as possible.",
            }
        return None  # suppress medium/low/info CVEs

    # ── New web-risk signal ───────────────────────────────────────────
    if ct == "added" and et == "web_risk":
        sev = change.severity or "info"
        if sev in ("critical", "high"):
            return {
                "ip": change.ip,
                "port": change.port,
                "title": "Web exposure detected",
                "detail": change.detail,
                "severity": sev,
                "alert_type": "new_web_risk",
                "action": "Review HTTP configuration and restrict exposed resources.",
            }
        return None  # suppress medium/low/info web signals

    # ── SSL cert changes ──────────────────────────────────────────────
    if et == "ssl_cert":
        if ct == "removed":
            return {
                "ip": change.ip,
                "port": change.port,
                "title": "SSL certificate disappeared",
                "detail": change.detail,
                "severity": "high",
                "alert_type": "ssl_removed",
                "action": "Investigate — service may have lost TLS or been reconfigured.",
            }
        # cert added or rotated — informational, don't alert
        return None

    # ── Everything else (removed hosts, metadata tweaks) → suppress ──
    return None


def filter_diff(diff: SurfaceDiff) -> list[dict]:
    """
    Run every change in a SurfaceDiff through classify_alert.
    Returns only the alerts that passed the filter (list of dicts).
    """
    alerts: list[dict] = []
    for change in diff.changes:
        alert = classify_alert(change)
        if alert is not None:
            alerts.append(alert)

    logger.info(
        "Filtered %d changes → %d alerts worth sending",
        len(diff.changes),
        len(alerts),
    )
    return alerts


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _extract_service_name(change: AssetChange) -> str:
    """Pull a human-readable service name from the change."""
    if change.new and isinstance(change.new, dict):
        return change.new.get("service_name") or "unknown"
    return "unknown"


def _service_action(port: int, svc_name: str) -> str:
    """One-sentence remediation per service type."""
    actions = {
        22:    "Restrict SSH to bastion host or VPN; disable password auth.",
        23:    "Disable Telnet immediately — use SSH instead.",
        135:   "Block MS-RPC from the internet via firewall rules.",
        139:   "Block NetBIOS from the internet; it should never be exposed.",
        445:   "Block SMB from the internet; apply MS17-010 patches.",
        1433:  "Restrict MSSQL to internal networks via firewall/WAF.",
        1521:  "Restrict Oracle DB to internal networks.",
        3306:  "Restrict MySQL to internal IPs; never expose to internet.",
        3389:  "Restrict RDP to VPN or internal network; enable NLA + MFA.",
        5432:  "Restrict PostgreSQL to internal IPs via pg_hba.conf + firewall.",
        5900:  "Disable or restrict VNC to internal networks; use SSH tunnels.",
        5984:  "Restrict CouchDB admin interface to internal networks.",
        6379:  "Restrict Redis to internal IPs; enable AUTH if not already.",
        8080:  "Review what is served here; restrict admin panels to internal.",
        8443:  "Review what is served here; ensure proper TLS configuration.",
        8888:  "Restrict dev/admin interfaces to internal networks.",
        9200:  "Restrict Elasticsearch to internal networks immediately.",
        11211: "Restrict Memcached to internal only; disable UDP if possible.",
        27017: "Restrict MongoDB to internal IPs; enable authentication.",
        50070: "Block Hadoop NameNode from internet; internal access only.",
    }
    return actions.get(port, "Review whether this service should be publicly accessible.")
