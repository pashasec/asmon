"""
asmon/scoring.py — Hybrid risk scoring engine.

Combines multiple risk signal sources into a unified score:
  - CVE severity (from Shodan or active scan)
  - Exposed services (open ports, sensitive services)
  - Web risk signals (headers, cookies, endpoints)

Score range: 0-100
Levels:
  - critical: 80-100
  - high: 60-79
  - medium: 40-59
  - low: 20-39
  - info: 0-19

Design principles:
  - Pure function. Takes a Snapshot, returns a RiskScore.
  - Deterministic. Same input = same output.
  - Transparent. Risk factors are enumerated for auditability.
"""

import logging
from asmon.models import Snapshot, RiskScore, HostRecord

logger = logging.getLogger("asmon.scoring")


# ---------------------------------------------------------------------------
# Scoring weights and thresholds
# ---------------------------------------------------------------------------

# CVE scoring weights
CVE_WEIGHTS = {
    "critical": 25,  # Each critical CVE adds 25 points
    "high": 15,      # Each high CVE adds 15 points
    "medium": 5,     # Each medium CVE adds 5 points
    "low": 2,        # Each low CVE adds 2 points
    "info": 0,       # Info-level CVEs don't add to score
    "unknown": 3,    # Unknown severity treated as low-medium
}

# Web risk signal weights
WEB_RISK_WEIGHTS = {
    "high": 10,      # High-severity web signal adds 10 points
    "medium": 5,     # Medium adds 5 points
    "low": 2,        # Low adds 2 points
    "info": 0,       # Info doesn't add to score
}

# Vulnerability finding weights (from active security modules)
VULN_FINDING_WEIGHTS = {
    "critical": 40,  # Critical vulns (RCE, SQLi confirmed) - very high impact
    "high": 25,      # High vulns (XSS, SSRF, etc.)
    "medium": 10,    # Medium vulns (info disclosure)
    "low": 3,        # Low vulns
    "info": 0,
    "confirmed": 1.5,  # Multiplier for confirmed findings
    "high_confidence": 1.2,  # Multiplier for high confidence
}

# Service exposure weights (points per exposed service type)
SERVICE_WEIGHTS = {
    # High-risk services (often misconfigured or shouldn't be public)
    "ssh": 5,
    "rdp": 8,
    "telnet": 10,
    "ftp": 6,
    "mysql": 10,
    "postgresql": 10,
    "mongodb": 12,
    "redis": 12,
    "elasticsearch": 10,
    "memcached": 10,
    "smb": 8,
    "vnc": 8,

    # Web services (lower risk, expected to be public)
    "http": 2,
    "https": 1,

    # Other common services
    "smtp": 3,
    "dns": 2,
    "default": 3,  # Unknown services
}

# Maximum scores per category (caps to prevent runaway scores)
MAX_CVE_SCORE = 60
MAX_SERVICE_SCORE = 30
MAX_WEB_RISK_SCORE = 40


# ---------------------------------------------------------------------------
# Scoring functions
# ---------------------------------------------------------------------------

def compute_risk_score(snapshot: Snapshot) -> RiskScore:
    """
    Compute a hybrid risk score for a snapshot.

    Combines:
      - CVE severity scores
      - Exposed service counts
      - Web risk signal counts

    Args:
        snapshot: Snapshot to score

    Returns:
        RiskScore with breakdown and factors
    """
    factors: list[str] = []

    # --- CVE scoring ---
    cve_score = 0
    cve_count = 0
    critical_cve_count = 0
    high_cve_count = 0

    for host in snapshot.hosts:
        for cve in host.cves:
            cve_count += 1
            severity = cve.severity.lower()
            weight = CVE_WEIGHTS.get(severity, CVE_WEIGHTS["unknown"])
            cve_score += weight

            if severity == "critical":
                critical_cve_count += 1
            elif severity == "high":
                high_cve_count += 1

    # Cap CVE score
    cve_score = min(cve_score, MAX_CVE_SCORE)

    if critical_cve_count > 0:
        factors.append(f"{critical_cve_count} critical CVE(s) detected")
    if high_cve_count > 0:
        factors.append(f"{high_cve_count} high-severity CVE(s) detected")

    # --- Service exposure scoring ---
    service_score = 0
    exposed_service_count = 0
    sensitive_services: list[str] = []

    for host in snapshot.hosts:
        for svc in host.services:
            if svc.state != "open":
                continue

            exposed_service_count += 1
            svc_name = (svc.service_name or "").lower()

            # Look up weight by service name
            weight = SERVICE_WEIGHTS.get(svc_name, SERVICE_WEIGHTS["default"])
            service_score += weight

            # Track sensitive services for factors
            if svc_name in ("mysql", "postgresql", "mongodb", "redis", "elasticsearch",
                           "memcached", "telnet", "rdp", "vnc", "smb"):
                sensitive_services.append(f"{svc_name}:{svc.port}")

    # Cap service score
    service_score = min(service_score, MAX_SERVICE_SCORE)

    if sensitive_services:
        factors.append(f"Sensitive services exposed: {', '.join(sensitive_services[:5])}")
    elif exposed_service_count > 10:
        factors.append(f"{exposed_service_count} services exposed")

    # --- Web risk scoring ---
    web_risk_score = 0
    web_signal_count = 0
    high_web_signal_count = 0
    missing_hsts = False
    missing_csp = False
    exposed_endpoints: list[str] = []

    for host in snapshot.hosts:
        for report in host.web_risks:
            for signal in report.signals:
                web_signal_count += 1
                severity = signal.severity.lower()
                weight = WEB_RISK_WEIGHTS.get(severity, 0)
                web_risk_score += weight

                if severity == "high":
                    high_web_signal_count += 1

                # Track specific signals for factors
                if signal.signal_type == "missing_header":
                    if "HSTS" in signal.title:
                        missing_hsts = True
                    if "CSP" in signal.title:
                        missing_csp = True
                elif signal.signal_type == "exposed_endpoint" and severity in ("high", "medium"):
                    exposed_endpoints.append(signal.endpoint or signal.title)
                elif signal.signal_type == "no_https_redirect":
                    factors.append("HTTP does not redirect to HTTPS")

    # Cap web risk score
    web_risk_score = min(web_risk_score, MAX_WEB_RISK_SCORE)

    if missing_hsts:
        factors.append("Missing HSTS header")
    if missing_csp:
        factors.append("Missing Content-Security-Policy")
    if exposed_endpoints:
        factors.append(f"Exposed endpoints: {', '.join(exposed_endpoints[:3])}")
    if high_web_signal_count > 0 and not (missing_hsts or missing_csp or exposed_endpoints):
        factors.append(f"{high_web_signal_count} high-severity web risk(s)")

    # --- Compute total score ---
    total_score = cve_score + service_score + web_risk_score

    # Clamp to 0-100
    total_score = max(0, min(100, total_score))

    # Determine level
    level = _score_to_level(total_score)

    # Add summary factor if no specific factors but score > 0
    if not factors and total_score > 0:
        factors.append("General exposure from services and web configuration")

    logger.info(
        "Risk score computed: %d (%s) — CVE:%d, Service:%d, Web:%d",
        total_score, level, cve_score, service_score, web_risk_score
    )

    return RiskScore(
        score=total_score,
        level=level,
        cve_score=cve_score,
        service_score=service_score,
        web_risk_score=web_risk_score,
        cve_count=cve_count,
        critical_cve_count=critical_cve_count,
        high_cve_count=high_cve_count,
        exposed_service_count=exposed_service_count,
        web_signal_count=web_signal_count,
        high_web_signal_count=high_web_signal_count,
        factors=factors,
    )


def _score_to_level(score: int) -> str:
    """Convert numeric score to qualitative level."""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    elif score >= 20:
        return "low"
    else:
        return "info"


def compute_host_risk(host: HostRecord) -> int:
    """
    Compute risk score for a single host.

    Useful for sorting hosts by risk.

    Args:
        host: HostRecord to score

    Returns:
        Integer risk score (0-100)
    """
    score = 0

    # CVEs
    for cve in host.cves:
        severity = cve.severity.lower()
        score += CVE_WEIGHTS.get(severity, CVE_WEIGHTS["unknown"])

    # Services
    for svc in host.services:
        if svc.state == "open":
            svc_name = (svc.service_name or "").lower()
            score += SERVICE_WEIGHTS.get(svc_name, SERVICE_WEIGHTS["default"])

    # Web risks
    for report in host.web_risks:
        for signal in report.signals:
            severity = signal.severity.lower()
            score += WEB_RISK_WEIGHTS.get(severity, 0)

    return max(0, min(100, score))
