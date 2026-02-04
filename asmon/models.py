"""
models.py — Canonical data structures for the entire tool.

Designed for direct JSON serialization via .model_dump().
Every module that touches attack-surface data imports from here.
Nothing in this file does I/O.
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Leaf-level primitives
# ---------------------------------------------------------------------------

class SSLCert(BaseModel):
    """Parsed SSL/TLS certificate metadata."""
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    san: list[str] = Field(default_factory=list)  # Subject Alternative Names
    fingerprint_sha256: Optional[str] = None


class ServiceInfo(BaseModel):
    """Single service on a single port."""
    port: int
    protocol: str                          # tcp | udp
    service_name: Optional[str] = None     # e.g. "ssh", "https"
    banner: Optional[str] = None           # first 512 bytes, sanitised
    product: Optional[str] = None
    version: Optional[str] = None
    ssl: Optional[SSLCert] = None
    cves: list[str] = Field(default_factory=list)  # from Shodan if available
    tags: list[str] = Field(default_factory=list)  # e.g. ["admin-panel", "unauthenticated"]
    detection_method: str = "passive"      # "passive" | "active" | "shodan"
    state: str = "open"                    # "open" | "closed" | "filtered"


class CVEInfo(BaseModel):
    """CVE metadata (NO exploit code)."""
    cve_id: str                            # e.g. "CVE-2024-1234"
    cvss_score: Optional[float] = None     # 0.0 - 10.0
    severity: str = "unknown"              # "critical" | "high" | "medium" | "low" | "info"
    description: str = ""
    affected_product: Optional[str] = None
    affected_version: Optional[str] = None
    published_date: Optional[str] = None
    references: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Web risk signals — passive HTTP observations (no scanning/fuzzing)
# ---------------------------------------------------------------------------

class WebRiskSignal(BaseModel):
    """
    A single web exposure signal detected via passive HTTP observation.

    This is NOT a vulnerability — it's a risk indicator that may warrant
    investigation. Detection uses only HEAD/GET requests with no payloads.
    """
    signal_type: str                       # "missing_header" | "insecure_cookie" | "tech_disclosure" | "exposed_endpoint" | "no_https_redirect"
    severity: str = "info"                 # "high" | "medium" | "low" | "info"
    title: str                             # Human-readable signal name
    detail: str                            # Technical detail / evidence
    endpoint: Optional[str] = None         # URL path where detected (if applicable)
    recommendation: str = ""               # Remediation guidance


class WebRiskReport(BaseModel):
    """
    Collection of web risk signals for a single host/port.

    This is NOT a vulnerability assessment — it's a passive exposure inventory.
    """
    host: str                              # IP or hostname
    port: int = 443                        # HTTP/HTTPS port
    url: str                               # Base URL scanned
    signals: list[WebRiskSignal] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    http_accessible: bool = False          # Could we reach HTTP?
    https_accessible: bool = False         # Could we reach HTTPS?
    server_header: Optional[str] = None    # Server header if disclosed
    technologies: list[str] = Field(default_factory=list)  # Detected tech stack


# ---------------------------------------------------------------------------
# Risk scoring — hybrid score combining CVEs, services, and web signals
# ---------------------------------------------------------------------------

class RiskScore(BaseModel):
    """
    Hybrid risk score combining multiple signal sources.

    Score range: 0-100
    Levels: critical (80-100), high (60-79), medium (40-59), low (20-39), info (0-19)
    """
    score: int = 0                         # 0-100 numeric score
    level: str = "info"                    # "critical" | "high" | "medium" | "low" | "info"

    # Component breakdown
    cve_score: int = 0                     # Points from CVE severity
    service_score: int = 0                 # Points from exposed services
    web_risk_score: int = 0                # Points from web risk signals

    # Summary counts
    cve_count: int = 0
    critical_cve_count: int = 0
    high_cve_count: int = 0
    exposed_service_count: int = 0
    web_signal_count: int = 0
    high_web_signal_count: int = 0

    factors: list[str] = Field(default_factory=list)  # Human-readable risk factors


class HostRecord(BaseModel):
    """All known information about a single IP."""
    ip: str
    hostnames: list[str] = Field(default_factory=list)
    org: Optional[str] = None
    asn: Optional[str | int] = None        # Shodan returns "AS12345" or int
    country: Optional[str] = None
    city: Optional[str] = None
    services: list[ServiceInfo] = Field(default_factory=list)
    last_seen: Optional[datetime] = None
    source: str = "shodan"                 # origin tag — never mix sources in one record
    shodan_enriched: bool = False          # True if Shodan enrichment succeeded
    active_scanned: bool = False           # True if active scan ran
    web_risk_scanned: bool = False         # True if web risk scan ran
    vuln_scanned: bool = False             # True if vulnerability scan ran
    cves: list[CVEInfo] = Field(default_factory=list)
    web_risks: list["WebRiskReport"] = Field(default_factory=list)  # Web exposure signals
    vuln_findings: list[dict] = Field(default_factory=list)  # Security module findings


# ---------------------------------------------------------------------------
# Snapshot — the unit of storage and comparison
# ---------------------------------------------------------------------------

class Snapshot(BaseModel):
    """
    A point-in-time capture of the entire known attack surface for a target.

    `target` is the user-provided identifier (domain / company name).
    `hosts` is the full set of discovered hosts at capture time.
    """
    snapshot_id: str                       # uuid4, generated by storage layer
    target: str
    captured_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    hosts: list[HostRecord] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)  # mode, flags, etc.
    active_scan_enabled: bool = False      # Was --active used?
    web_risk_enabled: bool = False         # Was --web-risk used?
    vuln_scan_enabled: bool = False        # Was --vuln-scan used?
    risk_score: Optional["RiskScore"] = None  # Computed hybrid risk score


# ---------------------------------------------------------------------------
# Diff primitives — output of the comparison engine
# ---------------------------------------------------------------------------

class AssetChange(BaseModel):
    """One atomic change detected between two snapshots."""
    change_type: str                       # "added" | "removed" | "changed"
    entity_type: str                       # "host" | "service" | "ssl_cert" | "cve" | "web_risk"
    ip: str
    port: Optional[int] = None
    detail: str                            # human-readable one-liner
    old: Optional[dict] = None             # previous state (if applicable)
    new: Optional[dict] = None             # current state (if applicable)
    severity: str = "info"                 # "critical" | "high" | "medium" | "low" | "info"


class SurfaceDiff(BaseModel):
    """Full diff report between two snapshots."""
    target: str
    baseline_id: str                       # older snapshot
    current_id: str                        # newer snapshot
    baseline_captured_at: datetime
    current_captured_at: datetime
    changes: list[AssetChange] = Field(default_factory=list)

    # Convenience counters (populated by diff engine)
    added_count: int = 0
    removed_count: int = 0
    changed_count: int = 0


# ---------------------------------------------------------------------------
# AI analysis envelope — keeps AI output cleanly separated from raw data
# ---------------------------------------------------------------------------

class AIAnalysis(BaseModel):
    """
    Wrapper for any AI-generated text.

    `raw_prompt` is logged for auditing (what we actually sent).
    `summary` is the LLM output — treat as advisory, never authoritative.
    """
    provider: str
    model: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_prompt: str
    summary: str
    flags: list[str] = Field(default_factory=list)  # risk flags extracted by post-processing


# ---------------------------------------------------------------------------
# Resolve forward references for Pydantic models
# ---------------------------------------------------------------------------
HostRecord.model_rebuild()
Snapshot.model_rebuild()
