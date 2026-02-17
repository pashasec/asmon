"""
app.py — FastAPI backend for the ASMON web dashboard.

Endpoints:
    GET  /                      — Serves the frontend
    GET  /detail/{snapshot_id}  — Detail page for a snapshot
    POST /api/scan              — Run a scan on a domain/IP
    GET  /api/scan/{scan_id}    — Poll scan status / get results
    GET  /api/snapshot/{id}     — Full snapshot data
    GET  /api/report/{id}       — Download HTML report
    GET  /api/history           — List past scans from snapshots

No login required. No API keys exposed to the frontend.
"""

import uuid
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

from asmon import config
from asmon.models import Snapshot, HostRecord, WebRiskReport
from asmon.storage.snapshots import SnapshotStore
from asmon.discovery import PassiveDiscovery

logger = logging.getLogger("asmon.dashboard")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="ASMON", version="1.0.0")

STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(exist_ok=True)

# Mount static files (CSS, JS)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ---------------------------------------------------------------------------
# In-memory scan tracker
# ---------------------------------------------------------------------------

class ScanJob:
    """Tracks a running or completed scan."""

    def __init__(self, scan_id: str, target: str):
        self.scan_id = scan_id
        self.target = target
        self.status = "running"       # running | completed | failed
        self.started_at = datetime.now(timezone.utc)
        self.finished_at: Optional[datetime] = None
        self.snapshot: Optional[Snapshot] = None
        self.error: Optional[str] = None
        self.progress: str = "Starting scan..."

_scans: dict[str, ScanJob] = {}
_scans_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=253, description="Domain or IP to scan")

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str

class ScanResultResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    started_at: str
    finished_at: Optional[str] = None
    error: Optional[str] = None
    progress: str = ""
    snapshot: Optional[dict] = None

class HistoryEntry(BaseModel):
    snapshot_id: str
    target: str
    captured_at: str
    host_count: int
    cve_count: int
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None

# ---------------------------------------------------------------------------
# Scan worker (runs in background thread)
# ---------------------------------------------------------------------------

def _run_scan_worker(job: ScanJob) -> None:
    """Execute the full passive scan pipeline in a background thread."""
    store = SnapshotStore(config.SNAPSHOT_DIR)
    discovery = PassiveDiscovery()

    try:
        # --- Discovery ---
        job.progress = "Running passive discovery..."
        disc_results = discovery.discover(job.target)
        discovered_ips: list[str] = disc_results["unique_ips"]

        ip_to_hostnames: dict[str, list[str]] = {}
        for hostname, ips in disc_results.get("resolved", {}).items():
            for ip in ips:
                if ip not in ip_to_hostnames:
                    ip_to_hostnames[ip] = []
                if hostname not in ip_to_hostnames[ip]:
                    ip_to_hostnames[ip].append(hostname)

        # --- Build hosts (no Shodan — keys stay server-side for paid plans) ---
        job.progress = f"Found {len(discovered_ips)} IPs, enriching..."
        hosts = [
            HostRecord(
                ip=ip, hostnames=ip_to_hostnames.get(ip, []),
                services=[], source="discovery", shodan_enriched=False,
            )
            for ip in discovered_ips
        ]

        # --- InternetDB enrichment (free, no key) ---
        if hosts:
            job.progress = "Querying InternetDB for ports and CVEs..."
            try:
                from asmon.internetdb import InternetDBClient
                idb = InternetDBClient()
                idb.enrich_hosts(hosts)
            except Exception as exc:
                logger.warning("InternetDB failed: %s", exc)

        # --- CISA KEV ---
        has_cves = any(len(h.cves) > 0 for h in hosts)
        if hosts and has_cves:
            job.progress = "Cross-referencing CISA KEV catalog..."
            try:
                from asmon.cisa_kev import CISAKEVClient
                kev = CISAKEVClient()
                kev.enrich_hosts(hosts)
            except Exception as exc:
                logger.warning("CISA KEV failed: %s", exc)

        # --- EPSS ---
        has_cves = any(len(h.cves) > 0 for h in hosts)
        if hosts and has_cves:
            job.progress = "Fetching EPSS exploitation scores..."
            try:
                from asmon.epss import EPSSClient
                epss = EPSSClient()
                epss.enrich_hosts(hosts)
            except Exception as exc:
                logger.warning("EPSS failed: %s", exc)

        # --- DNS security ---
        if hosts:
            job.progress = "Checking DNS security records..."
            try:
                from asmon.dns_security import DNSSecurityChecker
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
                logger.warning("DNS security failed: %s", exc)

        # --- Risk scoring ---
        job.progress = "Computing risk score..."
        from asmon.scoring import compute_risk_score
        risk_score = compute_risk_score(
            Snapshot(snapshot_id="temp", target=job.target, hosts=hosts)
        )

        # --- Save snapshot ---
        snapshot = Snapshot(
            snapshot_id=job.scan_id,
            target=job.target,
            hosts=hosts,
            metadata={
                "mode": "passive",
                "source": "dashboard",
                "subdomains_discovered": len(disc_results["subdomains"]),
                "ips_discovered": len(discovered_ips),
            },
            risk_score=risk_score,
        )
        store.save(snapshot)

        job.snapshot = snapshot
        job.status = "completed"
        job.progress = "Scan complete"
        job.finished_at = datetime.now(timezone.utc)

    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
        job.progress = f"Failed: {exc}"
        job.finished_at = datetime.now(timezone.utc)
        logger.error("Scan failed for %s: %s", job.target, exc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/")
async def serve_frontend():
    """Serve the main dashboard page."""
    index = STATIC_DIR / "index.html"
    if not index.exists():
        raise HTTPException(status_code=404, detail="Frontend not built")
    return FileResponse(str(index))


@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(req: ScanRequest):
    """Start a new scan. Returns immediately with a scan_id to poll."""
    target = req.target.strip().lower()

    # Basic validation
    if not target or len(target) < 3:
        raise HTTPException(status_code=400, detail="Invalid target")

    scan_id = str(uuid.uuid4())
    job = ScanJob(scan_id=scan_id, target=target)

    with _scans_lock:
        _scans[scan_id] = job

    # Run scan in background thread
    thread = threading.Thread(target=_run_scan_worker, args=(job,), daemon=True)
    thread.start()

    return ScanResponse(scan_id=scan_id, status="running", target=target)


@app.get("/api/scan/{scan_id}", response_model=ScanResultResponse)
async def get_scan_result(scan_id: str):
    """Poll scan status. Returns snapshot data when complete."""
    with _scans_lock:
        job = _scans.get(scan_id)

    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = ScanResultResponse(
        scan_id=job.scan_id,
        status=job.status,
        target=job.target,
        started_at=job.started_at.isoformat(),
        finished_at=job.finished_at.isoformat() if job.finished_at else None,
        error=job.error,
        progress=job.progress,
    )

    if job.snapshot:
        result.snapshot = job.snapshot.model_dump(mode="json")

    return result


@app.get("/api/history", response_model=list[HistoryEntry])
async def get_history(target: Optional[str] = None, limit: int = 20):
    """List past scan snapshots."""
    store = SnapshotStore(config.SNAPSHOT_DIR)
    entries: list[HistoryEntry] = []

    if target:
        targets = [target.strip().lower()]
    else:
        targets = store.list_targets()

    for t in targets:
        snapshots = store.list_snapshots(t)
        for snap in snapshots[:limit]:
            cve_count = sum(len(h.cves) for h in snap.hosts)
            entry = HistoryEntry(
                snapshot_id=snap.snapshot_id,
                target=snap.target,
                captured_at=snap.captured_at.isoformat(),
                host_count=len(snap.hosts),
                cve_count=cve_count,
                risk_score=snap.risk_score.score if snap.risk_score else None,
                risk_level=snap.risk_score.level if snap.risk_score else None,
            )
            entries.append(entry)

    # Sort by date, newest first
    entries.sort(key=lambda e: e.captured_at, reverse=True)
    return entries[:limit]


@app.get("/api/snapshot/{snapshot_id}")
async def get_snapshot(snapshot_id: str):
    """Return full snapshot data for a given ID."""
    store = SnapshotStore(config.SNAPSHOT_DIR)
    snap = store.get(snapshot_id)
    if not snap:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return snap.model_dump(mode="json")


@app.get("/api/report/{snapshot_id}")
async def download_report(snapshot_id: str):
    """Generate and return an HTML report for download."""
    store = SnapshotStore(config.SNAPSHOT_DIR)
    snap = store.get(snapshot_id)
    if not snap:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    from asmon.report import generate_html
    html = generate_html(snap)
    safe_target = snap.target.replace(".", "_")
    ts = snap.captured_at.strftime("%Y%m%d_%H%M%S")
    filename = f"asmon_report_{safe_target}_{ts}.html"

    return HTMLResponse(
        content=html,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Type": "text/html; charset=utf-8",
        },
    )


@app.get("/detail/{snapshot_id}")
async def serve_detail_page(snapshot_id: str):
    """Serve the detail page."""
    detail = STATIC_DIR / "detail.html"
    if not detail.exists():
        raise HTTPException(status_code=404, detail="Detail page not built")
    return FileResponse(str(detail))
