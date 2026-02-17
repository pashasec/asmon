"""
report.py — HTML/PDF report generator for ASMON scans.

Generates a self-contained HTML report from a Snapshot (+ optional
SurfaceDiff).  All CSS is inlined — the HTML file can be opened in any
browser with no external dependencies.

PDF export uses the same HTML piped through a headless browser or
weasyprint if available.  Falls back to "just open the HTML" if no
PDF engine is installed.

Usage from CLI:
    python -m asmon.asmon --target example.com --report html
    python -m asmon.asmon --target example.com --report pdf
    python -m asmon.asmon --targets targets.yaml --report html
"""

import logging
from datetime import datetime, timezone
from pathlib import Path
from html import escape

from asmon import config
from asmon.models import Snapshot, SurfaceDiff, HostRecord, RiskScore

logger = logging.getLogger("asmon.report")

REPORT_DIR = config.DATA_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------------------------
# CSS (inlined into every report)
# ------------------------------------------------------------------

_CSS = """\
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 2rem; }
.container { max-width: 960px; margin: 0 auto; }
h1 { font-size: 1.8rem; color: #f8fafc; margin-bottom: 0.25rem; }
h2 { font-size: 1.3rem; color: #94a3b8; margin: 2rem 0 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
h3 { font-size: 1.1rem; color: #cbd5e1; margin: 1.2rem 0 0.5rem; }
.subtitle { color: #64748b; font-size: 0.9rem; margin-bottom: 1.5rem; }
.badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 4px; font-size: 0.75rem;
         font-weight: 600; text-transform: uppercase; }
.badge-critical { background: #dc2626; color: #fff; }
.badge-high { background: #ea580c; color: #fff; }
.badge-medium { background: #d97706; color: #fff; }
.badge-low { background: #2563eb; color: #fff; }
.badge-info { background: #475569; color: #e2e8f0; }
.score-box { display: inline-flex; align-items: center; gap: 0.75rem; padding: 0.75rem 1.25rem;
             border-radius: 8px; margin: 1rem 0; }
.score-critical { background: #450a0a; border: 1px solid #dc2626; }
.score-high { background: #431407; border: 1px solid #ea580c; }
.score-medium { background: #422006; border: 1px solid #d97706; }
.score-low { background: #1e3a5f; border: 1px solid #2563eb; }
.score-info { background: #1e293b; border: 1px solid #475569; }
.score-number { font-size: 2rem; font-weight: 700; color: #f8fafc; }
.score-label { font-size: 0.85rem; color: #94a3b8; }
table { width: 100%; border-collapse: collapse; margin: 0.75rem 0; }
th { text-align: left; padding: 0.5rem 0.75rem; background: #1e293b; color: #94a3b8;
     font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #1e293b; font-size: 0.85rem; }
tr:hover td { background: #1e293b; }
.card { background: #1e293b; border-radius: 8px; padding: 1rem 1.25rem; margin: 0.75rem 0; }
.host-header { display: flex; justify-content: space-between; align-items: center; }
.ip { font-family: monospace; font-size: 1rem; color: #f8fafc; }
.hostnames { color: #64748b; font-size: 0.8rem; }
.change-added { color: #4ade80; }
.change-removed { color: #f87171; }
.change-changed { color: #fbbf24; }
.footer { margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #334155;
          color: #475569; font-size: 0.75rem; text-align: center; }
.section-empty { color: #475569; font-style: italic; padding: 0.5rem 0; }
"""


# ------------------------------------------------------------------
# HTML builder
# ------------------------------------------------------------------

def generate_html(
    snapshot: Snapshot,
    diff: SurfaceDiff | None = None,
    title: str | None = None,
) -> str:
    """Build a complete self-contained HTML report string."""

    target = snapshot.target
    title = title or f"ASMON Report - {target}"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    parts: list[str] = []
    parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
<h1>Attack Surface Report</h1>
<p class="subtitle">{escape(target)} &mdash; {escape(now)}</p>
""")

    # --- Risk score ---
    parts.append(_render_risk_score(snapshot.risk_score))

    # --- Summary stats ---
    parts.append(_render_summary(snapshot))

    # --- Diff section (if available) ---
    if diff and diff.changes:
        parts.append(_render_diff_section(diff))

    # --- Host details ---
    parts.append(_render_hosts(snapshot.hosts))

    # --- CVE table ---
    all_cves = [(h.ip, cve) for h in snapshot.hosts for cve in h.cves]
    if all_cves:
        parts.append(_render_cve_table(all_cves))

    # --- Web risks ---
    all_signals = [
        (h.ip, report, signal)
        for h in snapshot.hosts
        for report in h.web_risks
        for signal in report.signals
    ]
    if all_signals:
        parts.append(_render_web_risks(all_signals))

    # --- Footer ---
    parts.append(f"""
<div class="footer">
  Generated by ASMON (Attack Surface Monitor) &mdash; {escape(now)}<br>
  Snapshot: {escape(snapshot.snapshot_id[:8])} &mdash;
  {len(snapshot.hosts)} host(s), {sum(len(h.services) for h in snapshot.hosts)} service(s)
</div>
</div>
</body>
</html>""")

    return "\n".join(parts)


def _render_risk_score(score: RiskScore | None) -> str:
    if not score:
        return ""
    level = score.level
    css_class = f"score-{level}"
    badge_class = f"badge-{level}"
    return f"""
<div class="score-box {css_class}">
  <span class="score-number">{score.score}</span>
  <div>
    <span class="badge {badge_class}">{level.upper()}</span><br>
    <span class="score-label">Risk Score (0-100)</span>
  </div>
</div>
"""


def _render_summary(snapshot: Snapshot) -> str:
    total_hosts = len(snapshot.hosts)
    total_services = sum(len(h.services) for h in snapshot.hosts)
    total_cves = sum(len(h.cves) for h in snapshot.hosts)
    critical_cves = sum(1 for h in snapshot.hosts for c in h.cves if c.severity == "critical")
    high_cves = sum(1 for h in snapshot.hosts for c in h.cves if c.severity == "high")

    unique_ports = set()
    for h in snapshot.hosts:
        for s in h.services:
            unique_ports.add(s.port)

    return f"""
<h2>Summary</h2>
<table>
<tr><td>Hosts discovered</td><td><strong>{total_hosts}</strong></td></tr>
<tr><td>Open services</td><td><strong>{total_services}</strong> across <strong>{len(unique_ports)}</strong> unique ports</td></tr>
<tr><td>CVEs identified</td><td><strong>{total_cves}</strong>
  (<span class="badge badge-critical">{critical_cves} critical</span>
   <span class="badge badge-high">{high_cves} high</span>)</td></tr>
<tr><td>Scan time</td><td>{snapshot.captured_at.strftime('%Y-%m-%d %H:%M UTC')}</td></tr>
</table>
"""


def _render_diff_section(diff: SurfaceDiff) -> str:
    lines = [f"""
<h2>Changes Since Last Scan</h2>
<p class="subtitle">Baseline: {diff.baseline_captured_at.strftime('%Y-%m-%d %H:%M UTC')}
({diff.baseline_id[:8]})</p>
<table>
<tr><th>Type</th><th>IP</th><th>Detail</th><th>Severity</th></tr>
"""]

    for change in diff.changes:
        css = f"change-{change.change_type}"
        sev_badge = f'<span class="badge badge-{change.severity}">{change.severity}</span>'
        detail_text = escape(change.detail)
        if len(detail_text) > 120:
            detail_text = detail_text[:120] + "..."
        lines.append(
            f'<tr><td class="{css}">{change.change_type.upper()}</td>'
            f'<td class="ip">{escape(change.ip)}</td>'
            f'<td>{detail_text}</td>'
            f'<td>{sev_badge}</td></tr>'
        )

    lines.append("</table>")
    return "\n".join(lines)


def _render_hosts(hosts: list[HostRecord]) -> str:
    lines = ["<h2>Hosts</h2>"]

    for host in hosts:
        hostnames = ", ".join(host.hostnames) if host.hostnames else "no reverse DNS"
        org = f" &mdash; {escape(host.org)}" if host.org else ""
        country = f" ({escape(host.country)})" if host.country else ""

        lines.append(f"""
<div class="card">
  <div class="host-header">
    <div>
      <span class="ip">{escape(host.ip)}</span>{org}{country}
      <div class="hostnames">{escape(hostnames)}</div>
    </div>
    <div>
      <span class="badge badge-info">{len(host.services)} services</span>
      <span class="badge badge-{'critical' if any(c.severity == 'critical' for c in host.cves) else 'info'}">{len(host.cves)} CVEs</span>
    </div>
  </div>
""")

        # Services table
        if host.services:
            lines.append("""
  <h3>Services</h3>
  <table>
  <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>
""")
            for svc in sorted(host.services, key=lambda s: s.port):
                lines.append(
                    f'  <tr><td>{svc.port}</td><td>{svc.protocol}</td>'
                    f'<td>{escape(svc.service_name or "-")}</td>'
                    f'<td>{escape(svc.product or "-")}</td>'
                    f'<td>{escape(svc.version or "-")}</td></tr>'
                )
            lines.append("  </table>")

        lines.append("</div>")

    return "\n".join(lines)


def _render_cve_table(cves: list[tuple[str, object]]) -> str:
    # Sort: critical first, then high, etc.
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    cves_sorted = sorted(cves, key=lambda x: rank.get(x[1].severity, 5))

    lines = ["""
<h2>Vulnerabilities (CVEs)</h2>
<table>
<tr><th>CVE ID</th><th>Severity</th><th>Host</th><th>Product</th><th>Description</th></tr>
"""]

    # Cap at 100 rows for readability
    shown = cves_sorted[:100]
    for ip, cve in shown:
        sev_badge = f'<span class="badge badge-{cve.severity}">{cve.severity}</span>'
        desc = escape(cve.description or "-")
        if len(desc) > 150:
            desc = desc[:150] + "..."
        lines.append(
            f'<tr><td><strong>{escape(cve.cve_id)}</strong></td>'
            f'<td>{sev_badge}</td>'
            f'<td class="ip">{escape(ip)}</td>'
            f'<td>{escape(cve.affected_product or "-")}</td>'
            f'<td>{desc}</td></tr>'
        )

    if len(cves_sorted) > 100:
        lines.append(f'<tr><td colspan="5" class="section-empty">... and {len(cves_sorted) - 100} more CVEs</td></tr>')

    lines.append("</table>")
    return "\n".join(lines)


def _render_web_risks(signals: list[tuple[str, object, object]]) -> str:
    lines = ["""
<h2>Web Risk Signals</h2>
<table>
<tr><th>Severity</th><th>Host</th><th>Finding</th><th>Detail</th><th>Recommendation</th></tr>
"""]

    for ip, report, signal in signals:
        sev_badge = f'<span class="badge badge-{signal.severity}">{signal.severity}</span>'
        detail = escape(signal.detail or "")
        if len(detail) > 120:
            detail = detail[:120] + "..."
        rec = escape(signal.recommendation or "-")
        if len(rec) > 120:
            rec = rec[:120] + "..."
        lines.append(
            f'<tr><td>{sev_badge}</td>'
            f'<td class="ip">{escape(ip)}</td>'
            f'<td><strong>{escape(signal.title)}</strong></td>'
            f'<td>{detail}</td>'
            f'<td>{rec}</td></tr>'
        )

    lines.append("</table>")
    return "\n".join(lines)


# ------------------------------------------------------------------
# File writers
# ------------------------------------------------------------------

def save_html_report(
    snapshot: Snapshot,
    diff: SurfaceDiff | None = None,
    output_dir: Path | None = None,
) -> Path:
    """Generate and save an HTML report. Returns the file path."""
    output_dir = output_dir or REPORT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    html = generate_html(snapshot, diff)
    safe_target = snapshot.target.replace(".", "_").replace("/", "_")
    ts = snapshot.captured_at.strftime("%Y%m%d_%H%M%S")
    filename = f"asmon_report_{safe_target}_{ts}.html"
    path = output_dir / filename

    path.write_text(html, encoding="utf-8")
    logger.info("HTML report saved: %s", path)
    return path


def save_pdf_report(
    snapshot: Snapshot,
    diff: SurfaceDiff | None = None,
    output_dir: Path | None = None,
) -> Path:
    """
    Generate a PDF report.

    Tries weasyprint first (pip install weasyprint).
    Falls back to saving HTML with a note.
    """
    output_dir = output_dir or REPORT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    html = generate_html(snapshot, diff)
    safe_target = snapshot.target.replace(".", "_").replace("/", "_")
    ts = snapshot.captured_at.strftime("%Y%m%d_%H%M%S")
    pdf_path = output_dir / f"asmon_report_{safe_target}_{ts}.pdf"

    try:
        from weasyprint import HTML as WeasyHTML  # type: ignore[import-untyped]
        WeasyHTML(string=html).write_pdf(str(pdf_path))
        logger.info("PDF report saved: %s", pdf_path)
        return pdf_path
    except ImportError:
        logger.warning(
            "weasyprint not installed — saving HTML instead. "
            "Install with: pip install weasyprint"
        )
        html_path = output_dir / f"asmon_report_{safe_target}_{ts}.html"
        html_path.write_text(html, encoding="utf-8")
        logger.info("HTML report saved (PDF unavailable): %s", html_path)
        return html_path
    except Exception as exc:
        logger.error("PDF generation failed: %s — saving HTML instead", exc)
        html_path = output_dir / f"asmon_report_{safe_target}_{ts}.html"
        html_path.write_text(html, encoding="utf-8")
        return html_path
