"""
core/diff.py — Attack surface diff engine.

This is the core of the tool. Given two Snapshot objects (baseline and current),
it produces a SurfaceDiff containing every detected change.

Detection logic:
  - Hosts are keyed by IP address.
  - Services within a host are keyed by (port, protocol).
  - SSL certs are compared by fingerprint when available, otherwise by subject+validity.
  - Changes are classified as: added, removed, changed.

Design principles:
  - Pure function. Takes two Snapshots, returns a SurfaceDiff.
  - No I/O, no side effects. Logging only.
  - The diff engine does not interpret risk. That's the AI layer's job (or the user's).
"""

import logging
from asmon.models import Snapshot, SurfaceDiff, AssetChange, HostRecord, ServiceInfo

logger = logging.getLogger("asmon.diff")


def compute_diff(baseline: Snapshot, current: Snapshot) -> SurfaceDiff:
    """
    Compare two snapshots and return a structured diff.
    baseline = older snapshot. current = newer snapshot.
    """
    logger.info(
        "Computing diff: baseline=%s (%d hosts) vs current=%s (%d hosts)",
        baseline.snapshot_id, len(baseline.hosts),
        current.snapshot_id, len(current.hosts),
    )

    changes: list[AssetChange] = []

    baseline_hosts = _index_hosts(baseline.hosts)
    current_hosts = _index_hosts(current.hosts)

    baseline_ips = set(baseline_hosts.keys())
    current_ips = set(current_hosts.keys())

    # --- Host-level: new hosts ---
    for ip in sorted(current_ips - baseline_ips):
        host = current_hosts[ip]
        changes.append(AssetChange(
            change_type="added",
            entity_type="host",
            ip=ip,
            detail=f"New host: {ip} ({', '.join(host.hostnames) or 'no hostname'})",
            new=host.model_dump(),
        ))

    # --- Host-level: removed hosts ---
    for ip in sorted(baseline_ips - current_ips):
        host = baseline_hosts[ip]
        changes.append(AssetChange(
            change_type="removed",
            entity_type="host",
            ip=ip,
            detail=f"Host gone: {ip} ({', '.join(host.hostnames) or 'no hostname'})",
            old=host.model_dump(),
        ))

    # --- Service + metadata changes on persisting hosts ---
    for ip in sorted(baseline_ips & current_ips):
        changes.extend(_diff_services(ip, baseline_hosts[ip].services, current_hosts[ip].services))
        changes.extend(_diff_host_meta(ip, baseline_hosts[ip], current_hosts[ip]))
        changes.extend(_diff_cves(ip, baseline_hosts[ip], current_hosts[ip]))

    diff = SurfaceDiff(
        target=current.target,
        baseline_id=baseline.snapshot_id,
        current_id=current.snapshot_id,
        baseline_captured_at=baseline.captured_at,
        current_captured_at=current.captured_at,
        changes=changes,
        added_count=sum(1 for c in changes if c.change_type == "added"),
        removed_count=sum(1 for c in changes if c.change_type == "removed"),
        changed_count=sum(1 for c in changes if c.change_type == "changed"),
    )

    logger.info("Diff: +%d -%d ~%d", diff.added_count, diff.removed_count, diff.changed_count)
    return diff


# ---------------------------------------------------------------------------
# Service comparison
# ---------------------------------------------------------------------------

def _diff_services(ip: str, old_svc: list[ServiceInfo], new_svc: list[ServiceInfo]) -> list[AssetChange]:
    changes: list[AssetChange] = []
    old_map = {(s.port, s.protocol): s for s in old_svc}
    new_map = {(s.port, s.protocol): s for s in new_svc}

    old_keys, new_keys = set(old_map), set(new_map)

    for key in sorted(new_keys - old_keys):
        port, proto = key
        svc = new_map[key]
        changes.append(AssetChange(
            change_type="added", entity_type="service", ip=ip, port=port,
            detail=f"New service: {ip}:{port}/{proto} ({svc.service_name or 'unknown'})",
            new=svc.model_dump(),
        ))

    for key in sorted(old_keys - new_keys):
        port, proto = key
        svc = old_map[key]
        changes.append(AssetChange(
            change_type="removed", entity_type="service", ip=ip, port=port,
            detail=f"Service gone: {ip}:{port}/{proto} ({svc.service_name or 'unknown'})",
            old=svc.model_dump(),
        ))

    for key in sorted(old_keys & new_keys):
        port, proto = key
        old, new = old_map[key], new_map[key]
        field_diff = _compare_fields(old, new)
        if field_diff:
            changes.append(AssetChange(
                change_type="changed", entity_type="service", ip=ip, port=port,
                detail=f"Changed: {ip}:{port}/{proto} — {field_diff}",
                old=old.model_dump(), new=new.model_dump(),
            ))
        ssl_change = _diff_ssl(ip, port, old, new)
        if ssl_change:
            changes.append(ssl_change)

    return changes


def _compare_fields(old: ServiceInfo, new: ServiceInfo) -> str:
    parts: list[str] = []
    if old.product != new.product:
        parts.append(f"product {old.product!r}->{new.product!r}")
    if old.version != new.version:
        parts.append(f"version {old.version!r}->{new.version!r}")
    if old.service_name != new.service_name:
        parts.append(f"service {old.service_name!r}->{new.service_name!r}")
    if old.banner != new.banner:
        parts.append("banner changed")
    added_cves = set(new.cves) - set(old.cves)
    removed_cves = set(old.cves) - set(new.cves)
    if added_cves:
        parts.append(f"new CVEs: {sorted(added_cves)}")
    if removed_cves:
        parts.append(f"fixed CVEs: {sorted(removed_cves)}")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# SSL comparison
# ---------------------------------------------------------------------------

def _diff_ssl(ip: str, port: int, old: ServiceInfo, new: ServiceInfo) -> AssetChange | None:
    o, n = old.ssl, new.ssl
    if o is None and n is None:
        return None
    if o is None:
        return AssetChange(change_type="added", entity_type="ssl_cert", ip=ip, port=port,
                           detail=f"SSL cert appeared: {ip}:{port} subject={n.subject}",
                           new=n.model_dump())
    if n is None:
        return AssetChange(change_type="removed", entity_type="ssl_cert", ip=ip, port=port,
                           detail=f"SSL cert gone: {ip}:{port}", old=o.model_dump())

    # Both present — compare by fingerprint or fallback fields
    if o.fingerprint_sha256 and n.fingerprint_sha256:
        if o.fingerprint_sha256 != n.fingerprint_sha256:
            return AssetChange(change_type="changed", entity_type="ssl_cert", ip=ip, port=port,
                               detail=f"SSL rotated: {ip}:{port} new subject={n.subject}",
                               old=o.model_dump(), new=n.model_dump())
    elif o.subject != n.subject or o.not_after != n.not_after:
        return AssetChange(change_type="changed", entity_type="ssl_cert", ip=ip, port=port,
                           detail=f"SSL changed: {ip}:{port} subject={n.subject}",
                           old=o.model_dump(), new=n.model_dump())
    return None


# ---------------------------------------------------------------------------
# Host metadata comparison
# ---------------------------------------------------------------------------

def _diff_host_meta(ip: str, old: HostRecord, new: HostRecord) -> list[AssetChange]:
    changes: list[AssetChange] = []
    if old.org != new.org:
        changes.append(AssetChange(change_type="changed", entity_type="host", ip=ip,
                                   detail=f"Org: {old.org!r} -> {new.org!r}"))
    if old.asn != new.asn:
        changes.append(AssetChange(change_type="changed", entity_type="host", ip=ip,
                                   detail=f"ASN: AS{old.asn} -> AS{new.asn}"))
    added_h = set(new.hostnames) - set(old.hostnames)
    removed_h = set(old.hostnames) - set(new.hostnames)
    if added_h or removed_h:
        parts = []
        if added_h: parts.append(f"+{sorted(added_h)}")
        if removed_h: parts.append(f"-{sorted(removed_h)}")
        changes.append(AssetChange(change_type="changed", entity_type="host", ip=ip,
                                   detail=f"Hostnames on {ip}: {' '.join(parts)}"))
    return changes


# ---------------------------------------------------------------------------
# CVE comparison (for active scan results)
# ---------------------------------------------------------------------------

def _diff_cves(ip: str, old: HostRecord, new: HostRecord) -> list[AssetChange]:
    """Compare CVEs between baseline and current host."""
    changes: list[AssetChange] = []

    old_cve_ids = {cve.cve_id for cve in old.cves}
    new_cve_ids = {cve.cve_id for cve in new.cves}

    # New CVEs detected
    for cve_id in sorted(new_cve_ids - old_cve_ids):
        cve = next(c for c in new.cves if c.cve_id == cve_id)
        changes.append(AssetChange(
            change_type="added",
            entity_type="cve",
            ip=ip,
            detail=f"New CVE: {cve_id} ({cve.severity}) - {cve.description[:80]}",
            new=cve.model_dump(),
            severity=cve.severity,
        ))

    # CVEs no longer detected (possibly patched)
    for cve_id in sorted(old_cve_ids - new_cve_ids):
        cve = next(c for c in old.cves if c.cve_id == cve_id)
        changes.append(AssetChange(
            change_type="removed",
            entity_type="cve",
            ip=ip,
            detail=f"CVE fixed: {cve_id} (no longer detected)",
            old=cve.model_dump(),
            severity="info",
        ))

    return changes


def _index_hosts(hosts: list[HostRecord]) -> dict[str, HostRecord]:
    return {h.ip: h for h in hosts}
