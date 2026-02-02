"""
tests/test_diff.py — Unit tests for core/diff.py.

Tests are self-contained. No network calls, no Shodan, no AI.
We construct Snapshot objects in-memory and verify the diff output.
"""

import sys
from datetime import datetime, timezone, timedelta

from asmon.models import Snapshot, HostRecord, ServiceInfo, SSLCert
from asmon.diff import compute_diff


def _snapshot(hosts, snap_id="test", offset_hours=0):
    return Snapshot(
        snapshot_id=snap_id, target="example.com",
        captured_at=datetime(2025, 6, 1, 12, 0, tzinfo=timezone.utc) + timedelta(hours=offset_hours),
        hosts=hosts,
    )

def _host(ip, services=None, **kw):
    return HostRecord(ip=ip, services=services or [],
                      hostnames=kw.get("hostnames", []),
                      org=kw.get("org"), asn=kw.get("asn"))

def _svc(port, proto="tcp", **kw):
    return ServiceInfo(port=port, protocol=proto,
                       service_name=kw.get("service_name"),
                       product=kw.get("product"), version=kw.get("version"),
                       banner=kw.get("banner"), cves=kw.get("cves", []),
                       ssl=kw.get("ssl"))


# --- Host-level ---

def test_new_host_detected():
    b = _snapshot([_host("1.2.3.4")], "base", 0)
    c = _snapshot([_host("1.2.3.4"), _host("5.6.7.8")], "curr", 1)
    d = compute_diff(b, c)
    assert d.added_count == 1
    assert any(x.ip == "5.6.7.8" and x.change_type == "added" for x in d.changes)

def test_host_removed():
    b = _snapshot([_host("1.2.3.4"), _host("5.6.7.8")], "base", 0)
    c = _snapshot([_host("1.2.3.4")], "curr", 1)
    d = compute_diff(b, c)
    assert d.removed_count == 1

def test_no_changes():
    h = [_host("1.2.3.4", [_svc(443, service_name="https")])]
    d = compute_diff(_snapshot(h, "base", 0), _snapshot(h, "curr", 1))
    assert len(d.changes) == 0

# --- Service-level ---

def test_new_service():
    b = _snapshot([_host("1.2.3.4", [_svc(443)])], "base", 0)
    c = _snapshot([_host("1.2.3.4", [_svc(443), _svc(22, service_name="ssh")])], "curr", 1)
    d = compute_diff(b, c)
    added = [x for x in d.changes if x.change_type == "added" and x.entity_type == "service"]
    assert len(added) == 1 and added[0].port == 22

def test_service_removed():
    b = _snapshot([_host("1.2.3.4", [_svc(443), _svc(22)])], "base", 0)
    c = _snapshot([_host("1.2.3.4", [_svc(443)])], "curr", 1)
    d = compute_diff(b, c)
    removed = [x for x in d.changes if x.change_type == "removed" and x.entity_type == "service"]
    assert len(removed) == 1 and removed[0].port == 22

def test_version_change():
    b = _snapshot([_host("1.2.3.4", [_svc(22, product="OpenSSH", version="7.9")])], "base", 0)
    c = _snapshot([_host("1.2.3.4", [_svc(22, product="OpenSSH", version="8.9")])], "curr", 1)
    d = compute_diff(b, c)
    assert any("version" in x.detail for x in d.changes)

def test_new_cves():
    b = _snapshot([_host("1.2.3.4", [_svc(443, cves=[])])], "base", 0)
    c = _snapshot([_host("1.2.3.4", [_svc(443, cves=["CVE-2024-1234"])])], "curr", 1)
    d = compute_diff(b, c)
    assert any("CVE-2024-1234" in x.detail for x in d.changes)

# --- SSL ---

def test_ssl_rotation():
    old = SSLCert(subject="*.example.com", fingerprint_sha256="a" * 64)
    new = SSLCert(subject="*.example.com", fingerprint_sha256="b" * 64)
    b = _snapshot([_host("1.2.3.4", [_svc(443, ssl=old)])], "base", 0)
    c = _snapshot([_host("1.2.3.4", [_svc(443, ssl=new)])], "curr", 1)
    d = compute_diff(b, c)
    ssl_ch = [x for x in d.changes if x.entity_type == "ssl_cert"]
    assert len(ssl_ch) == 1 and ssl_ch[0].change_type == "changed"

def test_ssl_appeared():
    b = _snapshot([_host("1.2.3.4", [_svc(443, ssl=None)])], "base", 0)
    c = _snapshot([_host("1.2.3.4", [_svc(443, ssl=SSLCert(subject="ex.com"))])], "curr", 1)
    d = compute_diff(b, c)
    assert any(x.entity_type == "ssl_cert" and x.change_type == "added" for x in d.changes)

# --- Metadata ---

def test_org_change():
    b = _snapshot([_host("1.2.3.4", org="Old")], "base", 0)
    c = _snapshot([_host("1.2.3.4", org="New")], "curr", 1)
    d = compute_diff(b, c)
    assert any("Org" in x.detail for x in d.changes)

def test_asn_change():
    b = _snapshot([_host("1.2.3.4", asn=1111)], "base", 0)
    c = _snapshot([_host("1.2.3.4", asn=2222)], "curr", 1)
    d = compute_diff(b, c)
    assert any("ASN" in x.detail for x in d.changes)

# --- Edge cases ---

def test_empty_snapshots():
    d = compute_diff(_snapshot([], "base", 0), _snapshot([], "curr", 1))
    assert len(d.changes) == 0

def test_full_replacement():
    b = _snapshot([_host("1.1.1.1", [_svc(80)]), _host("2.2.2.2")], "base", 0)
    c = _snapshot([_host("3.3.3.3", [_svc(8080)]), _host("4.4.4.4")], "curr", 1)
    d = compute_diff(b, c)
    assert d.added_count == 2 and d.removed_count == 2


# --- Runner ---

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  [PASS] {fn.__name__}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {fn.__name__}: {e}")
            failed += 1
    print(f"\n  {passed} passed, {failed} failed")
    sys.exit(0 if not failed else 1)
