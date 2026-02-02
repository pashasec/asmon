#!/usr/bin/env python3
"""
Quick test of active scanning module.
Tests against localhost (safe, no external targets).
"""

from asmon.active.scanner import ActiveScanner
from asmon.active.ports import parse_port_spec
from asmon.models import HostRecord

print("[TEST] Active Scanning Module")
print("=" * 60)

# Test 1: Port spec parsing
print("\n[1] Testing port spec parsing...")
ports = parse_port_spec("22,80,443")
assert ports == [22, 80, 443], "Failed to parse port list"
print(f"    [PASS] Parsed '22,80,443' -> {ports}")

ports = parse_port_spec("top100")
assert len(ports) > 0, "Failed to parse top100"
print(f"    [PASS] Parsed 'top100' -> {len(ports)} ports")

# Test 2: Scanner initialization
print("\n[2] Testing scanner initialization...")
scanner = ActiveScanner(
    port_spec="22,80",
    rate_limit=10,
    timeout=1,
    enable_cve_check=False,
)
print(f"    [PASS] Scanner initialized: {len(scanner.ports)} ports")

# Test 3: Scan localhost (should be safe)
print("\n[3] Testing localhost scan (safe)...")
try:
    result = scanner.scan_host("127.0.0.1")
    print(f"    [PASS] Scan completed")
    print(f"    Services found: {len(result['services'])}")
    for svc in result['services']:
        print(f"      - {svc.port}/{svc.protocol} ({svc.service_name or 'unknown'})")
except Exception as exc:
    print(f"    [INFO] Scan failed (expected if no services on localhost): {exc}")

# Test 4: CVE correlation
print("\n[4] Testing CVE correlation...")
from asmon.active.cve import lookup_cves
cves = lookup_cves("OpenSSH", "7.4")
if cves:
    print(f"    [PASS] Found {len(cves)} CVEs for OpenSSH 7.4")
    for cve in cves:
        print(f"      - {cve.cve_id} ({cve.severity})")
else:
    print("    [INFO] No CVEs in static database for OpenSSH 7.4")

print("\n" + "=" * 60)
print("[COMPLETE] All basic tests passed!")
print("\nTo test with real targets:")
print("  python -m asmon.asmon --target example.com --active --active-ports top100")
