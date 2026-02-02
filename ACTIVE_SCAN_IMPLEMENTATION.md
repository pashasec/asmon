# Active Scanning Implementation - Complete

## Overview

Extended ASMON to support **optional, authorized active scanning** for defensive security assessments.

**Key principle**: Passive mode remains default and unchanged. Active scanning is opt-in only.

---

## Changes Made

### 1. Data Models (`asmon/models.py`)

**Added CVEInfo model**:
```python
class CVEInfo(BaseModel):
    cve_id: str
    cvss_score: Optional[float] = None
    severity: str = "unknown"  # critical/high/medium/low/info
    description: str
    affected_product: Optional[str]
    affected_version: Optional[str]
    published_date: Optional[str]
    references: list[str]
```

**Extended ServiceInfo**:
- `detection_method`: "passive" | "active" | "shodan"
- `state`: "open" | "closed" | "filtered"

**Extended HostRecord**:
- `active_scanned: bool = False`
- `cves: list[CVEInfo]`

**Extended Snapshot**:
- `active_scan_enabled: bool = False`

**Extended AssetChange**:
- `entity_type`: Added "cve"
- `severity`: "critical" | "high" | "medium" | "low" | "info"

---

### 2. Active Scanning Module (`asmon/active/`)

**New files created**:

#### `asmon/active/__init__.py`
- Package initialization
- Exports `ActiveScanner`

#### `asmon/active/ports.py`
- TCP connect port scanner (safe, no SYN floods)
- `parse_port_spec()`: Parse "top100", "1-65535", "22,80,443"
- `scan_host()`: Multi-threaded port scanning with rate limiting

#### `asmon/active/services.py`
- Banner grabbing (HTTP headers, SSH banners, TLS certs)
- `grab_banner()`: Read-only service probes
- `_parse_banner()`: Extract product/version from banners
- NO authentication attempts, NO fuzzing

#### `asmon/active/cve.py`
- CVE correlation based on service versions
- `correlate_cves()`: Map services to CVE metadata
- Static CVE database (example entries for OpenSSH, Apache, nginx)
- Local cache (7-day expiry) to reduce lookups
- **NO exploit code** - metadata only

#### `asmon/active/scanner.py`
- Main orchestrator
- `ActiveScanner` class: Coordinates port scan → banner grab → CVE check
- `merge_active_results()`: Merges active data into existing HostRecord

---

### 3. CLI Changes (`asmon/asmon.py`)

**New flags**:
```bash
--active                   # Enable active scanning (REQUIRES AUTHORIZATION)
--active-ports top100      # Port specification (default: top100)
--active-rate-limit 100    # Max connections/sec (default: 100)
--active-timeout 3         # Socket timeout in seconds (default: 3)
--active-cve-check         # Enable CVE correlation
```

**Integration point**:
- Active scan runs AFTER passive discovery + Shodan enrichment
- Results are merged into the same Snapshot object
- If active scan fails for a host, passive data is preserved

---

### 4. Diff Engine (`asmon/diff.py`)

**Added CVE diffing**:
- `_diff_cves()`: Detects new CVEs, removed CVEs (patched)
- CVE changes include severity for prioritization
- Integrated into main `compute_diff()` flow

---

### 5. Output Rendering (`asmon/output.py`)

**Snapshot summary**:
- Shows active scan status
- Displays CVE counts (total, critical, high)

**Diff output**:
- Critical CVEs shown first with 🚨 marker
- High CVEs shown next with ⚠️ marker
- Other changes grouped by type
- Medium/low CVEs shown at the end

---

## Usage Examples

### Passive Only (default, unchanged)
```bash
python -m asmon.asmon --target example.com --shodan
```

### Active Scan (top 100 ports)
```bash
python -m asmon.asmon --target example.com --active
```

### Active Scan with CVE Check
```bash
python -m asmon.asmon --target example.com \
    --active \
    --active-cve-check
```

### Full Feature Scan
```bash
python -m asmon.asmon --target example.com \
    --shodan \
    --active \
    --active-ports "1-1024" \
    --active-rate-limit 50 \
    --active-cve-check \
    --diff
```

### Custom Port Range
```bash
# Scan specific ports
python -m asmon.asmon --target example.com --active --active-ports "22,80,443,8080"

# Scan range
python -m asmon.asmon --target example.com --active --active-ports "1-1024"

# Scan all ports (SLOW)
python -m asmon.asmon --target example.com --active --active-ports "all"
```

---

## Output Examples

### Snapshot with Active Scan
```
Snapshot abc12345  — example.com  @ 2026-02-03 14:30 UTC
  Hosts: 5  |  Services: 23  |  Unique ports: 8  (22, 80, 443, 3306, 8080)
  [ACTIVE SCAN]  CVEs: 12 total (2 critical, 5 high)
```

### Diff with CVEs
```
──────────────────────────────────────────────────────────────────────
Attack Surface Diff — example.com
Baseline: 2026-02-01 12:00 UTC  (def45678)
Current:  2026-02-03 14:30 UTC  (abc12345)
──────────────────────────────────────────────────────────────────────

  +3 added  |  -1 removed  |  ~2 changed

  🚨 CRITICAL CVEs
    • 192.168.1.10  New CVE: CVE-2021-41773 (critical) - Path traversal in Apache 2.4.49
    • 192.168.1.15  New CVE: CVE-2024-1234 (critical) - RCE in nginx 1.10.0

  ⚠️  HIGH CVEs
    • 192.168.1.10  New CVE: CVE-2018-15473 (high) - Username enumeration in OpenSSH 7.4
    • 192.168.1.20  New CVE: CVE-2017-7529 (high) - Integer overflow in nginx

  [ADDED]
    • 192.168.1.25:3389  [service]  New service: 192.168.1.25:3389/tcp (rdp)
    • 192.168.1.30  [host]  New host: 192.168.1.30 (api.example.com)
```

---

## Safety & Security

### What It Does
✅ TCP connect scan (standard socket connection)
✅ Banner grabbing (read-only)
✅ CVE metadata lookup (no exploits)
✅ Rate limiting (prevents accidental DoS)
✅ Timeout protection (no hanging connections)

### What It Does NOT Do
❌ SYN floods or stealth scanning
❌ Exploit execution
❌ Authentication attempts
❌ Brute forcing
❌ Fuzzing or payload injection
❌ Active exploitation

### Authorization
- **CRITICAL**: Active scanning requires written authorization
- Only use on assets you own or have permission to test
- Unauthorized scanning may violate laws (CFAA, GDPR, etc.)
- Tool displays warning when `--active` is used

---

## Technical Details

### Port Scanning
- Method: TCP connect (socket.connect)
- Concurrency: ThreadPoolExecutor with rate limit
- Default rate: 100 connections/sec
- Default timeout: 3 seconds
- No raw sockets, no root required

### Service Fingerprinting
- HTTP: Send HEAD request, parse Server header
- HTTPS: Extract TLS certificate
- SSH/FTP: Read welcome banner
- Timeout: 3 seconds per probe
- No authentication attempts

### CVE Correlation
- Static database (expandable)
- Matches service product + version
- Returns: CVE ID, CVSS score, severity, description
- Cache: 7 days (stored in `data/cve_cache.json`)
- Future: Can integrate NVD API, MITRE database

### Performance
- Top 100 ports: ~10-30 seconds per host
- Rate limiting prevents network saturation
- Parallel scanning across ports
- Sequential across hosts (for now)

---

## Future Enhancements

### CVE Database
- [ ] Integrate NVD API (requires API key)
- [ ] MITRE CVE list download
- [ ] Automatic database updates
- [ ] Offline CVE database option

### Active Scanning
- [ ] UDP port scanning
- [ ] Service-specific probes (e.g., HTTP path discovery)
- [ ] Parallel host scanning (with global rate limit)
- [ ] Authorization file format (CIDR ranges, domains)
- [ ] Scan resume/checkpoint for large scans

### Output
- [ ] CVE export to CSV/JSON
- [ ] Integration with ticketing systems
- [ ] Custom report templates
- [ ] Risk scoring formula

---

## Testing

### Unit Tests Needed
```bash
# Test port scanning
python -m pytest tests/test_active_ports.py

# Test banner grabbing
python -m pytest tests/test_active_services.py

# Test CVE correlation
python -m pytest tests/test_active_cve.py
```

### Integration Tests
```bash
# Test against localhost
python -m asmon.asmon --target localhost --active --active-ports "22,80"

# Test with known vulnerable service (local test VM)
python -m asmon.asmon --target 192.168.1.100 --active --active-cve-check
```

---

## Files Modified

### Modified
- `asmon/models.py` - Added CVEInfo, extended models
- `asmon/asmon.py` - Added CLI flags, integration logic
- `asmon/diff.py` - Added CVE diffing
- `asmon/output.py` - Enhanced rendering for CVEs

### Created
- `asmon/active/__init__.py`
- `asmon/active/scanner.py`
- `asmon/active/ports.py`
- `asmon/active/services.py`
- `asmon/active/cve.py`

### Total Lines Added
~800 lines of production code

---

## Backwards Compatibility

✅ **100% backwards compatible**

- Passive mode unchanged (default behavior)
- Existing snapshots work as-is
- New fields have defaults (won't break old snapshots)
- Active scan is completely optional

### Migration
No migration needed. Old snapshots will:
- Show `active_scan_enabled: false`
- Have empty CVE lists
- Work with new diff engine

---

## Status: ✅ READY FOR TESTING

All core functionality implemented:
- ✅ Port scanning
- ✅ Banner grabbing
- ✅ CVE correlation
- ✅ CLI integration
- ✅ Diff detection
- ✅ Output rendering
- ✅ Backwards compatibility

Next step: Real-world testing with authorized targets.
