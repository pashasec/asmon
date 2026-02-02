# Shodan Pipeline Hardening - Changes Summary

## Problem Statement
Tool was losing ALL discovery data when Shodan enrichment failed, resulting in empty snapshots (Hosts: 0).

## Root Causes Fixed
1. ASN validation errors: Shodan returns `"AS396982"` (string), model expected `int`
2. 403 Forbidden errors crashed the tool instead of continuing
3. Discovery data discarded when enrichment failed - no fallback mechanism
4. Validation errors in Shodan response normalization crashed enrichment

---

## Changes Applied

### 1. [models.py](asmon/models.py#L46-L52) - Data Model Tolerance

**Line 46**: ASN type changed to accept both formats
```python
# Before:
asn: Optional[int] = None

# After:
asn: Optional[str | int] = None  # Shodan returns "AS12345" or int
```

**Line 52**: Added enrichment tracking flag
```python
shodan_enriched: bool = False  # True if Shodan enrichment succeeded
```

**Why**: Real Shodan data varies - ASN can be string or int, enrichment status must be explicit.

---

### 2. [shodan.py](asmon/shodan.py#L62-L75) - Graceful Error Handling

**Lines 62-75**: Never raise exceptions, always return None
```python
# Before:
except ShodanException as exc:
    if "No information available" in str(exc):
        logger.debug("No Shodan data for %s", ip)
        return None
    raise  # ← Crashed on 403!

# After:
except ShodanException as exc:
    exc_str = str(exc)
    if "No information available" in exc_str:
        logger.debug("No Shodan data for %s", ip)
    elif "403" in exc_str or "Forbidden" in exc_str:
        logger.warning("Shodan access denied for %s (check plan limits)", ip)
    else:
        logger.warning("Shodan lookup error for %s: %s", ip, exc)
    return None  # ← Always return None
```

**Why**: 403 errors are common with plan limits - tool must continue, not crash.

**Lines 110-165**: Wrapped normalization in try/except
```python
def _normalise_host(raw: dict) -> HostRecord:
    try:
        # ... parse services, handle individual failures ...
        return HostRecord(
            # ... fields ...
            shodan_enriched=True,
        )
    except Exception as exc:
        # Validation failed - return minimal record
        logger.warning("Failed to normalise Shodan data: %s", exc)
        return HostRecord(
            ip=raw.get("ip_str", "unknown"),
            services=[],
            source="shodan",
            shodan_enriched=False,
        )
```

**Why**: Shodan data is unpredictable - partial failures shouldn't lose the entire host.

---

### 3. [asmon.py](asmon/asmon.py#L110-L120) - Helper Function

**Lines 110-120**: Created fallback record builder
```python
def _create_basic_host(ip: str) -> HostRecord:
    """Create minimal host record when Shodan enrichment unavailable."""
    return HostRecord(
        ip=ip,
        hostnames=[],
        services=[],
        source="discovery",
        shodan_enriched=False,
    )
```

**Why**: Discovery IPs are PRIMARY data - must be preserved even without enrichment.

---

### 4. [asmon.py](asmon/asmon.py#L170-L208) - Critical: Never Lose Discovery Data

**Individual IP enrichment (≤50 IPs)**:
```python
# Before:
for ip in discovered_ips:
    try:
        host = shodan.host_details(ip)
        if host:
            hosts.append(host)
    except Exception as exc:
        logger.warning("Shodan lookup failed for %s: %s", ip, exc)
        # ← IP lost!

# After:
for ip in discovered_ips:
    try:
        host = shodan.host_details(ip)
        if host:
            hosts.append(host)
        else:
            hosts.append(_create_basic_host(ip))  # ← Preserve IP
    except Exception as exc:
        logger.warning("Shodan lookup failed for %s: %s", ip, exc)
        hosts.append(_create_basic_host(ip))  # ← Preserve IP
```

**Domain search (>50 IPs)**:
```python
# Before:
try:
    hosts = shodan.search_domain(root_domain)
except Exception as exc:
    logger.error("Shodan search failed: %s", exc)
    return 3  # ← Crash! All data lost!

# After:
try:
    hosts = shodan.search_domain(root_domain)
    # Add any discovered IPs not in Shodan results
    shodan_ips = {h.ip for h in hosts}
    for ip in discovered_ips:
        if ip not in shodan_ips:
            hosts.append(_create_basic_host(ip))
except Exception as exc:
    logger.warning("Shodan search failed: %s", exc)
    # Fallback: use discovery data
    hosts = [_create_basic_host(ip) for ip in discovered_ips]
```

**No Shodan mode**:
```python
# Before:
else:
    logger.info("Shodan not enabled. Use --shodan to enrich results.")
    # ← hosts = [] stays empty!

# After:
else:
    logger.info("Shodan not enabled. Creating records from passive discovery.")
    hosts = [_create_basic_host(ip) for ip in discovered_ips]
```

**Why**: Discovery = PRIMARY, Shodan = OPTIONAL. Never lose IPs due to API issues.

---

## Behavior Changes

### Before Hardening:
```
$ python -m asmon.asmon --target example.com --shodan
[ERROR] Shodan validation error: ASN expected int, got "AS12345"
Snapshot saved: ...
Hosts: 0  |  Services: 0  ← EMPTY!
```

### After Hardening:
```
$ python -m asmon.asmon --target example.com --shodan
[WARN] Shodan access denied for 1.2.3.4 (check plan limits)
[WARN] Failed to normalise Shodan data: validation error
Snapshot saved: ...
Hosts: 15  |  Services: 8  ← Discovery data preserved!
```

---

## What Was NOT Changed
- No business logic redesign
- No new features added
- No refactoring of unrelated code
- Discovery, diff, AI analysis untouched

---

## Verification Commands

```bash
# Test with Shodan (should never show Hosts: 0)
python -m asmon.asmon --target example.com --shodan --shodan-key YOUR_KEY

# Test without Shodan (should show discovered IPs)
python -m asmon.asmon --target example.com

# Check enrichment status in snapshot JSON
cat data/snapshots/*.json | jq '.hosts[] | {ip, shodan_enriched}'
```

---

## Status: ✅ HARDENED

- ✅ ASN accepts both string and int
- ✅ 403 errors handled gracefully (warning, not crash)
- ✅ Validation errors handled gracefully
- ✅ Discovery data NEVER lost
- ✅ Enrichment status tracked per host
- ✅ No stack traces for Shodan issues
- ✅ Tool continues execution on partial failures
