"""
cve.py — CVE correlation based on service versions.

IMPORTANT: This module does NOT contain exploit code.
It only maps detected service versions to known CVE metadata.

Data sources:
- MITRE CVE list (public)
- NVD (National Vulnerability Database)
- Local cache to reduce API calls
"""

import logging
import json
from pathlib import Path
from datetime import datetime, timedelta

from asmon.models import ServiceInfo, CVEInfo
from asmon import config

logger = logging.getLogger("asmon.active.cve")

# Local CVE cache
CVE_CACHE_PATH = config.DATA_DIR / "cve_cache.json"
CVE_CACHE_EXPIRY_DAYS = 7


def correlate_cves(services: list[ServiceInfo]) -> list[CVEInfo]:
    """
    Map services to known CVEs (metadata only, NO exploits).

    Args:
        services: List of detected services with product + version

    Returns:
        List of CVEInfo objects (deduplicated)
    """
    cves = []

    for svc in services:
        if not svc.product or not svc.version:
            logger.debug("Skipping CVE lookup for %s:%d (no product/version)", svc.service_name, svc.port)
            continue

        logger.info("Looking up CVEs for %s %s", svc.product, svc.version)
        matches = lookup_cves(svc.product, svc.version)
        cves.extend(matches)

    # Deduplicate by CVE ID
    seen = set()
    unique_cves = []
    for cve in cves:
        if cve.cve_id not in seen:
            seen.add(cve.cve_id)
            unique_cves.append(cve)

    logger.info("Found %d unique CVEs", len(unique_cves))
    return unique_cves


def lookup_cves(product: str, version: str) -> list[CVEInfo]:
    """
    Query CVE database for product+version.

    Strategy:
    1. Check local cache first
    2. Use static CVE database (included in repo)
    3. TODO: Query NVD API (rate-limited, requires API key)
    """
    # Check cache
    cached = _check_cache(product, version)
    if cached is not None:
        logger.debug("Cache hit for %s %s", product, version)
        return cached

    # Use static database (minimal implementation)
    results = _query_static_db(product, version)

    # Cache results
    _update_cache(product, version, results)

    return results


def _query_static_db(product: str, version: str) -> list[CVEInfo]:
    """
    Query static CVE database (simplified).

    This is a minimal implementation using hardcoded known CVEs.
    In production, this would query a real CVE database or API.
    """
    # Normalize product name
    product_lower = product.lower()

    # Known vulnerable versions (EXAMPLE DATA - not comprehensive)
    known_vulns = {
        "openssh": {
            "7.4": [
                CVEInfo(
                    cve_id="CVE-2018-15473",
                    cvss_score=5.3,
                    severity="medium",
                    description="Username enumeration vulnerability in OpenSSH 7.4",
                    affected_product="OpenSSH",
                    affected_version="7.4",
                    published_date="2018-08-17",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
                )
            ],
        },
        "apache": {
            "2.4.49": [
                CVEInfo(
                    cve_id="CVE-2021-41773",
                    cvss_score=7.5,
                    severity="high",
                    description="Path traversal vulnerability in Apache HTTP Server 2.4.49",
                    affected_product="Apache",
                    affected_version="2.4.49",
                    published_date="2021-10-05",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
                )
            ],
        },
        "nginx": {
            "1.10.0": [
                CVEInfo(
                    cve_id="CVE-2017-7529",
                    cvss_score=7.5,
                    severity="high",
                    description="Integer overflow in nginx range filter module",
                    affected_product="nginx",
                    affected_version="1.10.0",
                    published_date="2017-07-11",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2017-7529"],
                )
            ],
        },
    }

    # Lookup
    if product_lower in known_vulns:
        version_map = known_vulns[product_lower]
        if version in version_map:
            logger.info("Found %d CVEs for %s %s", len(version_map[version]), product, version)
            return version_map[version]

    logger.debug("No CVEs found for %s %s in static DB", product, version)
    return []


def _check_cache(product: str, version: str) -> list[CVEInfo] | None:
    """Check local CVE cache."""
    if not CVE_CACHE_PATH.exists():
        return None

    try:
        with open(CVE_CACHE_PATH) as f:
            cache = json.load(f)

        key = f"{product}:{version}"
        entry = cache.get(key)

        if not entry:
            return None

        # Check expiry
        cached_at = datetime.fromisoformat(entry["cached_at"])
        if datetime.now() - cached_at > timedelta(days=CVE_CACHE_EXPIRY_DAYS):
            logger.debug("Cache expired for %s", key)
            return None

        return [CVEInfo(**cve) for cve in entry["cves"]]

    except Exception as exc:
        logger.warning("Failed to read CVE cache: %s", exc)
        return None


def _update_cache(product: str, version: str, cves: list[CVEInfo]):
    """Update local CVE cache."""
    CVE_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)

    cache = {}
    if CVE_CACHE_PATH.exists():
        try:
            with open(CVE_CACHE_PATH) as f:
                cache = json.load(f)
        except Exception:
            pass

    key = f"{product}:{version}"
    cache[key] = {
        "cached_at": datetime.now().isoformat(),
        "cves": [cve.model_dump() for cve in cves],
    }

    try:
        with open(CVE_CACHE_PATH, "w") as f:
            json.dump(cache, f, indent=2)
        logger.debug("Updated CVE cache for %s", key)
    except Exception as exc:
        logger.warning("Failed to update CVE cache: %s", exc)
