"""
cisa_kev.py — CISA Known Exploited Vulnerabilities (KEV) enrichment.

Downloads the CISA KEV catalog (free, no API key, no rate limit) and
cross-references CVEs found on hosts.  This transforms a generic
"CVE detected" finding into "CVE is actively exploited in the wild."

    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Cache strategy:
  - Catalog is downloaded once and cached to disk.
  - Cache expires after 24 hours (CISA updates ~weekly).
  - If download fails, stale cache is used with a warning.
  - If no cache exists and download fails, enrichment is skipped.

What it enriches on each CVEInfo:
  - severity       → "critical" (any CVE in KEV is actively exploited)
  - description    → from KEV shortDescription
  - affected_product → from KEV vendorProject/product
  - published_date → dateAdded to KEV catalog
  - references     → adds requiredAction + notes
"""

import json
import logging
import requests
from pathlib import Path
from datetime import datetime, timezone, timedelta
from asmon.models import HostRecord, CVEInfo

logger = logging.getLogger("asmon.cisa_kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_TIMEOUT = 20

# Cache alongside snapshots
_DEFAULT_CACHE_DIR = Path(__file__).resolve().parent / "data"
_CACHE_FILENAME = "cisa_kev_cache.json"
_CACHE_MAX_AGE = timedelta(hours=24)


class CISAKEVClient:
    """
    Download and query the CISA KEV catalog.

    Usage:
        kev = CISAKEVClient()
        kev.enrich_hosts(hosts)   # enriches CVEInfo objects in place
    """

    def __init__(self, cache_dir: Path | str | None = None):
        self._cache_dir = Path(cache_dir) if cache_dir else _DEFAULT_CACHE_DIR
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_file = self._cache_dir / _CACHE_FILENAME

        # Load catalog: try cache first, download if stale/missing
        self._catalog: dict[str, dict] = {}
        self._load_catalog()

    # ------------------------------------------------------------------
    # Catalog loading
    # ------------------------------------------------------------------

    def _load_catalog(self) -> None:
        """Load KEV catalog from cache or download fresh."""
        # Try cache first
        if self._cache_file.exists():
            cache_age = datetime.now(timezone.utc) - datetime.fromtimestamp(
                self._cache_file.stat().st_mtime, tz=timezone.utc
            )
            if cache_age < _CACHE_MAX_AGE:
                logger.info("Using cached CISA KEV catalog (age: %s)", cache_age)
                self._load_from_cache()
                return
            else:
                logger.info("CISA KEV cache expired (age: %s), refreshing", cache_age)

        # Download fresh
        if self._download():
            self._load_from_cache()
        elif self._cache_file.exists():
            # Download failed but stale cache exists — use it
            logger.warning("Using stale CISA KEV cache (download failed)")
            self._load_from_cache()
        else:
            logger.warning("No CISA KEV data available — enrichment skipped")

    def _download(self) -> bool:
        """Download KEV catalog from CISA. Returns True on success."""
        try:
            logger.info("Downloading CISA KEV catalog from %s", KEV_URL)
            resp = requests.get(KEV_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()

            data = resp.json()
            vuln_count = data.get("count", 0)
            logger.info("Downloaded %d KEV entries", vuln_count)

            # Write to cache (atomic)
            tmp = self._cache_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(self._cache_file)

            return True

        except requests.exceptions.RequestException as exc:
            logger.error("Failed to download CISA KEV: %s", exc)
            return False
        except (ValueError, KeyError) as exc:
            logger.error("Invalid CISA KEV response: %s", exc)
            return False

    def _load_from_cache(self) -> None:
        """Parse cached JSON into lookup dict keyed by CVE ID."""
        try:
            data = json.loads(self._cache_file.read_text(encoding="utf-8"))
            vulns = data.get("vulnerabilities", [])

            self._catalog = {}
            for entry in vulns:
                cve_id = entry.get("cveID")
                if cve_id:
                    self._catalog[cve_id] = entry

            logger.info("Loaded %d KEV entries into lookup", len(self._catalog))

        except Exception as exc:
            logger.error("Failed to parse CISA KEV cache: %s", exc)
            self._catalog = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_known_exploited(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog (actively exploited)."""
        return cve_id in self._catalog

    def get_kev_entry(self, cve_id: str) -> dict | None:
        """Get full KEV entry for a CVE, or None."""
        return self._catalog.get(cve_id)

    @property
    def catalog_size(self) -> int:
        """Number of CVEs in the loaded catalog."""
        return len(self._catalog)

    def enrich_hosts(self, hosts: list[HostRecord]) -> dict:
        """
        Cross-reference every CVE on every host against the KEV catalog.

        Enriches CVEInfo objects in place:
          - severity → "critical"
          - description → KEV shortDescription
          - affected_product → vendor/product
          - published_date → dateAdded
          - references → requiredAction appended

        Returns summary dict.
        """
        if not self._catalog:
            logger.warning("No KEV catalog loaded — skipping enrichment")
            return {"total_cves_checked": 0, "kev_matches": 0, "ransomware_linked": 0}

        stats = {
            "total_cves_checked": 0,
            "kev_matches": 0,
            "ransomware_linked": 0,
        }

        for host in hosts:
            for cve in host.cves:
                stats["total_cves_checked"] += 1

                kev = self._catalog.get(cve.cve_id)
                if kev is None:
                    continue

                stats["kev_matches"] += 1

                # Upgrade severity — anything in KEV is critical by definition
                cve.severity = "critical"

                # Fill in description if empty
                if not cve.description:
                    cve.description = kev.get("shortDescription", "")

                # Fill in product info
                vendor = kev.get("vendorProject", "")
                product = kev.get("product", "")
                if not cve.affected_product:
                    cve.affected_product = f"{vendor} {product}".strip()

                # Fill in date
                if not cve.published_date:
                    cve.published_date = kev.get("dateAdded")

                # Add required action to references
                action = kev.get("requiredAction", "")
                if action and action not in cve.references:
                    cve.references.append(action)

                notes = kev.get("notes", "")
                if notes and notes not in cve.references:
                    cve.references.append(notes)

                # Track ransomware connection
                ransomware = kev.get("knownRansomwareCampaignUse", "Unknown")
                if ransomware.lower() not in ("unknown", ""):
                    stats["ransomware_linked"] += 1
                    # Add ransomware flag to description
                    cve.description = f"[RANSOMWARE LINKED] {cve.description}"

        logger.info(
            "CISA KEV: checked %d CVEs, %d actively exploited, %d ransomware-linked",
            stats["total_cves_checked"],
            stats["kev_matches"],
            stats["ransomware_linked"],
        )

        return stats
