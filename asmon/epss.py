"""
epss.py — EPSS (Exploit Prediction Scoring System) enrichment.

Queries the FIRST.org EPSS API to get exploitation probability for CVEs.
Free, no API key, supports batch queries (up to 100 CVEs per request).

    https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2017-0144

What EPSS provides:
  - epss:       Probability (0.0–1.0) that a CVE will be exploited in the
                next 30 days.  0.94 = 94% chance.
  - percentile: Where this CVE ranks relative to all others.
                0.99 = worse than 99% of all CVEs.

Why this matters:
  - Not all CVEs are equal.  A host with 50 CVEs needs prioritisation.
  - EPSS answers: "which 3 should I patch TODAY?"
  - Complements CISA KEV: KEV says "this IS being exploited",
    EPSS says "this WILL LIKELY be exploited."

Severity upgrade rules:
  - EPSS >= 0.7  AND severity not already critical  →  "high"
  - EPSS >= 0.4  AND severity is unknown/low/info   →  "medium"
  - EPSS <  0.4                                      →  no change
  (CISA KEV "critical" is never downgraded.)
"""

import logging
import requests
from asmon.models import HostRecord, CVEInfo

logger = logging.getLogger("asmon.epss")

EPSS_API_URL = "https://api.first.org/data/v1/epss"
REQUEST_TIMEOUT = 15
BATCH_SIZE = 100  # EPSS API limit per request


class EPSSClient:
    """
    Query EPSS scores for CVEs in batch.

    Usage:
        client = EPSSClient()
        client.enrich_hosts(hosts)
    """

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "asmon/1.0"})

    def batch_lookup(self, cve_ids: list[str]) -> dict[str, dict]:
        """
        Query EPSS for a batch of CVE IDs.

        Args:
            cve_ids: List of CVE IDs (e.g. ["CVE-2021-44228", ...])

        Returns:
            Dict mapping CVE ID → {"epss": float, "percentile": float}
        """
        results: dict[str, dict] = {}

        # Process in chunks of BATCH_SIZE
        for i in range(0, len(cve_ids), BATCH_SIZE):
            chunk = cve_ids[i:i + BATCH_SIZE]
            chunk_results = self._query_chunk(chunk)
            results.update(chunk_results)

        return results

    def _query_chunk(self, cve_ids: list[str]) -> dict[str, dict]:
        """Query EPSS API for a single batch (up to 100 CVEs)."""
        cve_param = ",".join(cve_ids)

        try:
            resp = self._session.get(
                EPSS_API_URL,
                params={"cve": cve_param},
                timeout=REQUEST_TIMEOUT,
            )

            if resp.status_code != 200:
                logger.warning("EPSS API returned %d", resp.status_code)
                return {}

            data = resp.json()
            results = {}

            for entry in data.get("data", []):
                cve_id = entry.get("cve")
                if cve_id:
                    results[cve_id] = {
                        "epss": float(entry.get("epss", 0)),
                        "percentile": float(entry.get("percentile", 0)),
                    }

            return results

        except requests.exceptions.Timeout:
            logger.warning("EPSS API timeout for batch of %d CVEs", len(cve_ids))
            return {}
        except requests.exceptions.RequestException as exc:
            logger.warning("EPSS API request failed: %s", exc)
            return {}
        except (ValueError, KeyError) as exc:
            logger.warning("EPSS API returned invalid data: %s", exc)
            return {}

    def enrich_hosts(self, hosts: list[HostRecord]) -> dict:
        """
        Enrich CVEs across all hosts with EPSS scores.

        For each CVE:
          - Appends EPSS probability + percentile to description
          - Upgrades severity based on exploitation likelihood
          - Adds EPSS reference

        Returns summary dict.
        """
        # 1. Collect all unique CVE IDs across all hosts
        cve_to_hosts: dict[str, list[CVEInfo]] = {}
        for host in hosts:
            for cve in host.cves:
                if cve.cve_id not in cve_to_hosts:
                    cve_to_hosts[cve.cve_id] = []
                cve_to_hosts[cve.cve_id].append(cve)

        if not cve_to_hosts:
            logger.info("No CVEs to enrich with EPSS")
            return {"total_cves": 0, "epss_found": 0, "severity_upgrades": 0}

        logger.info("Querying EPSS for %d unique CVEs", len(cve_to_hosts))

        # 2. Batch query EPSS
        all_cve_ids = list(cve_to_hosts.keys())
        epss_data = self.batch_lookup(all_cve_ids)

        # 3. Enrich each CVEInfo object
        stats = {
            "total_cves": len(cve_to_hosts),
            "epss_found": len(epss_data),
            "severity_upgrades": 0,
            "high_risk_cves": 0,     # EPSS >= 0.7
        }

        for cve_id, score in epss_data.items():
            epss_score = score["epss"]
            percentile = score["percentile"]

            # Apply to all CVEInfo objects with this CVE ID
            for cve_info in cve_to_hosts.get(cve_id, []):
                # Append EPSS info to description
                pct_str = f"{epss_score * 100:.1f}%"
                rank_str = f"{percentile * 100:.0f}th percentile"
                epss_note = f"[EPSS: {pct_str} exploitation probability, {rank_str}]"

                if cve_info.description:
                    if "[EPSS:" not in cve_info.description:
                        cve_info.description = f"{epss_note} {cve_info.description}"
                else:
                    cve_info.description = epss_note

                # Add EPSS reference
                ref = f"EPSS Score: {epss_score:.4f} ({rank_str})"
                if ref not in cve_info.references:
                    cve_info.references.append(ref)

                # Severity upgrade (never downgrade KEV "critical")
                upgraded = _maybe_upgrade_severity(cve_info, epss_score)
                if upgraded:
                    stats["severity_upgrades"] += 1

                if epss_score >= 0.7:
                    stats["high_risk_cves"] += 1

        logger.info(
            "EPSS: scored %d/%d CVEs, %d severity upgrades, %d high-risk (>=70%%)",
            stats["epss_found"],
            stats["total_cves"],
            stats["severity_upgrades"],
            stats["high_risk_cves"],
        )

        return stats


def _maybe_upgrade_severity(cve: CVEInfo, epss_score: float) -> bool:
    """
    Upgrade CVE severity based on EPSS score.
    Never downgrades. Returns True if severity changed.

    Rules:
      - EPSS >= 0.7 → at least "high" (unless already "critical")
      - EPSS >= 0.4 → at least "medium" (unless already "high"/"critical")
      - EPSS <  0.4 → no change
    """
    _SEVERITY_RANK = {
        "unknown": 0,
        "info": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }

    current_rank = _SEVERITY_RANK.get(cve.severity, 0)

    if epss_score >= 0.7:
        target = "high"
    elif epss_score >= 0.4:
        target = "medium"
    else:
        return False

    target_rank = _SEVERITY_RANK[target]

    if target_rank > current_rank:
        old = cve.severity
        cve.severity = target
        logger.debug("EPSS upgraded %s: %s → %s (EPSS=%.2f)", cve.cve_id, old, target, epss_score)
        return True

    return False
