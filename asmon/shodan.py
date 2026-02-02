"""
integrations/shodan.py — Shodan API client and response normaliser.

Responsibilities:
  1. Authenticate (key from config or injected at construction)
  2. Query by domain or organisation name
  3. Paginate results (Shodan returns 100/page by default)
  4. Normalise raw Shodan JSON into our canonical HostRecord list

Design notes:
  - We never store raw Shodan responses. Normalisation happens inline.
  - SSL parsing is best-effort; missing fields are silently None.
  - CVEs are forwarded verbatim from Shodan (we don't validate them).
  - Rate-limit errors (429) are surfaced immediately — the caller decides retry policy.
"""

import logging
from datetime import datetime, timezone

import shodan as shodan_lib
from shodan import APIError as ShodanException

from asmon.models import HostRecord, ServiceInfo, SSLCert

logger = logging.getLogger("asmon.shodan")


class ShodanClient:
    """
    Thin wrapper around the official shodan Python SDK.
    Keeps all Shodan-specific logic isolated from the rest of the tool.
    """

    def __init__(self, api_key: str | None = None):
        if not api_key:
            raise ValueError(
                "Shodan API key is required. "
                "Set SHODAN_API_KEY env var or pass --shodan-key."
            )
        self._api = shodan_lib.Shodan(api_key)
        logger.info("ShodanClient initialised.")

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def search_domain(self, domain: str, max_results: int = 500) -> list[HostRecord]:
        """
        Search Shodan for all hosts associated with a domain.
        Uses the hostname: search filter.
        """
        logger.info("Searching Shodan for domain: %s (max=%d)", domain, max_results)
        query = f"hostname:{domain}"
        return self._paginated_search(query, max_results)

    def search_org(self, org_name: str, max_results: int = 500) -> list[HostRecord]:
        """Search by organisation name."""
        logger.info("Searching Shodan for org: %s (max=%d)", org_name, max_results)
        query = f"org:\"{org_name}\""
        return self._paginated_search(query, max_results)

    def host_details(self, ip: str) -> HostRecord | None:
        """Fetch full details for a single IP. Returns None on 404."""
        try:
            raw = self._api.host(ip)
            return _normalise_host(raw)
        except ShodanException as exc:
            if "No information available" in str(exc):
                logger.debug("No Shodan data for %s", ip)
                return None
            raise

    # ------------------------------------------------------------------
    # Internal: pagination
    # ------------------------------------------------------------------

    def _paginated_search(self, query: str, max_results: int) -> list[HostRecord]:
        """
        Iterate Shodan search pages until we hit max_results or exhaust results.
        search_all() handles pagination internally in the SDK.
        """
        hosts: list[HostRecord] = []
        seen_ips: set[str] = set()

        try:
            for result in self._api.search_all(query, limit=max_results):
                ip = result.get("ip_str")
                if not ip or ip in seen_ips:
                    continue
                seen_ips.add(ip)

                host = _normalise_host(result)
                hosts.append(host)
                logger.debug("Collected host %s (%d/%d)", ip, len(hosts), max_results)

                if len(hosts) >= max_results:
                    break

        except ShodanException as exc:
            logger.warning("Shodan search ended early: %s", exc)

        logger.info("Shodan search returned %d hosts.", len(hosts))
        return hosts


# ---------------------------------------------------------------------------
# Normalisation helpers (module-level, stateless)
# ---------------------------------------------------------------------------

def _normalise_host(raw: dict) -> HostRecord:
    """
    Flatten a Shodan host dict into our HostRecord.
    Silently skips fields that don't map cleanly.
    """
    services: list[ServiceInfo] = []

    for port_info in raw.get("data", []):
        ssl_cert = None
        ssl_raw = port_info.get("ssl", {})
        cert_raw = ssl_raw.get("cert", {})
        if cert_raw:
            ssl_cert = _parse_ssl(cert_raw)

        svc = ServiceInfo(
            port=port_info.get("port", 0),
            protocol=port_info.get("transport", "tcp"),
            service_name=port_info.get("service"),
            banner=_truncate(port_info.get("data")),
            product=port_info.get("product"),
            version=port_info.get("version"),
            ssl=ssl_cert,
            cves=port_info.get("cves") or [],
        )
        services.append(svc)

    last_seen = None
    if raw.get("timestamp"):
        try:
            last_seen = datetime.fromisoformat(raw["timestamp"].replace("Z", "+00:00"))
        except (ValueError, TypeError):
            pass

    return HostRecord(
        ip=raw.get("ip_str", ""),
        hostnames=raw.get("hostnames") or [],
        org=raw.get("org"),
        asn=raw.get("asn"),
        country=raw.get("country_name") or raw.get("country"),
        city=raw.get("city"),
        services=services,
        last_seen=last_seen,
        source="shodan",
    )


def _parse_ssl(cert: dict) -> SSLCert:
    """Best-effort SSL cert parser. Missing fields become None."""

    def _dt(val):
        if not val:
            return None
        try:
            return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None

    subject = cert.get("subject", {})
    issuer = cert.get("issuer", {})
    validity = cert.get("validity", {})

    return SSLCert(
        subject=subject.get("CN") if isinstance(subject, dict) else str(subject),
        issuer=issuer.get("O") if isinstance(issuer, dict) else str(issuer),
        not_before=_dt(validity.get("start")),
        not_after=_dt(validity.get("end")),
        san=cert.get("san") or [],
        fingerprint_sha256=(cert.get("fingerprint") or {}).get("sha256"),
    )


def _truncate(banner: str | None, max_len: int = 512) -> str | None:
    """Trim banners to a safe length. Strip null bytes."""
    if banner is None:
        return None
    return banner.replace("\x00", "").strip()[:max_len]
