"""
internetdb.py — Shodan InternetDB client (free, no API key).

InternetDB is Shodan's free, unauthenticated API that returns basic
port, hostname, CPE, tag, and CVE data for any IPv4 address.

    https://internetdb.shodan.io/{ip}

Why this matters:
  - No API key required (works out of the box)
  - No rate limit documented (be respectful: small delay between requests)
  - Returns ports + CVEs for every IP passively discovered
  - Makes ASMON useful even without a paid Shodan account

What it returns:
  - ports:      list of open ports (e.g. [22, 80, 443])
  - hostnames:  reverse DNS hostnames
  - cpes:       Common Platform Enumeration strings (product/version)
  - vulns:      CVE IDs associated with detected services
  - tags:       labels like "cloud", "vpn", "self-signed", etc.

What it does NOT return:
  - Banners / raw service responses
  - CVSS scores (just CVE IDs — we enrich via CISA KEV later)
  - Service names (we infer from port numbers)

Design:
  - Pure enrichment layer.  Takes a list of HostRecords, enriches in place.
  - Merges with existing data (never overwrites Shodan-sourced fields).
  - Failures on individual IPs are logged and skipped — never fatal.
"""

import time
import logging
import requests
from asmon.models import HostRecord, ServiceInfo, CVEInfo

logger = logging.getLogger("asmon.internetdb")

INTERNETDB_URL = "https://internetdb.shodan.io"
REQUEST_TIMEOUT = 10

# Well-known port → likely service name mapping
_PORT_SERVICE_MAP: dict[int, str] = {
    21:    "ftp",
    22:    "ssh",
    23:    "telnet",
    25:    "smtp",
    53:    "dns",
    80:    "http",
    110:   "pop3",
    143:   "imap",
    443:   "https",
    445:   "smb",
    465:   "smtps",
    587:   "submission",
    993:   "imaps",
    995:   "pop3s",
    1433:  "mssql",
    1521:  "oracle",
    2082:  "cpanel",
    2083:  "cpanel-ssl",
    2086:  "whm",
    2096:  "whm-ssl",
    3306:  "mysql",
    3389:  "rdp",
    5432:  "postgresql",
    5900:  "vnc",
    5984:  "couchdb",
    6379:  "redis",
    8080:  "http-alt",
    8443:  "https-alt",
    8888:  "http-alt",
    9200:  "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


class InternetDBClient:
    """
    Query Shodan InternetDB for free port/CVE/hostname data.

    Usage:
        client = InternetDBClient()
        client.enrich_hosts(hosts)   # enriches in place
    """

    def __init__(self, delay_between_requests: float = 0.2):
        """
        Args:
            delay_between_requests: Seconds to wait between API calls.
                                   Be respectful — it's a free service.
        """
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "asmon/1.0"})
        self._delay = delay_between_requests

    def lookup(self, ip: str) -> dict | None:
        """
        Query InternetDB for a single IP.

        Returns parsed JSON dict on success, None on failure or 404.
        """
        url = f"{INTERNETDB_URL}/{ip}"
        try:
            resp = self._session.get(url, timeout=REQUEST_TIMEOUT)

            if resp.status_code == 404:
                # IP not in database — normal, not an error
                logger.debug("InternetDB: no data for %s", ip)
                return None

            if resp.status_code != 200:
                logger.warning("InternetDB returned %d for %s", resp.status_code, ip)
                return None

            return resp.json()

        except requests.exceptions.Timeout:
            logger.warning("InternetDB timeout for %s", ip)
            return None
        except requests.exceptions.RequestException as exc:
            logger.warning("InternetDB request failed for %s: %s", ip, exc)
            return None
        except ValueError:
            logger.warning("InternetDB returned invalid JSON for %s", ip)
            return None

    def enrich_hosts(self, hosts: list[HostRecord]) -> dict:
        """
        Enrich a list of HostRecords with InternetDB data.

        Modifies hosts in place.  Merges carefully:
        - New ports are added as ServiceInfo (won't overwrite existing)
        - New hostnames are appended (won't duplicate)
        - New CVEs are added at host level (won't duplicate)
        - CPE-derived product info added where possible

        Returns summary dict:
            {
                "queried": int,
                "enriched": int,
                "new_ports_added": int,
                "new_cves_added": int,
                "new_hostnames_added": int,
            }
        """
        stats = {
            "queried": 0,
            "enriched": 0,
            "new_ports_added": 0,
            "new_cves_added": 0,
            "new_hostnames_added": 0,
        }

        for i, host in enumerate(hosts):
            if i > 0:
                time.sleep(self._delay)

            stats["queried"] += 1
            data = self.lookup(host.ip)

            if data is None:
                continue

            stats["enriched"] += 1

            # --- Merge ports → ServiceInfo ---
            existing_ports = {(s.port, s.protocol) for s in host.services}

            for port in data.get("ports", []):
                if (port, "tcp") not in existing_ports:
                    svc_name = _PORT_SERVICE_MAP.get(port)
                    host.services.append(ServiceInfo(
                        port=port,
                        protocol="tcp",
                        service_name=svc_name,
                        detection_method="internetdb",
                        state="open",
                    ))
                    stats["new_ports_added"] += 1

            # --- Merge hostnames ---
            for hostname in data.get("hostnames", []):
                if hostname and hostname not in host.hostnames:
                    host.hostnames.append(hostname)
                    stats["new_hostnames_added"] += 1

            # --- Merge CVEs ---
            existing_cve_ids = {c.cve_id for c in host.cves}

            for cve_id in data.get("vulns", []):
                if cve_id not in existing_cve_ids:
                    host.cves.append(CVEInfo(
                        cve_id=cve_id,
                        severity="unknown",   # InternetDB doesn't provide CVSS
                        description="",        # Will be enriched by CISA KEV later
                    ))
                    existing_cve_ids.add(cve_id)
                    stats["new_cves_added"] += 1

            # --- Parse CPEs for product/version info ---
            _enrich_services_from_cpes(host, data.get("cpes", []))

            # --- Store tags as metadata ---
            tags = data.get("tags", [])
            if tags:
                for svc in host.services:
                    if svc.detection_method == "internetdb":
                        for tag in tags:
                            if tag not in svc.tags:
                                svc.tags.append(tag)

        logger.info(
            "InternetDB enrichment: %d/%d IPs enriched, "
            "+%d ports, +%d CVEs, +%d hostnames",
            stats["enriched"], stats["queried"],
            stats["new_ports_added"], stats["new_cves_added"],
            stats["new_hostnames_added"],
        )

        return stats


def _enrich_services_from_cpes(host: HostRecord, cpes: list[str]) -> None:
    """
    Parse CPE strings and attach product/version to matching services.

    CPE format: cpe:/a:vendor:product:version
    Example:    cpe:/a:apache:http_server:2.4.49
    """
    for cpe in cpes:
        parts = cpe.replace("cpe:/", "").replace("cpe:2.3:", "").split(":")
        if len(parts) < 3:
            continue

        # parts[0] = type (a=application, o=os, h=hardware)
        # parts[1] = vendor
        # parts[2] = product
        # parts[3] = version (if present)
        vendor = parts[1] if len(parts) > 1 else None
        product = parts[2] if len(parts) > 2 else None
        version = parts[3] if len(parts) > 3 else None

        if not product:
            continue

        # Try to find a matching service by product name
        product_lower = product.lower().replace("_", " ")
        for svc in host.services:
            if svc.detection_method == "internetdb" and not svc.product:
                # Match by known product→port associations
                if _cpe_matches_service(product_lower, svc.port):
                    svc.product = f"{vendor}/{product}" if vendor else product
                    if version and version != "*":
                        svc.version = version
                    break


def _cpe_matches_service(product: str, port: int) -> bool:
    """Heuristic: does this CPE product likely run on this port?"""
    mappings = {
        "http":          {80, 8080, 8888},
        "http server":   {80, 8080, 8888},
        "apache":        {80, 443, 8080},
        "nginx":         {80, 443, 8080},
        "lighttpd":      {80, 443},
        "openssl":       {443, 8443},
        "openssh":       {22},
        "mysql":         {3306},
        "postgresql":    {5432},
        "redis":         {6379},
        "mongodb":       {27017},
        "elasticsearch": {9200},
        "couchdb":       {5984},
        "memcached":     {11211},
        "proftpd":       {21},
        "vsftpd":        {21},
        "pure ftpd":     {21},
        "exim":          {25, 465, 587},
        "postfix":       {25, 465, 587},
        "dovecot":       {143, 993, 110, 995},
    }

    for keyword, ports in mappings.items():
        if keyword in product and port in ports:
            return True

    return False
