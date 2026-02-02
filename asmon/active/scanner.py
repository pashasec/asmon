"""
scanner.py — Main active scanning orchestrator.

Coordinates:
1. Port scanning (TCP connect)
2. Service fingerprinting (banner grabbing)
3. CVE correlation (metadata only)

SAFE MODE: No exploits, no brute force, no authentication attempts.
"""

import logging
from datetime import datetime, timezone

from asmon.models import HostRecord, ServiceInfo
from asmon.active.ports import parse_port_spec, scan_host
from asmon.active.services import grab_banner
from asmon.active.cve import correlate_cves

logger = logging.getLogger("asmon.active.scanner")


class ActiveScanner:
    """
    Safe, authorized active scanner.

    Usage:
        scanner = ActiveScanner(port_spec="top100", rate_limit=50)
        host_data = scanner.scan_host("192.168.1.1")
    """

    def __init__(
        self,
        port_spec: str = "top100",
        rate_limit: int = 100,
        timeout: int = 3,
        enable_cve_check: bool = False,
    ):
        """
        Initialize active scanner.

        Args:
            port_spec: Port specification ("top100", "1-1024", "22,80,443")
            rate_limit: Max concurrent connections (default: 100)
            timeout: Socket timeout in seconds (default: 3)
            enable_cve_check: Whether to correlate CVEs (default: False)
        """
        self.ports = parse_port_spec(port_spec)
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.enable_cve_check = enable_cve_check

        logger.info(
            "Active scanner initialized: %d ports, rate_limit=%d, timeout=%ds, cve_check=%s",
            len(self.ports),
            rate_limit,
            timeout,
            enable_cve_check,
        )

    def scan_host(self, ip: str) -> dict:
        """
        Perform active scan on a single host.

        Returns:
            {
                "services": [ServiceInfo, ...],
                "cves": [CVEInfo, ...],
                "active_scanned": True,
            }
        """
        logger.info("Starting active scan on %s", ip)

        # Step 1: Port scan
        open_ports = scan_host(ip, self.ports, self.rate_limit, self.timeout)

        if not open_ports:
            logger.info("No open ports found on %s", ip)
            return {"services": [], "cves": [], "active_scanned": True}

        # Step 2: Service fingerprinting
        services = []
        for port_info in open_ports:
            port = port_info["port"]
            logger.debug("Fingerprinting %s:%d", ip, port)

            banner_data = grab_banner(ip, port, self.timeout)

            svc = ServiceInfo(
                port=port,
                protocol="tcp",
                service_name=banner_data["service_name"],
                banner=banner_data["banner"],
                product=banner_data["product"],
                version=banner_data["version"],
                detection_method="active",
                state=port_info["state"],
            )
            services.append(svc)

        logger.info("Detected %d services on %s", len(services), ip)

        # Step 3: CVE correlation (optional)
        cves = []
        if self.enable_cve_check:
            logger.info("Correlating CVEs for %s", ip)
            cves = correlate_cves(services)
            if cves:
                logger.warning("Found %d CVEs on %s", len(cves), ip)

        return {
            "services": services,
            "cves": cves,
            "active_scanned": True,
        }


def merge_active_results(host: HostRecord, active_data: dict) -> None:
    """
    Merge active scan results into existing HostRecord.

    This updates the host in-place by adding:
    - New services from active scan
    - CVEs detected
    - active_scanned flag
    """
    # Add active services (avoid duplicates based on port)
    existing_ports = {svc.port for svc in host.services}
    for svc in active_data["services"]:
        if svc.port not in existing_ports:
            host.services.append(svc)

    # Add CVEs
    host.cves.extend(active_data["cves"])

    # Mark as scanned
    host.active_scanned = True

    logger.debug(
        "Merged active results into %s: %d services, %d CVEs",
        host.ip,
        len(active_data["services"]),
        len(active_data["cves"]),
    )
