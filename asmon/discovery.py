"""
integrations/discovery.py — Passive target discovery.

What this does:
  - Subdomain enumeration via Certificate Transparency (crt.sh)
  - DNS resolution of discovered subdomains
  - Reverse DNS / PTR lookups for IP enrichment

What this deliberately does NOT do:
  - Brute-force subdomain guessing
  - Zone transfers
  - Anything that sends packets to the target

All queries go to third-party passive sources (crt.sh, public DNS resolvers).
"""

import logging
import socket
import re
from urllib.parse import urlparse

import requests

logger = logging.getLogger("asmon.discovery")

CRT_SH_URL = "https://crt.sh/"
# Public DNS resolver for subdomain resolution
PUBLIC_RESOLVER = "8.8.8.8"
RESOLVE_TIMEOUT_SEC = 3


class PassiveDiscovery:
    """Passive-only target discovery. No packets to the target network."""

    def __init__(self, session: requests.Session | None = None):
        self._session = session or requests.Session()
        self._session.headers.update({"User-Agent": "asmon-passive-discovery/1.0"})

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def discover(self, target: str) -> dict:
        """
        Main entry point. Accepts a raw target string:
          - "example.com"
          - "https://sub.example.com/path"
          - "*.example.com"

        Returns a structured dict with subdomains and resolved IPs.
        """
        domain = self._extract_domain(target)
        logger.info("Passive discovery started for: %s", domain)

        subdomains = self._crt_sh_lookup(domain)
        resolved = self._resolve_all(subdomains)

        result = {
            "root_domain": domain,
            "subdomains": sorted(subdomains),
            "resolved": resolved,  # {subdomain: [ip, ...]}
            "unique_ips": sorted({ip for ips in resolved.values() for ip in ips}),
        }

        logger.info(
            "Discovery complete: %d subdomains, %d unique IPs",
            len(subdomains), len(result["unique_ips"])
        )
        return result

    # ------------------------------------------------------------------
    # Certificate Transparency — crt.sh
    # ------------------------------------------------------------------

    def _crt_sh_lookup(self, domain: str) -> set[str]:
        """
        Query crt.sh for all certificates ever issued for *.domain.
        Parses the common_name and name_value fields.
        Returns a deduplicated set of subdomains.
        """
        subdomains: set[str] = set()
        url = f"{CRT_SH_URL}?q=%.{domain}&output=json"

        try:
            resp = self._session.get(url, timeout=15)
            resp.raise_for_status()
            entries = resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("crt.sh query failed for %s: %s", domain, exc)
            return subdomains

        for entry in entries:
            for field in ("common_name", "name_value"):
                raw = entry.get(field, "")
                # name_value can contain newline-separated SANs
                for name in raw.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        subdomains.add(name)

        logger.debug("crt.sh returned %d unique names for %s", len(subdomains), domain)
        return subdomains

    # ------------------------------------------------------------------
    # DNS resolution
    # ------------------------------------------------------------------

    def _resolve_all(self, subdomains: set[str]) -> dict[str, list[str]]:
        """
        Resolve each subdomain to A/AAAA records using the system resolver.
        Failures are silently skipped — subdomains may be parked or expired.
        """
        resolved: dict[str, list[str]] = {}

        for sub in subdomains:
            ips = self._resolve(sub)
            if ips:
                resolved[sub] = ips

        return resolved

    @staticmethod
    def _resolve(hostname: str) -> list[str]:
        """
        Resolve a single hostname. Returns A + AAAA records.
        Uses getaddrinfo for dual-stack support.
        """
        ips: set[str] = set()
        try:
            # AF_UNSPEC = both IPv4 and IPv6
            results = socket.getaddrinfo(
                hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, 0
            )
            for _family, _type, _proto, _canon, sockaddr in results:
                ips.add(sockaddr[0])
        except socket.gaierror:
            pass  # Normal for expired/parked subdomains
        return sorted(ips)

    # ------------------------------------------------------------------
    # Input parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_domain(target: str) -> str:
        """
        Pull the root domain out of whatever the user gave us.
        Handles URLs, bare domains, wildcard notation.
        """
        # Strip wildcards
        target = target.strip().lstrip("*.")

        # If it looks like a URL, parse it
        if "://" in target:
            parsed = urlparse(target)
            target = parsed.hostname or target

        # Strip path/port leftovers
        target = target.split("/")[0].split(":")[0].lower()

        # Basic sanity check
        if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", target):
            raise ValueError(f"Cannot extract a valid domain from: {target!r}")

        return target
