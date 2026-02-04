"""
asmon/modules/subdomain_takeover.py — Subdomain takeover detection.

Detects potential subdomain takeover vulnerabilities:
  - Dangling CNAME records pointing to deprovisioned services
  - Cloud service fingerprinting (AWS, Azure, GCP, etc.)
  - HTTP response fingerprinting for takeover confirmation
"""

import logging
import socket
import re
from typing import Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from asmon.modules.base import (
    BaseModule,
    ModuleRegistry,
    Finding,
    FindingSeverity,
    FindingConfidence,
    FindingType,
)
from asmon.modules.http_utils import SecurityHTTPClient

logger = logging.getLogger("asmon.modules.subdomain_takeover")


# ---------------------------------------------------------------------------
# Fingerprints for takeover detection
# Each entry: (service_name, cname_patterns, http_fingerprints, takeover_severity)
# ---------------------------------------------------------------------------

TAKEOVER_FINGERPRINTS = [
    # AWS S3
    {
        "service": "AWS S3",
        "cname_patterns": [r"\.s3\.amazonaws\.com$", r"\.s3-.*\.amazonaws\.com$"],
        "http_patterns": [
            r"NoSuchBucket",
            r"The specified bucket does not exist",
        ],
        "severity": "high",
        "references": ["https://github.com/EdOverflow/can-i-take-over-xyz"],
    },

    # AWS Elastic Beanstalk
    {
        "service": "AWS Elastic Beanstalk",
        "cname_patterns": [r"\.elasticbeanstalk\.com$"],
        "http_patterns": [r"404 Not Found.*nginx"],
        "severity": "high",
    },

    # AWS CloudFront
    {
        "service": "AWS CloudFront",
        "cname_patterns": [r"\.cloudfront\.net$"],
        "http_patterns": [
            r"Bad Request.*CloudFront",
            r"The request could not be satisfied",
        ],
        "severity": "medium",  # Harder to takeover
    },

    # Azure
    {
        "service": "Azure",
        "cname_patterns": [
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.cloudapp\.net$",
            r"\.azure-api\.net$",
            r"\.azureedge\.net$",
            r"\.blob\.core\.windows\.net$",
            r"\.trafficmanager\.net$",
        ],
        "http_patterns": [
            r"404 Web Site not found",
            r"The resource you are looking for has been removed",
        ],
        "severity": "high",
    },

    # GitHub Pages
    {
        "service": "GitHub Pages",
        "cname_patterns": [r"\.github\.io$", r"\.githubusercontent\.com$"],
        "http_patterns": [
            r"There isn't a GitHub Pages site here",
            r"For root URLs \(like http://example\.com/\)",
        ],
        "severity": "high",
    },

    # Heroku
    {
        "service": "Heroku",
        "cname_patterns": [r"\.herokuapp\.com$", r"\.herokudns\.com$"],
        "http_patterns": [
            r"No such app",
            r"There is no app configured at that hostname",
        ],
        "severity": "high",
    },

    # Shopify
    {
        "service": "Shopify",
        "cname_patterns": [r"\.myshopify\.com$"],
        "http_patterns": [
            r"Sorry, this shop is currently unavailable",
            r"Only one step left!",
        ],
        "severity": "high",
    },

    # Tumblr
    {
        "service": "Tumblr",
        "cname_patterns": [r"\.tumblr\.com$"],
        "http_patterns": [
            r"There's nothing here",
            r"Whatever you were looking for doesn't currently exist",
        ],
        "severity": "high",
    },

    # WordPress.com
    {
        "service": "WordPress.com",
        "cname_patterns": [r"\.wordpress\.com$"],
        "http_patterns": [
            r"Do you want to register",
        ],
        "severity": "medium",
    },

    # Zendesk
    {
        "service": "Zendesk",
        "cname_patterns": [r"\.zendesk\.com$"],
        "http_patterns": [
            r"Help Center Closed",
            r"This help center is closed",
        ],
        "severity": "medium",
    },

    # Fastly
    {
        "service": "Fastly",
        "cname_patterns": [r"\.fastly\.net$", r"\.global\.fastly\.net$"],
        "http_patterns": [
            r"Fastly error: unknown domain",
        ],
        "severity": "high",
    },

    # Pantheon
    {
        "service": "Pantheon",
        "cname_patterns": [r"\.pantheonsite\.io$"],
        "http_patterns": [
            r"404 error unknown site",
            r"The gods are wise",
        ],
        "severity": "high",
    },

    # Cargo
    {
        "service": "Cargo",
        "cname_patterns": [r"\.cargocollective\.com$"],
        "http_patterns": [
            r"404 Not Found",
        ],
        "severity": "medium",
    },

    # Ghost
    {
        "service": "Ghost",
        "cname_patterns": [r"\.ghost\.io$"],
        "http_patterns": [
            r"The thing you were looking for is no longer here",
        ],
        "severity": "medium",
    },

    # Surge.sh
    {
        "service": "Surge.sh",
        "cname_patterns": [r"\.surge\.sh$"],
        "http_patterns": [
            r"project not found",
        ],
        "severity": "high",
    },

    # Netlify
    {
        "service": "Netlify",
        "cname_patterns": [r"\.netlify\.app$", r"\.netlify\.com$"],
        "http_patterns": [
            r"Not Found - Request ID:",
        ],
        "severity": "high",
    },

    # Vercel
    {
        "service": "Vercel",
        "cname_patterns": [r"\.vercel\.app$", r"\.now\.sh$"],
        "http_patterns": [
            r"The deployment could not be found",
        ],
        "severity": "high",
    },

    # Fly.io
    {
        "service": "Fly.io",
        "cname_patterns": [r"\.fly\.dev$"],
        "http_patterns": [
            r"404 Not Found",
        ],
        "severity": "medium",
    },

    # Bitbucket
    {
        "service": "Bitbucket",
        "cname_patterns": [r"\.bitbucket\.io$"],
        "http_patterns": [
            r"Repository not found",
        ],
        "severity": "high",
    },

    # Unbounce
    {
        "service": "Unbounce",
        "cname_patterns": [r"\.unbouncepages\.com$"],
        "http_patterns": [
            r"The requested URL was not found on this server",
        ],
        "severity": "medium",
    },
]


@ModuleRegistry.register
class SubdomainTakeoverModule(BaseModule):
    """Detects potential subdomain takeover vulnerabilities."""

    name = "subdomain_takeover"
    description = "Detects dangling DNS records and takeover opportunities"
    risk_level = "low"
    requires_authorization = False  # Passive DNS + HTTP checks

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.http = SecurityHTTPClient(
            timeout=self.timeout,
            rate_limit=self.rate_limit,
            user_agent=self.user_agent,
        )
        self.check_http = True
        self.concurrent_requests = kwargs.get("max_concurrent", 10)

    def run(self, target: dict) -> list[Finding]:
        """
        Check for subdomain takeover vulnerabilities.

        Args:
            target: Dict with 'host' (subdomain to check) and optionally 'subdomains' list
        """
        self.findings = []

        # Can check a single host or multiple subdomains
        hosts_to_check = []

        if "subdomains" in target:
            hosts_to_check.extend(target["subdomains"])
        elif "host" in target:
            hosts_to_check.append(target["host"])

        if not hosts_to_check:
            return self.findings

        self.logger.info("Checking %d hosts for subdomain takeover", len(hosts_to_check))

        # Check each host
        with ThreadPoolExecutor(max_workers=self.concurrent_requests) as executor:
            futures = {
                executor.submit(self._check_host, host): host
                for host in hosts_to_check
            }

            for future in as_completed(futures):
                host = futures[future]
                try:
                    finding = future.result()
                    if finding:
                        self.add_finding(finding)
                except Exception as e:
                    self.logger.debug("Error checking %s: %s", host, e)

        return self.findings

    def _check_host(self, host: str) -> Optional[Finding]:
        """Check a single host for takeover vulnerability."""

        # Step 1: Get CNAME records
        cname_target = self._get_cname(host)

        if not cname_target:
            # No CNAME, check for NXDOMAIN as potential dangling
            if self._is_nxdomain(host):
                return self._create_nxdomain_finding(host)
            return None

        # Step 2: Match CNAME against known vulnerable services
        service_match = self._match_service(cname_target)

        if not service_match:
            return None

        service_name = service_match["service"]
        self.logger.debug("Host %s has CNAME to %s (%s)", host, cname_target, service_name)

        # Step 3: Check if the CNAME target responds with takeover fingerprint
        if self.check_http:
            is_vulnerable, evidence = self._check_http_fingerprint(host, service_match)

            if is_vulnerable:
                return Finding(
                    finding_id=self.generate_finding_id("takeover", host, service_name),
                    finding_type=FindingType.SUBDOMAIN_TAKEOVER.value,
                    module=self.name,
                    severity=service_match.get("severity", "high"),
                    confidence=FindingConfidence.HIGH.value,
                    host=host,
                    title=f"Subdomain takeover possible via {service_name}",
                    description=f"The subdomain {host} has a CNAME pointing to {cname_target} "
                               f"({service_name}) which appears to be unclaimed. "
                               "An attacker could register this service and serve malicious content.",
                    evidence={
                        "cname_target": cname_target,
                        "service": service_name,
                        "http_fingerprint": evidence,
                    },
                    remediation=f"Remove the DNS CNAME record for {host} or reclaim the {service_name} resource.",
                    references=service_match.get("references", []),
                    cwe_ids=["CWE-284"],
                )

        # CNAME exists but HTTP check not confirming - lower confidence
        return Finding(
            finding_id=self.generate_finding_id("dangling_cname", host, service_name),
            finding_type=FindingType.DANGLING_CNAME.value,
            module=self.name,
            severity=FindingSeverity.MEDIUM.value,
            confidence=FindingConfidence.MEDIUM.value,
            host=host,
            title=f"Dangling CNAME to {service_name}",
            description=f"The subdomain {host} has a CNAME pointing to {cname_target} ({service_name}). "
                       "This may indicate a potential takeover if the target is unclaimed.",
            evidence={
                "cname_target": cname_target,
                "service": service_name,
            },
            remediation="Verify the target resource is properly configured or remove the CNAME.",
            cwe_ids=["CWE-284"],
        )

    def _get_cname(self, host: str) -> Optional[str]:
        """Get CNAME record for a host."""
        try:
            import dns.resolver
            answers = dns.resolver.resolve(host, "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip(".")
        except ImportError:
            # Fallback without dnspython
            return self._get_cname_socket(host)
        except Exception:
            return None

    def _get_cname_socket(self, host: str) -> Optional[str]:
        """Fallback CNAME detection using socket."""
        try:
            # This doesn't directly get CNAME but can help detect resolution
            socket.getaddrinfo(host, None)
            return None  # Resolved successfully, likely not dangling
        except socket.gaierror:
            return None

    def _is_nxdomain(self, host: str) -> bool:
        """Check if host returns NXDOMAIN."""
        try:
            socket.getaddrinfo(host, None)
            return False
        except socket.gaierror as e:
            # NXDOMAIN typically returns specific error codes
            return "Name or service not known" in str(e) or "getaddrinfo failed" in str(e)

    def _match_service(self, cname_target: str) -> Optional[dict]:
        """Match CNAME target against known vulnerable services."""
        cname_lower = cname_target.lower()

        for fingerprint in TAKEOVER_FINGERPRINTS:
            for pattern in fingerprint["cname_patterns"]:
                if re.search(pattern, cname_lower, re.IGNORECASE):
                    return fingerprint

        return None

    def _check_http_fingerprint(
        self,
        host: str,
        service_match: dict
    ) -> Tuple[bool, Optional[str]]:
        """Check HTTP response for takeover fingerprint."""

        # Try both HTTP and HTTPS
        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}"

            result = self.http.get(url)

            if not result.success or not result.response:
                continue

            body = result.response.body_preview

            for pattern in service_match.get("http_patterns", []):
                if re.search(pattern, body, re.IGNORECASE):
                    return True, pattern

        return False, None

    def _create_nxdomain_finding(self, host: str) -> Optional[Finding]:
        """Create finding for NXDOMAIN subdomain."""
        # NXDOMAIN alone is not always interesting
        # Only report if there's evidence this was previously used
        return None
