"""
asmon/web/analyzer.py — Web risk signal analyzer.

Orchestrates passive HTTP observation to detect web exposure signals.
Uses only HEAD/GET requests — no payloads, no fuzzing, no exploitation.

This is an EASM-class passive detector, NOT a vulnerability scanner.
"""

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from asmon.models import WebRiskSignal, WebRiskReport
from asmon.web.signals import (
    check_missing_headers,
    check_insecure_cookies,
    check_tech_disclosure,
    check_exposed_endpoint,
    check_https_redirect,
    SENSITIVE_ENDPOINTS,
)

logger = logging.getLogger("asmon.web.analyzer")

# Default timeout for HTTP requests (seconds)
DEFAULT_TIMEOUT = 10
# Max endpoints to check to avoid abuse
MAX_ENDPOINT_CHECKS = 25


class WebRiskAnalyzer:
    """
    Passive web risk signal analyzer.

    Performs safe HTTP observation to detect security exposure indicators.
    Does NOT send payloads, perform fuzzing, or attempt exploitation.
    """

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        max_endpoint_checks: int = MAX_ENDPOINT_CHECKS,
        check_endpoints: bool = True,
        user_agent: str = "ASMON-WebRisk/1.0 (Attack Surface Monitor)"
    ):
        """
        Initialize the analyzer.

        Args:
            timeout: HTTP request timeout in seconds
            max_endpoint_checks: Maximum sensitive endpoints to probe
            check_endpoints: Whether to check for exposed endpoints
            user_agent: User-Agent header for requests
        """
        self.timeout = timeout
        self.max_endpoint_checks = max_endpoint_checks
        self.check_endpoints = check_endpoints
        self.user_agent = user_agent

        # Configure session with retries
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": user_agent})

        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def analyze(
        self,
        host: str,
        port: int = 443,
        hostname: Optional[str] = None
    ) -> WebRiskReport:
        """
        Analyze a host for web risk signals.

        Args:
            host: IP address or hostname to analyze
            port: HTTP/HTTPS port (default 443)
            hostname: Optional hostname for SNI (if host is IP)

        Returns:
            WebRiskReport with detected signals
        """
        # Determine if this is likely HTTPS
        is_https_port = port in (443, 8443, 8444, 9443)
        target_host = hostname or host

        # Build base URLs
        https_url = f"https://{target_host}:{port}" if port != 443 else f"https://{target_host}"
        http_url = f"http://{target_host}:{80}" if port in (443, 8443) else f"http://{target_host}:{port}"

        report = WebRiskReport(
            host=host,
            port=port,
            url=https_url if is_https_port else http_url,
            scanned_at=datetime.now(timezone.utc),
        )

        signals: list[WebRiskSignal] = []
        technologies: list[str] = []

        # --- Check HTTPS accessibility ---
        https_response = None
        if is_https_port:
            https_response = self._safe_request(https_url, method="HEAD")
            report.https_accessible = https_response is not None

        # --- Check HTTP accessibility and redirect ---
        http_response = None
        http_redirects_to_https = False

        # Only check HTTP if we're on a typical HTTPS port
        if is_https_port:
            http_base = f"http://{target_host}"
            http_response = self._safe_request(http_base, method="HEAD", allow_redirects=False)
            report.http_accessible = http_response is not None

            if http_response is not None:
                # Check if it redirects to HTTPS
                if http_response.status_code in (301, 302, 307, 308):
                    location = http_response.headers.get("Location", "")
                    http_redirects_to_https = location.startswith("https://")

        # Use whichever response we got
        primary_response = https_response or http_response

        if primary_response is None:
            logger.warning("Could not connect to %s:%d", host, port)
            return report

        # --- Analyze headers from primary response ---
        headers = dict(primary_response.headers)
        primary_url = str(primary_response.url)
        is_https = primary_url.startswith("https://")

        # Extract server info
        if "Server" in headers:
            report.server_header = headers["Server"]
            technologies.append(headers["Server"])
        if "X-Powered-By" in headers:
            technologies.append(headers["X-Powered-By"])

        # Check for missing security headers
        signals.extend(check_missing_headers(headers, primary_url))

        # Check for technology disclosure
        signals.extend(check_tech_disclosure(headers, primary_url))

        # Check for insecure cookies
        set_cookie_headers = primary_response.headers.get_list("Set-Cookie") if hasattr(
            primary_response.headers, 'get_list'
        ) else [v for k, v in primary_response.headers.items() if k.lower() == "set-cookie"]

        if set_cookie_headers:
            signals.extend(check_insecure_cookies(set_cookie_headers, primary_url, is_https))

        # Check HTTPS redirect behavior
        if is_https_port:
            redirect_signal = check_https_redirect(
                report.http_accessible,
                report.https_accessible,
                http_redirects_to_https,
                primary_url
            )
            if redirect_signal:
                signals.append(redirect_signal)

        # --- Check sensitive endpoints ---
        if self.check_endpoints:
            base_url = f"https://{target_host}" if report.https_accessible else f"http://{target_host}"
            endpoint_signals = self._check_sensitive_endpoints(base_url)
            signals.extend(endpoint_signals)

        report.signals = signals
        report.technologies = list(set(technologies))

        logger.info(
            "Web risk scan complete for %s:%d — %d signals detected",
            host, port, len(signals)
        )

        return report

    def _safe_request(
        self,
        url: str,
        method: str = "HEAD",
        allow_redirects: bool = True
    ) -> Optional[requests.Response]:
        """
        Make a safe HTTP request with error handling.

        Args:
            url: URL to request
            method: HTTP method (HEAD or GET)
            allow_redirects: Whether to follow redirects

        Returns:
            Response object or None on failure
        """
        try:
            if method == "HEAD":
                resp = self._session.head(
                    url,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False  # Accept self-signed certs for scanning
                )
            else:
                resp = self._session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    verify=False
                )
            return resp
        except requests.exceptions.SSLError as e:
            logger.debug("SSL error for %s: %s", url, e)
            return None
        except requests.exceptions.ConnectionError as e:
            logger.debug("Connection error for %s: %s", url, e)
            return None
        except requests.exceptions.Timeout:
            logger.debug("Timeout for %s", url)
            return None
        except Exception as e:
            logger.debug("Request failed for %s: %s", url, e)
            return None

    def _check_sensitive_endpoints(self, base_url: str) -> list[WebRiskSignal]:
        """
        Check for exposed sensitive endpoints.

        Args:
            base_url: Base URL (e.g., https://example.com)

        Returns:
            List of signals for exposed endpoints
        """
        signals = []

        for endpoint, title in SENSITIVE_ENDPOINTS[:self.max_endpoint_checks]:
            url = f"{base_url}{endpoint}"

            try:
                # Use HEAD first for efficiency, fall back to GET for some endpoints
                resp = self._safe_request(url, method="HEAD", allow_redirects=False)

                if resp is None:
                    continue

                signal = check_exposed_endpoint(endpoint, resp.status_code, title, base_url)
                if signal:
                    signals.append(signal)

            except Exception as e:
                logger.debug("Error checking endpoint %s: %s", endpoint, e)
                continue

        return signals


def analyze_host(
    host: str,
    port: int = 443,
    hostname: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    check_endpoints: bool = True,
) -> WebRiskReport:
    """
    Convenience function to analyze a single host.

    Args:
        host: IP address or hostname
        port: HTTP/HTTPS port
        hostname: Optional hostname for SNI
        timeout: Request timeout
        check_endpoints: Whether to check sensitive endpoints

    Returns:
        WebRiskReport with detected signals
    """
    analyzer = WebRiskAnalyzer(timeout=timeout, check_endpoints=check_endpoints)
    return analyzer.analyze(host, port, hostname)


def merge_web_risk_results(host_record, web_reports: list[WebRiskReport]) -> None:
    """
    Merge web risk reports into a host record.

    Args:
        host_record: HostRecord to update
        web_reports: List of WebRiskReport objects to merge
    """
    host_record.web_risks = web_reports
    host_record.web_risk_scanned = True
