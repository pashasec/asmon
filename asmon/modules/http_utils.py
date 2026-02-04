"""
asmon/modules/http_utils.py — HTTP utilities for security modules.

Provides standardized HTTP client with:
  - Rate limiting
  - Timeout enforcement
  - Evidence collection
  - Safe request handling
"""

import logging
import time
import re
from typing import Optional, Any
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from asmon.modules.base import RequestContext, ResponseContext, ProbeResult

logger = logging.getLogger("asmon.modules.http")

# Max response body to capture for evidence
MAX_BODY_PREVIEW = 2048


class SecurityHTTPClient:
    """
    HTTP client for security testing with built-in safety controls.
    """

    def __init__(
        self,
        timeout: int = 10,
        rate_limit: float = 10.0,
        user_agent: str = "ASMON-SecurityScanner/1.0",
        follow_redirects: bool = True,
        max_redirects: int = 5,
        verify_ssl: bool = False,
    ):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.verify_ssl = verify_ssl

        self._last_request = 0.0
        self._session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create configured session."""
        session = requests.Session()
        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        })

        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _rate_limit_wait(self):
        """Wait to respect rate limit."""
        if self.rate_limit <= 0:
            return
        min_interval = 1.0 / self.rate_limit
        elapsed = time.time() - self._last_request
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request = time.time()

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        data: Optional[Any] = None,
        json: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ) -> ProbeResult:
        """
        Make an HTTP request with evidence collection.

        Returns ProbeResult with request/response context for evidence.
        """
        self._rate_limit_wait()

        req_headers = dict(self._session.headers)
        if headers:
            req_headers.update(headers)

        req_context = RequestContext(
            method=method.upper(),
            url=url,
            headers=req_headers,
            body=str(data) if data else (str(json) if json else None),
        )

        try:
            start_time = time.time()
            resp = self._session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json,
                cookies=cookies,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                verify=self.verify_ssl,
            )
            response_time = time.time() - start_time

            # Capture response for evidence (limited body)
            body_preview = ""
            try:
                body_preview = resp.text[:MAX_BODY_PREVIEW]
            except Exception:
                pass

            resp_context = ResponseContext(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body_preview=body_preview,
                body_length=len(resp.content),
                response_time=response_time,
            )

            return ProbeResult(
                success=True,
                request=req_context,
                response=resp_context,
            )

        except requests.exceptions.Timeout:
            return ProbeResult(success=False, request=req_context, error="timeout")
        except requests.exceptions.ConnectionError as e:
            return ProbeResult(success=False, request=req_context, error=f"connection_error: {e}")
        except Exception as e:
            return ProbeResult(success=False, request=req_context, error=str(e))

    def get(self, url: str, **kwargs) -> ProbeResult:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> ProbeResult:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> ProbeResult:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> ProbeResult:
        return self.request("OPTIONS", url, **kwargs)


# ---------------------------------------------------------------------------
# URL manipulation utilities
# ---------------------------------------------------------------------------

def inject_payload(url: str, param: str, payload: str) -> str:
    """Inject payload into a URL parameter."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if param in params:
        params[param] = [payload]
    else:
        params[param] = [payload]

    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def get_params_from_url(url: str) -> dict[str, list[str]]:
    """Extract parameters from URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def build_url(base: str, path: str) -> str:
    """Safely join base URL and path."""
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


# ---------------------------------------------------------------------------
# Pattern matching utilities
# ---------------------------------------------------------------------------

def search_patterns(text: str, patterns: list[str], case_insensitive: bool = True) -> list[str]:
    """Search for multiple regex patterns in text."""
    matches = []
    flags = re.IGNORECASE if case_insensitive else 0

    for pattern in patterns:
        try:
            if re.search(pattern, text, flags):
                matches.append(pattern)
        except re.error:
            continue

    return matches


def contains_any(text: str, substrings: list[str], case_insensitive: bool = True) -> Optional[str]:
    """Check if text contains any of the substrings."""
    if case_insensitive:
        text = text.lower()
        substrings = [s.lower() for s in substrings]

    for sub in substrings:
        if sub in text:
            return sub
    return None


# ---------------------------------------------------------------------------
# Response analysis utilities
# ---------------------------------------------------------------------------

def is_error_page(body: str, status_code: int) -> bool:
    """Detect if response is an error page."""
    error_indicators = [
        "404 not found",
        "403 forbidden",
        "500 internal server error",
        "page not found",
        "access denied",
        "error occurred",
    ]
    return status_code >= 400 or contains_any(body, error_indicators) is not None


def extract_server_info(headers: dict) -> dict:
    """Extract server information from headers."""
    info = {}

    server = headers.get("Server", headers.get("server", ""))
    if server:
        info["server"] = server

    powered_by = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
    if powered_by:
        info["powered_by"] = powered_by

    asp_version = headers.get("X-AspNet-Version", headers.get("x-aspnet-version", ""))
    if asp_version:
        info["asp_version"] = asp_version

    return info


def get_content_type(headers: dict) -> str:
    """Get content type from headers."""
    ct = headers.get("Content-Type", headers.get("content-type", ""))
    return ct.split(";")[0].strip().lower()
