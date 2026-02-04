"""
asmon/modules/crawler.py — Web crawler for parameter discovery.

Discovers injectable targets by:
  - Crawling pages to find URLs with query parameters
  - Extracting forms and their input fields
  - Probing common parameter names on discovered endpoints
  - Building a list of testable URLs for injection modules
"""

import logging
import re
from typing import Optional, Set, List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from html.parser import HTMLParser

from asmon.modules.http_utils import SecurityHTTPClient

logger = logging.getLogger("asmon.modules.crawler")


# Common parameter names to probe
COMMON_PARAMS = [
    "id", "page", "p", "q", "search", "query", "keyword", "s",
    "cat", "category", "item", "product", "pid", "uid", "user",
    "file", "path", "dir", "document", "doc", "url", "link", "src",
    "redirect", "return", "next", "goto", "target", "rurl", "dest",
    "action", "cmd", "exec", "command", "do", "func", "function",
    "name", "username", "email", "login", "pass", "password",
    "sort", "order", "orderby", "sortby", "filter", "type",
    "lang", "language", "locale", "debug", "test", "mode",
    "callback", "jsonp", "format", "output", "template", "view",
]


@dataclass
class CrawlResult:
    """Result of crawling a target."""
    base_url: str
    urls_with_params: Set[str] = field(default_factory=set)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    discovered_endpoints: Set[str] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)


class LinkExtractor(HTMLParser):
    """Extract links and forms from HTML."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.forms: List[Dict[str, Any]] = list()
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: list):
        attrs_dict = dict(attrs)

        # Extract links from <a href="...">
        if tag == "a" and "href" in attrs_dict:
            href = attrs_dict["href"]
            full_url = urljoin(self.base_url, href)
            if self._is_same_domain(full_url):
                self.links.add(full_url)

        # Extract form action
        elif tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attrs_dict.get("action", "")),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
            }

        # Extract form inputs
        elif tag == "input" and self._current_form is not None:
            input_type = attrs_dict.get("type", "text").lower()
            input_name = attrs_dict.get("name", "")
            input_value = attrs_dict.get("value", "")

            if input_name and input_type not in ("submit", "button", "image", "reset"):
                self._current_form["inputs"].append({
                    "name": input_name,
                    "type": input_type,
                    "value": input_value,
                })

        # Extract textarea
        elif tag == "textarea" and self._current_form is not None:
            name = attrs_dict.get("name", "")
            if name:
                self._current_form["inputs"].append({
                    "name": name,
                    "type": "textarea",
                    "value": "",
                })

        # Extract select
        elif tag == "select" and self._current_form is not None:
            name = attrs_dict.get("name", "")
            if name:
                self._current_form["inputs"].append({
                    "name": name,
                    "type": "select",
                    "value": "",
                })

        # Also check for URLs in src attributes
        if "src" in attrs_dict:
            src = attrs_dict["src"]
            if "?" in src:
                full_url = urljoin(self.base_url, src)
                if self._is_same_domain(full_url):
                    self.links.add(full_url)

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            if self._current_form["inputs"]:  # Only save forms with inputs
                self.forms.append(self._current_form)
            self._current_form = None

    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is on the same domain."""
        base_domain = urlparse(self.base_url).netloc
        url_domain = urlparse(url).netloc
        return url_domain == base_domain or url_domain == ""


class WebCrawler:
    """
    Crawls a website to discover URLs with parameters and forms.

    Usage:
        crawler = WebCrawler(max_pages=50, max_depth=3)
        result = crawler.crawl("https://example.com")
        # result.urls_with_params contains testable URLs
    """

    def __init__(
        self,
        max_pages: int = 50,
        max_depth: int = 3,
        timeout: int = 10,
        rate_limit: float = 10.0,
        user_agent: str = "ASMON-Crawler/1.0",
        follow_redirects: bool = True,
        probe_params: bool = True,
    ):
        """
        Initialize crawler.

        Args:
            max_pages: Maximum pages to crawl
            max_depth: Maximum link depth from start
            timeout: Request timeout
            rate_limit: Requests per second
            user_agent: User-Agent header
            follow_redirects: Follow HTTP redirects
            probe_params: Probe common parameter names on endpoints
        """
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.user_agent = user_agent
        self.follow_redirects = follow_redirects
        self.probe_params = probe_params

        self.http = SecurityHTTPClient(
            timeout=timeout,
            rate_limit=rate_limit,
            user_agent=user_agent,
            follow_redirects=follow_redirects,
        )

        self._visited: Set[str] = set()
        self._urls_with_params: Set[str] = set()
        self._forms: List[Dict[str, Any]] = []
        self._endpoints: Set[str] = set()

    def crawl(self, start_url: str) -> CrawlResult:
        """
        Crawl starting from a URL.

        Args:
            start_url: URL to start crawling from

        Returns:
            CrawlResult with discovered URLs, forms, and endpoints
        """
        result = CrawlResult(base_url=start_url)

        # Normalize start URL
        parsed = urlparse(start_url)
        if not parsed.scheme:
            start_url = f"https://{start_url}"

        self._visited.clear()
        self._urls_with_params.clear()
        self._forms.clear()
        self._endpoints.clear()

        logger.info("Starting crawl from %s (max_pages=%d, max_depth=%d)",
                   start_url, self.max_pages, self.max_depth)

        # BFS crawl
        queue = [(start_url, 0)]  # (url, depth)

        while queue and len(self._visited) < self.max_pages:
            url, depth = queue.pop(0)

            # Normalize and check if visited
            normalized = self._normalize_url(url)
            if normalized in self._visited:
                continue

            self._visited.add(normalized)

            # Skip non-HTTP URLs
            if not url.startswith(("http://", "https://")):
                continue

            # Crawl page
            try:
                new_urls = self._crawl_page(url, start_url)

                # Add new URLs to queue if within depth
                if depth < self.max_depth:
                    for new_url in new_urls:
                        if self._normalize_url(new_url) not in self._visited:
                            queue.append((new_url, depth + 1))

            except Exception as e:
                result.errors.append(f"Error crawling {url}: {e}")
                logger.debug("Crawl error for %s: %s", url, e)

        # Probe common parameters on discovered endpoints
        if self.probe_params:
            self._probe_endpoints(start_url)

        result.urls_with_params = self._urls_with_params.copy()
        result.forms = self._forms.copy()
        result.discovered_endpoints = self._endpoints.copy()

        logger.info("Crawl complete: %d pages, %d URLs with params, %d forms",
                   len(self._visited), len(result.urls_with_params), len(result.forms))

        return result

    def _crawl_page(self, url: str, base_url: str) -> Set[str]:
        """Crawl a single page and extract links/forms."""
        new_urls: Set[str] = set()

        # Check if URL has parameters
        if "?" in url:
            self._urls_with_params.add(url)

        # Track endpoint (path without query)
        parsed = urlparse(url)
        endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self._endpoints.add(endpoint)

        # Fetch page
        result = self.http.get(url)

        if not result.success or not result.response:
            return new_urls

        # Only parse HTML
        content_type = result.response.headers.get("Content-Type", "")
        if "text/html" not in content_type.lower():
            return new_urls

        body = result.response.body_preview

        # Extract links and forms
        try:
            extractor = LinkExtractor(url)
            extractor.feed(body)

            new_urls = extractor.links

            # Store forms
            for form in extractor.forms:
                form["source_url"] = url
                self._forms.append(form)

            # Check extracted URLs for parameters
            for link in new_urls:
                if "?" in link:
                    self._urls_with_params.add(link)

        except Exception as e:
            logger.debug("HTML parse error for %s: %s", url, e)

        # Also extract URLs from JavaScript (simple regex)
        js_urls = self._extract_js_urls(body, url)
        new_urls.update(js_urls)

        return new_urls

    def _extract_js_urls(self, body: str, base_url: str) -> Set[str]:
        """Extract URLs from JavaScript code."""
        urls: Set[str] = set()

        # Match common URL patterns in JS
        patterns = [
            r'["\']([^"\']*\?[^"\']+)["\']',  # URLs with query strings
            r'href\s*[=:]\s*["\']([^"\']+)["\']',
            r'url\s*[=:]\s*["\']([^"\']+)["\']',
            r'src\s*[=:]\s*["\']([^"\']+)["\']',
            r'action\s*[=:]\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                if match.startswith(("/", "http://", "https://")):
                    full_url = urljoin(base_url, match)
                    if self._is_same_domain(full_url, base_url):
                        urls.add(full_url)
                        if "?" in full_url:
                            self._urls_with_params.add(full_url)

        return urls

    def _probe_endpoints(self, base_url: str):
        """Probe discovered endpoints with common parameter names."""
        logger.info("Probing %d endpoints for parameters", len(self._endpoints))

        for endpoint in list(self._endpoints)[:20]:  # Limit probing
            for param in COMMON_PARAMS[:15]:  # Limit params per endpoint
                test_url = f"{endpoint}?{param}=1"

                result = self.http.get(test_url)

                if result.success and result.response:
                    # Check if parameter is reflected or affects response
                    if result.response.status_code == 200:
                        body = result.response.body_preview

                        # Check for reflection or interesting behavior
                        if "1" in body or param in body:
                            self._urls_with_params.add(test_url)
                            logger.debug("Found working param: %s?%s=", endpoint, param)
                            break  # Found one, move to next endpoint

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication."""
        parsed = urlparse(url)
        # Remove fragment, normalize path
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc.lower(),
            parsed.path.rstrip("/") or "/",
            "",
            parsed.query,
            ""
        ))
        return normalized

    def _is_same_domain(self, url: str, base_url: str) -> bool:
        """Check if URL is on same domain as base."""
        base_domain = urlparse(base_url).netloc
        url_domain = urlparse(url).netloc
        return url_domain == base_domain


def form_to_url(form: Dict[str, Any]) -> str:
    """Convert a form to a testable URL with parameters."""
    action = form.get("action", "")
    inputs = form.get("inputs", [])

    if not inputs:
        return ""

    # Build query string from inputs
    params = {}
    for inp in inputs:
        name = inp.get("name", "")
        value = inp.get("value", "") or "test"
        if name:
            params[name] = value

    if not params:
        return ""

    # For GET forms, append to URL
    if form.get("method", "GET").upper() == "GET":
        if "?" in action:
            return f"{action}&{urlencode(params)}"
        else:
            return f"{action}?{urlencode(params)}"

    # For POST forms, still return URL with params for testing
    # (modules can use POST method if needed)
    if "?" in action:
        return f"{action}&{urlencode(params)}"
    else:
        return f"{action}?{urlencode(params)}"


def discover_injectable_urls(
    base_url: str,
    max_pages: int = 50,
    max_depth: int = 3,
    timeout: int = 10,
    rate_limit: float = 10.0,
) -> List[str]:
    """
    Convenience function to discover URLs suitable for injection testing.

    Args:
        base_url: Starting URL
        max_pages: Max pages to crawl
        max_depth: Max crawl depth
        timeout: Request timeout
        rate_limit: Requests per second

    Returns:
        List of URLs with parameters, ready for testing
    """
    crawler = WebCrawler(
        max_pages=max_pages,
        max_depth=max_depth,
        timeout=timeout,
        rate_limit=rate_limit,
    )

    result = crawler.crawl(base_url)

    # Combine URLs from crawling and forms
    urls = list(result.urls_with_params)

    for form in result.forms:
        form_url = form_to_url(form)
        if form_url and form_url not in urls:
            urls.append(form_url)

    return urls
