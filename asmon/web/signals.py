"""
asmon/web/signals.py — Web risk signal detection functions.

Each function checks for a specific type of web exposure signal.
All checks use only HEAD/GET requests — no payloads, no fuzzing.

Signal severity levels:
  - high: Significant security concern requiring attention
  - medium: Moderate concern, should be reviewed
  - low: Minor issue, best practice recommendation
  - info: Informational finding, no immediate risk
"""

import logging
from typing import Optional
from http.cookies import SimpleCookie

from asmon.models import WebRiskSignal

logger = logging.getLogger("asmon.web.signals")


# ---------------------------------------------------------------------------
# Security header constants
# ---------------------------------------------------------------------------

# Headers we check for and their importance
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "title": "Missing HSTS Header",
        "recommendation": "Add Strict-Transport-Security header with appropriate max-age.",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "title": "Missing CSP Header",
        "recommendation": "Implement Content-Security-Policy to prevent XSS and injection attacks.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "title": "Missing X-Frame-Options",
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "title": "Missing X-Content-Type-Options",
        "recommendation": "Add X-Content-Type-Options: nosniff to prevent MIME sniffing.",
    },
    "X-XSS-Protection": {
        "severity": "info",
        "title": "Missing X-XSS-Protection",
        "recommendation": "Consider adding X-XSS-Protection header (though CSP is preferred).",
    },
    "Referrer-Policy": {
        "severity": "low",
        "title": "Missing Referrer-Policy",
        "recommendation": "Add Referrer-Policy to control referrer information leakage.",
    },
    "Permissions-Policy": {
        "severity": "info",
        "title": "Missing Permissions-Policy",
        "recommendation": "Add Permissions-Policy to control browser feature access.",
    },
}

# Headers that disclose technology (should not be present)
DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Drupal-Dynamic-Cache",
]

# Sensitive endpoints to check (only GET/HEAD, no auth bypass attempts)
SENSITIVE_ENDPOINTS = [
    # Admin panels
    ("/admin", "Admin panel"),
    ("/administrator", "Administrator panel"),
    ("/wp-admin", "WordPress admin"),
    ("/admin.php", "Admin PHP script"),
    ("/manager", "Manager interface"),
    ("/phpmyadmin", "phpMyAdmin"),
    ("/adminer", "Adminer database tool"),
    # Login / Auth
    ("/login", "Login page"),
    ("/signin", "Sign-in page"),
    ("/auth", "Authentication endpoint"),
    # Debug / Test
    ("/debug", "Debug endpoint"),
    ("/test", "Test endpoint"),
    ("/phpinfo.php", "PHP info page"),
    ("/info.php", "Info page"),
    ("/server-status", "Server status"),
    ("/server-info", "Server info"),
    ("/.git/HEAD", "Git repository exposed"),
    ("/.env", "Environment file exposed"),
    ("/.htaccess", "Apache config exposed"),
    ("/web.config", "IIS config exposed"),
    # API docs
    ("/swagger", "Swagger API docs"),
    ("/api-docs", "API documentation"),
    ("/graphql", "GraphQL endpoint"),
    ("/graphiql", "GraphiQL interface"),
    # Backup / Config
    ("/backup", "Backup directory"),
    ("/config", "Configuration directory"),
    ("/console", "Console interface"),
]


# ---------------------------------------------------------------------------
# Signal detection functions
# ---------------------------------------------------------------------------

def check_missing_headers(headers: dict[str, str], url: str) -> list[WebRiskSignal]:
    """
    Check for missing security headers.

    Args:
        headers: Response headers (case-insensitive keys)
        url: The URL that was checked

    Returns:
        List of WebRiskSignal for each missing header
    """
    signals = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, info in SECURITY_HEADERS.items():
        if header.lower() not in headers_lower:
            signals.append(WebRiskSignal(
                signal_type="missing_header",
                severity=info["severity"],
                title=info["title"],
                detail=f"The {header} header is not set on {url}",
                endpoint=url,
                recommendation=info["recommendation"],
            ))

    return signals


def check_insecure_cookies(
    set_cookie_headers: list[str],
    url: str,
    is_https: bool
) -> list[WebRiskSignal]:
    """
    Check for insecure cookie attributes.

    Args:
        set_cookie_headers: List of Set-Cookie header values
        url: The URL that was checked
        is_https: Whether the connection is HTTPS

    Returns:
        List of WebRiskSignal for insecure cookies
    """
    signals = []

    for cookie_str in set_cookie_headers:
        # Parse the cookie
        try:
            cookie = SimpleCookie()
            cookie.load(cookie_str)
        except Exception:
            continue

        for name, morsel in cookie.items():
            cookie_lower = cookie_str.lower()

            # Check for missing Secure flag on HTTPS
            if is_https and "secure" not in cookie_lower:
                signals.append(WebRiskSignal(
                    signal_type="insecure_cookie",
                    severity="medium",
                    title=f"Cookie '{name}' missing Secure flag",
                    detail=f"Cookie '{name}' is set without the Secure flag on HTTPS connection",
                    endpoint=url,
                    recommendation="Add the Secure flag to ensure cookie is only sent over HTTPS.",
                ))

            # Check for missing HttpOnly flag (for session-like cookies)
            session_indicators = ["session", "sess", "auth", "token", "jwt", "sid"]
            is_session_cookie = any(ind in name.lower() for ind in session_indicators)

            if is_session_cookie and "httponly" not in cookie_lower:
                signals.append(WebRiskSignal(
                    signal_type="insecure_cookie",
                    severity="high",
                    title=f"Session cookie '{name}' missing HttpOnly flag",
                    detail=f"Cookie '{name}' appears to be a session cookie but lacks HttpOnly flag",
                    endpoint=url,
                    recommendation="Add HttpOnly flag to prevent JavaScript access to session cookies.",
                ))
            elif "httponly" not in cookie_lower:
                signals.append(WebRiskSignal(
                    signal_type="insecure_cookie",
                    severity="low",
                    title=f"Cookie '{name}' missing HttpOnly flag",
                    detail=f"Cookie '{name}' is set without the HttpOnly flag",
                    endpoint=url,
                    recommendation="Consider adding HttpOnly flag to prevent JavaScript access.",
                ))

            # Check for missing SameSite attribute
            if "samesite" not in cookie_lower:
                signals.append(WebRiskSignal(
                    signal_type="insecure_cookie",
                    severity="low",
                    title=f"Cookie '{name}' missing SameSite attribute",
                    detail=f"Cookie '{name}' does not specify SameSite attribute",
                    endpoint=url,
                    recommendation="Add SameSite=Strict or SameSite=Lax to prevent CSRF.",
                ))

    return signals


def check_tech_disclosure(headers: dict[str, str], url: str) -> list[WebRiskSignal]:
    """
    Check for technology disclosure via headers.

    Args:
        headers: Response headers
        url: The URL that was checked

    Returns:
        List of WebRiskSignal for disclosed technologies
    """
    signals = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header in DISCLOSURE_HEADERS:
        header_lower = header.lower()
        if header_lower in headers_lower:
            value = headers_lower[header_lower]
            # Determine severity based on specificity of disclosure
            severity = "low"
            if any(x in value.lower() for x in ["version", "php/", "apache/", "nginx/", "iis/"]):
                severity = "medium"

            signals.append(WebRiskSignal(
                signal_type="tech_disclosure",
                severity=severity,
                title=f"Technology disclosure: {header}",
                detail=f"{header}: {value}",
                endpoint=url,
                recommendation=f"Remove or obfuscate the {header} header to reduce fingerprinting.",
            ))

    return signals


def check_exposed_endpoint(
    endpoint: str,
    status_code: int,
    title: str,
    base_url: str
) -> Optional[WebRiskSignal]:
    """
    Check if a sensitive endpoint is exposed.

    Args:
        endpoint: The path that was checked
        status_code: HTTP response status code
        title: Description of the endpoint
        base_url: Base URL of the host

    Returns:
        WebRiskSignal if endpoint appears accessible, None otherwise
    """
    # Consider endpoint exposed if we get 200, 301, 302, 401, 403
    # 401/403 means it exists but is protected (still worth noting)
    # 404, 500 means not found or error

    if status_code in (200, 301, 302):
        severity = "high" if any(x in endpoint for x in [".git", ".env", "phpinfo", "debug"]) else "medium"
        return WebRiskSignal(
            signal_type="exposed_endpoint",
            severity=severity,
            title=f"Exposed: {title}",
            detail=f"Endpoint {endpoint} returned HTTP {status_code}",
            endpoint=f"{base_url}{endpoint}",
            recommendation=f"Restrict access to {endpoint} or remove if not needed.",
        )
    elif status_code in (401, 403):
        return WebRiskSignal(
            signal_type="exposed_endpoint",
            severity="info",
            title=f"Protected endpoint exists: {title}",
            detail=f"Endpoint {endpoint} exists but returned HTTP {status_code}",
            endpoint=f"{base_url}{endpoint}",
            recommendation="Ensure proper authentication is enforced.",
        )

    return None


def check_https_redirect(
    http_accessible: bool,
    https_accessible: bool,
    http_redirects_to_https: bool,
    url: str
) -> Optional[WebRiskSignal]:
    """
    Check if HTTP properly redirects to HTTPS.

    Args:
        http_accessible: Whether HTTP port is reachable
        https_accessible: Whether HTTPS port is reachable
        http_redirects_to_https: Whether HTTP redirects to HTTPS
        url: Base URL

    Returns:
        WebRiskSignal if HTTP doesn't redirect to HTTPS
    """
    if http_accessible and https_accessible and not http_redirects_to_https:
        return WebRiskSignal(
            signal_type="no_https_redirect",
            severity="high",
            title="HTTP does not redirect to HTTPS",
            detail="HTTP is accessible but does not redirect to HTTPS",
            endpoint=url,
            recommendation="Configure HTTP to redirect all traffic to HTTPS.",
        )
    elif http_accessible and not https_accessible:
        return WebRiskSignal(
            signal_type="no_https_redirect",
            severity="high",
            title="HTTPS not available",
            detail="Site is only accessible over HTTP (no HTTPS)",
            endpoint=url,
            recommendation="Enable HTTPS with a valid TLS certificate.",
        )

    return None
