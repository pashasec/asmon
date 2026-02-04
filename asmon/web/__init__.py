"""
asmon/web — Web risk signal detection module.

Passive HTTP observation for security exposure indicators.
Uses only HEAD/GET requests — no payloads, no fuzzing, no exploitation.

This is NOT a vulnerability scanner. It detects risk signals such as:
  - Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Insecure cookies (missing Secure/HttpOnly flags)
  - Technology disclosure (Server, X-Powered-By headers)
  - Exposed sensitive endpoints (admin, login, debug)
  - HTTP without HTTPS redirect
"""

from asmon.web.analyzer import WebRiskAnalyzer, analyze_host

__all__ = ["WebRiskAnalyzer", "analyze_host"]
