"""
active/ — Authorized active scanning module.

IMPORTANT: Only use with explicit written authorization.
Unauthorized scanning may violate laws (CFAA, GDPR, etc.).

This module provides:
- TCP connect port scanning (safe, no SYN floods)
- Service fingerprinting (banner grabbing)
- CVE correlation (metadata only, NO exploits)
"""

__all__ = ["ActiveScanner"]

from asmon.active.scanner import ActiveScanner
