"""
asmon/modules — Optional active security analysis modules.

IMPORTANT: All modules in this package are DISABLED by default.
They must be explicitly enabled via CLI flags (--enable-module).

These modules perform active security testing and should ONLY be used
on systems you own or have explicit written authorization to test.

Available modules:
  - ssl_analysis: Weak SSL/TLS configuration detection
  - endpoint_discovery: Admin panels, sensitive files, backup discovery
  - subdomain_takeover: Dangling DNS and takeover detection
  - sqli_detection: SQL injection signal detection
  - xss_detection: Cross-site scripting reflection detection
  - lfi_detection: Local file inclusion / path traversal
  - rce_detection: Remote code execution indicators
  - oob_detection: Out-of-band vulnerability detection
  - misconfig: Security misconfiguration checks
"""

from asmon.modules.base import (
    BaseModule,
    ModuleRegistry,
    Finding,
    FindingSeverity,
    FindingConfidence,
)
from asmon.modules.orchestrator import ModuleOrchestrator

__all__ = [
    "BaseModule",
    "ModuleRegistry",
    "Finding",
    "FindingSeverity",
    "FindingConfidence",
    "ModuleOrchestrator",
]
