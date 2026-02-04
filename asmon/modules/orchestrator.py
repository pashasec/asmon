"""
asmon/modules/orchestrator.py — Module execution orchestrator.

Handles:
  - Module discovery and loading
  - Execution coordination
  - Finding aggregation
  - Safety controls and warnings
"""

import logging
import sys
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from asmon.modules.base import BaseModule, ModuleRegistry, Finding

logger = logging.getLogger("asmon.modules.orchestrator")

# Import modules to register them
from asmon.modules import ssl_analysis
from asmon.modules import endpoint_discovery
from asmon.modules import subdomain_takeover
from asmon.modules import sqli_detection
from asmon.modules import xss_detection
from asmon.modules import lfi_detection
from asmon.modules import rce_detection
from asmon.modules import oob_detection

AUTHORIZATION_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ⚠️  ACTIVE VULNERABILITY SCANNING  ⚠️                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  You are about to perform ACTIVE security testing. This includes:            ║
║    • Sending potentially malicious payloads                                  ║
║    • Testing for SQL injection, XSS, RCE, and other vulnerabilities         ║
║    • Making numerous requests that may trigger security alerts               ║
║                                                                              ║
║  ONLY proceed if you have EXPLICIT WRITTEN AUTHORIZATION to test the target.║
║  Unauthorized testing is ILLEGAL and may result in criminal prosecution.    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


class ModuleOrchestrator:
    """Coordinates execution of security analysis modules."""

    def __init__(
        self,
        rate_limit: int = 10,
        timeout: int = 10,
        max_concurrent: int = 5,
        callback_url: Optional[str] = None,
        show_warning: bool = True,
    ):
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.callback_url = callback_url
        self.show_warning = show_warning
        self.findings: List[Finding] = []
        self._modules_run: List[str] = []

    def list_available_modules(self) -> Dict[str, str]:
        """List all available modules with descriptions."""
        return {
            name: cls.description
            for name, cls in ModuleRegistry.get_all().items()
        }

    def run_modules(
        self,
        target: Dict[str, Any],
        modules: Optional[List[str]] = None,
        skip_warning: bool = False,
    ) -> List[Finding]:
        """
        Run specified modules against target.

        Args:
            target: Dict with host, port, url, subdomains, etc.
            modules: List of module names to run (None = all)
            skip_warning: Skip authorization warning

        Returns:
            List of all findings
        """
        self.findings = []
        self._modules_run = []

        # Show authorization warning
        if self.show_warning and not skip_warning:
            print(AUTHORIZATION_WARNING, file=sys.stderr)
            try:
                response = input("Type 'YES' to confirm you have authorization: ")
                if response.strip() != "YES":
                    logger.warning("User declined authorization confirmation")
                    return []
            except (EOFError, KeyboardInterrupt):
                return []

        # Determine modules to run
        available = ModuleRegistry.get_all()
        if modules:
            to_run = {name: available[name] for name in modules if name in available}
        else:
            to_run = available

        if not to_run:
            logger.warning("No modules to run")
            return []

        logger.info("Running %d modules: %s", len(to_run), list(to_run.keys()))

        # Execute each module
        for name, module_cls in to_run.items():
            try:
                module = module_cls(
                    rate_limit=self.rate_limit,
                    timeout=self.timeout,
                    max_concurrent=self.max_concurrent,
                    callback_url=self.callback_url,
                )

                logger.info("Running module: %s", name)
                findings = module.run(target)
                self.findings.extend(findings)
                self._modules_run.append(name)

                logger.info("Module %s found %d issues", name, len(findings))

            except Exception as e:
                logger.error("Module %s failed: %s", name, e)

        return self.findings

    def run_single_module(
        self,
        module_name: str,
        target: Dict[str, Any],
        skip_warning: bool = False,
    ) -> List[Finding]:
        """Run a single module."""
        return self.run_modules(target, modules=[module_name], skip_warning=skip_warning)

    def get_summary(self) -> Dict[str, Any]:
        """Get execution summary."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            "modules_run": self._modules_run,
            "total_findings": len(self.findings),
            "severity_breakdown": severity_counts,
            "findings_by_type": self._group_by_type(),
        }

    def _group_by_type(self) -> Dict[str, int]:
        """Group findings by type."""
        by_type: Dict[str, int] = {}
        for f in self.findings:
            by_type[f.finding_type] = by_type.get(f.finding_type, 0) + 1
        return by_type


def run_security_scan(
    target: Dict[str, Any],
    modules: Optional[List[str]] = None,
    rate_limit: int = 10,
    timeout: int = 10,
    callback_url: Optional[str] = None,
    skip_warning: bool = False,
) -> List[Finding]:
    """
    Convenience function to run security scan.

    Args:
        target: Target specification (host, url, etc.)
        modules: Specific modules to run (None = all)
        rate_limit: Requests per second limit
        timeout: Request timeout
        callback_url: OOB callback server URL
        skip_warning: Skip authorization warning

    Returns:
        List of findings
    """
    orchestrator = ModuleOrchestrator(
        rate_limit=rate_limit,
        timeout=timeout,
        callback_url=callback_url,
    )
    return orchestrator.run_modules(target, modules=modules, skip_warning=skip_warning)
