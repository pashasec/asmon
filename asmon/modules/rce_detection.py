"""
asmon/modules/rce_detection.py — Remote Code Execution indicator detection.

Detection via:
  - Command injection error patterns
  - Code injection indicators
  - Template injection (SSTI)
  - Deserialization indicators
  - Time-based command execution
"""

import logging
import re
import time
from typing import Optional
from urllib.parse import urlparse

from asmon.modules.base import (
    BaseModule, ModuleRegistry, Finding, FindingSeverity, FindingConfidence, FindingType,
)
from asmon.modules.http_utils import SecurityHTTPClient, inject_payload, get_params_from_url

logger = logging.getLogger("asmon.modules.rce")

# Command injection payloads
CMD_PAYLOADS = [
    # Basic command injection
    ("; id", ["uid=", "gid="]),
    ("| id", ["uid=", "gid="]),
    ("|| id", ["uid=", "gid="]),
    ("& id", ["uid=", "gid="]),
    ("&& id", ["uid=", "gid="]),
    ("`id`", ["uid=", "gid="]),
    ("$(id)", ["uid=", "gid="]),
    ("\nid\n", ["uid=", "gid="]),

    # Windows
    ("| whoami", ["\\", "AUTHORITY"]),
    ("& whoami", ["\\", "AUTHORITY"]),
    ("|| whoami", ["\\", "AUTHORITY"]),

    # Echo-based (safer)
    ("; echo ASMON_RCE_TEST", ["ASMON_RCE_TEST"]),
    ("| echo ASMON_RCE_TEST", ["ASMON_RCE_TEST"]),
    ("|| echo ASMON_RCE_TEST", ["ASMON_RCE_TEST"]),
    ("$(echo ASMON_RCE_TEST)", ["ASMON_RCE_TEST"]),
    ("`echo ASMON_RCE_TEST`", ["ASMON_RCE_TEST"]),
]

# Time-based payloads
TIME_PAYLOADS = [
    ("; sleep 5", 5),
    ("| sleep 5", 5),
    ("|| sleep 5", 5),
    ("& ping -c 5 127.0.0.1", 4),
    ("| ping -n 5 127.0.0.1", 4),  # Windows
    ("`sleep 5`", 5),
    ("$(sleep 5)", 5),
]

# Template injection (SSTI) payloads
SSTI_PAYLOADS = [
    ("{{7*7}}", ["49"]),
    ("${7*7}", ["49"]),
    ("#{7*7}", ["49"]),
    ("<%= 7*7 %>", ["49"]),
    ("{{7*'7'}}", ["7777777", "49"]),
    ("${{7*7}}", ["49"]),
    ("{{config}}", ["SECRET_KEY", "DEBUG"]),
    ("{{self}}", ["TemplateReference"]),
    ("{{request}}", ["Request"]),
    ("{{''.__class__}}", ["str"]),
    ("${T(java.lang.Runtime)}", ["Runtime", "java.lang"]),
]

# Deserialization indicators
DESER_PATTERNS = [
    r"java\.io\.InvalidClassException",
    r"java\.io\.ObjectStreamException",
    r"unserialize\(\)",
    r"pickle\.loads",
    r"yaml\.load",
    r"ObjectInputStream",
    r"ClassNotFoundException",
]


@ModuleRegistry.register
class RCEDetectionModule(BaseModule):
    """Detects Remote Code Execution vulnerabilities."""

    name = "rce_detection"
    description = "Detects command injection, SSTI, and deserialization vulnerabilities"
    risk_level = "high"
    requires_authorization = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.http = SecurityHTTPClient(timeout=15, rate_limit=self.rate_limit, user_agent=self.user_agent)
        self.time_threshold = 4.0

    def run(self, target: dict) -> list[Finding]:
        self.findings = []
        url = target.get("url")
        if not url:
            return self.findings

        params = get_params_from_url(url)
        if not params:
            return self.findings

        self.logger.info("Testing %d parameters for RCE: %s", len(params), url)

        for param in params.keys():
            self._test_command_injection(url, param)
            self._test_ssti(url, param)
            self._test_time_based(url, param)

        return self.findings

    def _test_command_injection(self, url: str, param: str):
        for payload, signatures in CMD_PAYLOADS:
            test_url = inject_payload(url, param, payload)
            result = self.http.get(test_url)

            if not result.success or not result.response:
                continue

            body = result.response.body_preview

            for sig in signatures:
                if sig in body:
                    self.add_finding(Finding(
                        finding_id=self.generate_finding_id("rce_cmd", url, param, payload[:15]),
                        finding_type=FindingType.RCE_COMMAND_INJECTION.value,
                        module=self.name,
                        severity=FindingSeverity.CRITICAL.value,
                        confidence=FindingConfidence.CONFIRMED.value,
                        host=urlparse(url).netloc.split(":")[0],
                        url=url,
                        parameter=param,
                        title=f"Command Injection in parameter '{param}'",
                        description=f"Parameter '{param}' is vulnerable to OS command injection.",
                        evidence={"payload": payload, "signature": sig, "parameter": param},
                        remediation="Never pass user input to shell commands. Use safe APIs.",
                        cwe_ids=["CWE-78"],
                    ))
                    return

    def _test_ssti(self, url: str, param: str):
        for payload, signatures in SSTI_PAYLOADS:
            test_url = inject_payload(url, param, payload)
            result = self.http.get(test_url)

            if not result.success or not result.response:
                continue

            body = result.response.body_preview

            for sig in signatures:
                if sig in body and payload.replace("7*7", "").replace("7*'7'", "") not in body:
                    self.add_finding(Finding(
                        finding_id=self.generate_finding_id("rce_ssti", url, param),
                        finding_type=FindingType.RCE_TEMPLATE_INJECTION.value,
                        module=self.name,
                        severity=FindingSeverity.CRITICAL.value,
                        confidence=FindingConfidence.HIGH.value,
                        host=urlparse(url).netloc.split(":")[0],
                        url=url,
                        parameter=param,
                        title=f"Server-Side Template Injection in parameter '{param}'",
                        description="Template expressions are evaluated, indicating SSTI vulnerability.",
                        evidence={"payload": payload, "result": sig, "parameter": param},
                        remediation="Sanitize template inputs. Use sandbox mode.",
                        cwe_ids=["CWE-94"],
                    ))
                    return

    def _test_time_based(self, url: str, param: str):
        # Baseline timing
        baseline_times = []
        for _ in range(2):
            start = time.time()
            result = self.http.get(url)
            if result.success:
                baseline_times.append(time.time() - start)

        if not baseline_times:
            return

        avg_baseline = sum(baseline_times) / len(baseline_times)

        for payload, delay in TIME_PAYLOADS[:4]:  # Limit slow tests
            test_url = inject_payload(url, param, payload)

            start = time.time()
            result = self.http.get(test_url)
            elapsed = time.time() - start

            if result.success and elapsed > (avg_baseline + self.time_threshold):
                # Verify
                start2 = time.time()
                self.http.get(test_url)
                elapsed2 = time.time() - start2

                if elapsed2 > (avg_baseline + self.time_threshold):
                    self.add_finding(Finding(
                        finding_id=self.generate_finding_id("rce_time", url, param),
                        finding_type=FindingType.RCE_COMMAND_INJECTION.value,
                        module=self.name,
                        severity=FindingSeverity.CRITICAL.value,
                        confidence=FindingConfidence.HIGH.value,
                        host=urlparse(url).netloc.split(":")[0],
                        url=url,
                        parameter=param,
                        title=f"Command Injection (time-based) in parameter '{param}'",
                        description=f"Sleep command caused {elapsed:.1f}s delay (baseline: {avg_baseline:.1f}s).",
                        evidence={"payload": payload, "delay": round(elapsed, 2), "baseline": round(avg_baseline, 2)},
                        remediation="Never pass user input to shell commands.",
                        cwe_ids=["CWE-78"],
                    ))
                    return
