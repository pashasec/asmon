"""
asmon/modules/base.py — Base classes for security analysis modules.

Provides the foundation for all pluggable security modules:
  - BaseModule: Abstract base class all modules inherit from
  - Finding: Standardized vulnerability/issue representation
  - ModuleRegistry: Central registry for module discovery
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Callable
from pydantic import BaseModel, Field

logger = logging.getLogger("asmon.modules")


# ---------------------------------------------------------------------------
# Finding severity and confidence levels
# ---------------------------------------------------------------------------

class FindingSeverity(str, Enum):
    """Severity levels aligned with CVSS."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingConfidence(str, Enum):
    """Confidence in finding accuracy."""
    CONFIRMED = "confirmed"  # Verified exploitation or definitive evidence
    HIGH = "high"            # Strong indicators, high certainty
    MEDIUM = "medium"        # Multiple signals, reasonable certainty
    LOW = "low"              # Single weak signal, needs verification
    TENTATIVE = "tentative"  # Heuristic match, may be false positive


class FindingType(str, Enum):
    """Categories of security findings."""
    SSL_WEAK_CIPHER = "ssl_weak_cipher"
    SSL_EXPIRED_CERT = "ssl_expired_cert"
    SSL_SELF_SIGNED = "ssl_self_signed"
    SSL_WEAK_PROTOCOL = "ssl_weak_protocol"
    SSL_MISSING_HSTS = "ssl_missing_hsts"

    EXPOSED_ADMIN = "exposed_admin"
    EXPOSED_BACKUP = "exposed_backup"
    EXPOSED_CONFIG = "exposed_config"
    EXPOSED_DEBUG = "exposed_debug"
    EXPOSED_SOURCE = "exposed_source"
    DIRECTORY_LISTING = "directory_listing"

    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    DANGLING_CNAME = "dangling_cname"

    SQLI_ERROR = "sqli_error"
    SQLI_BOOLEAN = "sqli_boolean"
    SQLI_TIME = "sqli_time"
    SQLI_UNION = "sqli_union"

    XSS_REFLECTED = "xss_reflected"
    XSS_DOM = "xss_dom"
    XSS_STORED = "xss_stored"

    LFI_PATH_TRAVERSAL = "lfi_path_traversal"
    LFI_WRAPPER = "lfi_wrapper"
    RFI_INCLUDE = "rfi_include"

    RCE_COMMAND_INJECTION = "rce_command_injection"
    RCE_CODE_INJECTION = "rce_code_injection"
    RCE_DESERIALIZATION = "rce_deserialization"
    RCE_TEMPLATE_INJECTION = "rce_template_injection"

    SSRF_INTERNAL = "ssrf_internal"
    SSRF_CLOUD_METADATA = "ssrf_cloud_metadata"

    OOB_DNS = "oob_dns"
    OOB_HTTP = "oob_http"

    MISCONFIG_CORS = "misconfig_cors"
    MISCONFIG_HEADERS = "misconfig_headers"
    MISCONFIG_VERBOSE_ERRORS = "misconfig_verbose_errors"
    MISCONFIG_DEFAULT_CREDS = "misconfig_default_creds"

    CVE_DETECTED = "cve_detected"

    GENERIC = "generic"


# ---------------------------------------------------------------------------
# Finding model — standardized vulnerability representation
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """
    A security finding detected by an analysis module.

    Contains all metadata needed for reporting, triage, and diff tracking.
    """
    # Identity
    finding_id: str                        # Unique ID (module:type:hash)
    finding_type: str                      # FindingType value
    module: str                            # Module that detected this

    # Classification
    severity: str = "info"                 # FindingSeverity value
    confidence: str = "low"                # FindingConfidence value

    # Target
    host: str                              # IP or hostname
    port: Optional[int] = None
    url: Optional[str] = None              # Full URL if applicable
    parameter: Optional[str] = None        # Vulnerable parameter

    # Details
    title: str                             # Short human-readable title
    description: str = ""                  # Detailed description

    # Evidence (request/response metadata only, no full bodies)
    evidence: dict = Field(default_factory=dict)
    # Example: {"request_method": "GET", "request_path": "/admin",
    #           "response_code": 200, "response_headers": {...},
    #           "matched_pattern": "...", "payload_used": "..."}

    # Remediation
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)

    # Metadata
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    detection_method: str = ""             # How it was detected
    false_positive_likelihood: str = "unknown"  # "low" | "medium" | "high" | "unknown"

    def __hash__(self):
        return hash(self.finding_id)

    def __eq__(self, other):
        if isinstance(other, Finding):
            return self.finding_id == other.finding_id
        return False


# ---------------------------------------------------------------------------
# Request/Response context for evidence collection
# ---------------------------------------------------------------------------

@dataclass
class RequestContext:
    """Captured request details for evidence."""
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class ResponseContext:
    """Captured response details for evidence."""
    status_code: int
    headers: dict = field(default_factory=dict)
    body_preview: str = ""  # First N bytes only
    body_length: int = 0
    response_time: float = 0.0


@dataclass
class ProbeResult:
    """Result of a single probe/test."""
    success: bool
    request: Optional[RequestContext] = None
    response: Optional[ResponseContext] = None
    matched_pattern: Optional[str] = None
    payload_used: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Base module class
# ---------------------------------------------------------------------------

class BaseModule(ABC):
    """
    Abstract base class for all security analysis modules.

    Subclasses must implement:
      - name: Module identifier
      - description: What the module does
      - run(): Main execution logic
    """

    # Module metadata (override in subclasses)
    name: str = "base"
    description: str = "Base module"
    author: str = "ASMON"
    version: str = "1.0.0"

    # Safety settings
    requires_authorization: bool = True
    risk_level: str = "medium"  # "low" | "medium" | "high"

    def __init__(
        self,
        rate_limit: int = 10,
        timeout: int = 10,
        max_concurrent: int = 5,
        user_agent: str = "ASMON-SecurityModule/1.0",
        callback_url: Optional[str] = None,
    ):
        """
        Initialize module with safety controls.

        Args:
            rate_limit: Max requests per second
            timeout: Request timeout in seconds
            max_concurrent: Max concurrent requests
            user_agent: User-Agent header
            callback_url: OOB callback server URL (if applicable)
        """
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.user_agent = user_agent
        self.callback_url = callback_url

        self._last_request_time = 0.0
        self._request_count = 0
        self.findings: list[Finding] = []
        self.logger = logging.getLogger(f"asmon.modules.{self.name}")

    def _rate_limit_wait(self):
        """Enforce rate limiting between requests."""
        if self.rate_limit <= 0:
            return

        min_interval = 1.0 / self.rate_limit
        elapsed = time.time() - self._last_request_time

        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)

        self._last_request_time = time.time()
        self._request_count += 1

    def add_finding(self, finding: Finding):
        """Add a finding to the results."""
        self.findings.append(finding)
        self.logger.info(
            "Finding: [%s] %s on %s — %s",
            finding.severity.upper(),
            finding.finding_type,
            finding.host,
            finding.title,
        )

    def generate_finding_id(self, finding_type: str, *args) -> str:
        """Generate a unique finding ID."""
        import hashlib
        data = f"{self.name}:{finding_type}:{':'.join(str(a) for a in args)}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    @abstractmethod
    def run(self, target: dict) -> list[Finding]:
        """
        Execute the module against a target.

        Args:
            target: Dict with 'host', 'port', 'url', 'services', etc.

        Returns:
            List of Finding objects
        """
        pass

    def pre_run_check(self, target: dict) -> bool:
        """
        Validate target before running.
        Override in subclasses for custom validation.
        """
        return "host" in target


# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------

class ModuleRegistry:
    """Central registry for discovering and loading modules."""

    _modules: dict[str, type[BaseModule]] = {}

    @classmethod
    def register(cls, module_class: type[BaseModule]):
        """Register a module class."""
        cls._modules[module_class.name] = module_class
        return module_class

    @classmethod
    def get(cls, name: str) -> Optional[type[BaseModule]]:
        """Get a module class by name."""
        return cls._modules.get(name)

    @classmethod
    def list_modules(cls) -> list[str]:
        """List all registered module names."""
        return list(cls._modules.keys())

    @classmethod
    def get_all(cls) -> dict[str, type[BaseModule]]:
        """Get all registered modules."""
        return cls._modules.copy()
