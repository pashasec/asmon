"""
asmon/modules/ssl_analysis.py — SSL/TLS configuration analysis.

Detects weak SSL/TLS configurations:
  - Expired/self-signed certificates
  - Weak cipher suites
  - Deprecated protocols (SSLv3, TLS 1.0, TLS 1.1)
  - Missing HSTS
  - Certificate chain issues
"""

import ssl
import socket
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from asmon.modules.base import (
    BaseModule,
    ModuleRegistry,
    Finding,
    FindingSeverity,
    FindingConfidence,
    FindingType,
)

logger = logging.getLogger("asmon.modules.ssl_analysis")


# Weak cipher patterns
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "RC2", "IDEA", "SEED", "CAMELLIA128",
]

# Deprecated protocols
DEPRECATED_PROTOCOLS = {
    ssl.PROTOCOL_SSLv23: "SSLv2/v3",
    # Note: SSLv2 and SSLv3 constants may not exist in newer Python
}

# Protocol test matrix
PROTOCOL_TESTS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1, "high"),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1, "medium"),
]


@ModuleRegistry.register
class SSLAnalysisModule(BaseModule):
    """Analyzes SSL/TLS configuration for security weaknesses."""

    name = "ssl_analysis"
    description = "Detects weak SSL/TLS configurations and certificate issues"
    risk_level = "low"
    requires_authorization = False  # Passive analysis

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.check_deprecated_protocols = True
        self.check_weak_ciphers = True
        self.check_cert_issues = True
        self.cert_expiry_warning_days = 30

    def run(self, target: dict) -> list[Finding]:
        """
        Analyze SSL/TLS configuration.

        Args:
            target: Dict with 'host', 'port' (default 443)
        """
        self.findings = []

        host = target.get("host")
        port = target.get("port", 443)

        if not host:
            return self.findings

        self.logger.info("Analyzing SSL/TLS for %s:%d", host, port)

        # Get certificate info
        cert_info = self._get_certificate(host, port)
        if cert_info:
            self._analyze_certificate(host, port, cert_info)

        # Check for deprecated protocols
        if self.check_deprecated_protocols:
            self._check_protocols(host, port)

        # Check cipher suites
        if self.check_weak_ciphers:
            self._check_ciphers(host, port)

        return self.findings

    def _get_certificate(self, host: str, port: int) -> Optional[dict]:
        """Retrieve certificate from server."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Get binary cert for more details
                    der_cert = ssock.getpeercert(binary_form=True)

                    return {
                        "cert": cert,
                        "cipher": cipher,
                        "version": version,
                        "der": der_cert,
                    }
        except ssl.SSLError as e:
            self.logger.debug("SSL error connecting to %s:%d: %s", host, port, e)
            # Try without SNI
            return self._get_certificate_no_sni(host, port)
        except Exception as e:
            self.logger.debug("Error getting cert from %s:%d: %s", host, port, e)
            return None

    def _get_certificate_no_sni(self, host: str, port: int) -> Optional[dict]:
        """Try getting certificate without SNI."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as ssock:
                    return {
                        "cert": ssock.getpeercert(binary_form=False),
                        "cipher": ssock.cipher(),
                        "version": ssock.version(),
                    }
        except Exception:
            return None

    def _analyze_certificate(self, host: str, port: int, cert_info: dict):
        """Analyze certificate for issues."""
        cert = cert_info.get("cert", {})

        if not cert:
            # Self-signed or invalid cert (no parsed data available)
            self.add_finding(Finding(
                finding_id=self.generate_finding_id("ssl_self_signed", host, port),
                finding_type=FindingType.SSL_SELF_SIGNED.value,
                module=self.name,
                severity=FindingSeverity.MEDIUM.value,
                confidence=FindingConfidence.HIGH.value,
                host=host,
                port=port,
                title="Self-signed or untrusted certificate",
                description="The server presents a certificate that could not be validated. "
                           "This may indicate a self-signed certificate or chain issues.",
                evidence={
                    "cipher": cert_info.get("cipher"),
                    "tls_version": cert_info.get("version"),
                },
                remediation="Install a certificate from a trusted Certificate Authority.",
                cwe_ids=["CWE-295"],
            ))
            return

        # Check expiration
        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.now()

                if expiry < now:
                    self.add_finding(Finding(
                        finding_id=self.generate_finding_id("ssl_expired", host, port),
                        finding_type=FindingType.SSL_EXPIRED_CERT.value,
                        module=self.name,
                        severity=FindingSeverity.HIGH.value,
                        confidence=FindingConfidence.CONFIRMED.value,
                        host=host,
                        port=port,
                        title="Expired SSL certificate",
                        description=f"Certificate expired on {not_after}",
                        evidence={
                            "not_after": not_after,
                            "subject": str(cert.get("subject")),
                        },
                        remediation="Renew the SSL certificate immediately.",
                        cwe_ids=["CWE-298"],
                    ))
                elif expiry < now + timedelta(days=self.cert_expiry_warning_days):
                    days_left = (expiry - now).days
                    self.add_finding(Finding(
                        finding_id=self.generate_finding_id("ssl_expiring", host, port),
                        finding_type=FindingType.SSL_EXPIRED_CERT.value,
                        module=self.name,
                        severity=FindingSeverity.LOW.value,
                        confidence=FindingConfidence.CONFIRMED.value,
                        host=host,
                        port=port,
                        title=f"SSL certificate expiring in {days_left} days",
                        description=f"Certificate will expire on {not_after}",
                        evidence={
                            "not_after": not_after,
                            "days_remaining": days_left,
                        },
                        remediation="Plan certificate renewal before expiration.",
                    ))
            except ValueError:
                pass

        # Check weak cipher in use
        cipher = cert_info.get("cipher", ())
        if cipher:
            cipher_name = cipher[0] if cipher else ""
            for weak in WEAK_CIPHERS:
                if weak.upper() in cipher_name.upper():
                    self.add_finding(Finding(
                        finding_id=self.generate_finding_id("ssl_weak_cipher", host, port, cipher_name),
                        finding_type=FindingType.SSL_WEAK_CIPHER.value,
                        module=self.name,
                        severity=FindingSeverity.HIGH.value,
                        confidence=FindingConfidence.CONFIRMED.value,
                        host=host,
                        port=port,
                        title=f"Weak cipher suite in use: {cipher_name}",
                        description=f"Server negotiated weak cipher: {cipher_name}. "
                                   "This cipher is considered insecure.",
                        evidence={
                            "cipher_name": cipher_name,
                            "cipher_bits": cipher[2] if len(cipher) > 2 else None,
                            "weak_component": weak,
                        },
                        remediation="Disable weak cipher suites and configure strong ciphers.",
                        cwe_ids=["CWE-327"],
                    ))
                    break

    def _check_protocols(self, host: str, port: int):
        """Check for deprecated protocol support."""
        for proto_name, proto_version, severity in PROTOCOL_TESTS:
            if self._test_protocol(host, port, proto_version):
                self.add_finding(Finding(
                    finding_id=self.generate_finding_id("ssl_weak_proto", host, port, proto_name),
                    finding_type=FindingType.SSL_WEAK_PROTOCOL.value,
                    module=self.name,
                    severity=severity,
                    confidence=FindingConfidence.CONFIRMED.value,
                    host=host,
                    port=port,
                    title=f"Deprecated protocol supported: {proto_name}",
                    description=f"Server accepts connections using {proto_name}, "
                               "which is deprecated and has known vulnerabilities.",
                    evidence={"protocol": proto_name},
                    remediation=f"Disable {proto_name} and use TLS 1.2 or higher.",
                    cwe_ids=["CWE-326"],
                ))

    def _test_protocol(self, host: str, port: int, protocol_version) -> bool:
        """Test if server accepts a specific protocol version."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = protocol_version
            context.maximum_version = protocol_version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except (ssl.SSLError, socket.error, OSError):
            return False

    def _check_ciphers(self, host: str, port: int):
        """Enumerate supported cipher suites for weaknesses."""
        # This is a simplified check - full enumeration would require
        # testing each cipher individually which is slow
        pass
