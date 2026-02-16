"""
dns_security.py — DNS security posture checks.

Pure DNS queries — no API keys, no rate limits, no packets to target.
Checks SPF, DMARC, DNSSEC, CAA, and MX records to assess email and
DNS security posture.

What it detects:
  - Missing SPF        → domain can be spoofed in emails
  - Weak SPF (~all)    → SPF exists but doesn't enforce (soft fail)
  - Missing DMARC      → no policy for email authentication failures
  - Weak DMARC (none)  → DMARC exists but doesn't enforce
  - Missing DNSSEC     → DNS responses can be tampered with
  - Missing CAA        → any CA can issue certs for this domain
  - Open mail relays   → MX records pointing to unexpected servers

Findings are returned as WebRiskSignal objects to integrate cleanly
with the existing snapshot model and diff engine.
"""

import logging
from typing import Optional
import dns.resolver
import dns.exception

from asmon.models import WebRiskSignal

logger = logging.getLogger("asmon.dns_security")

# Timeout for each DNS query
DNS_TIMEOUT = 5


class DNSSecurityChecker:
    """
    Check DNS security posture for a domain.

    Usage:
        checker = DNSSecurityChecker()
        signals = checker.check("example.com")
        # Returns list of WebRiskSignal objects
    """

    def __init__(self, timeout: float = DNS_TIMEOUT):
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = timeout
        self._resolver.timeout = timeout

    def check(self, domain: str) -> list[WebRiskSignal]:
        """
        Run all DNS security checks on a domain.

        Returns list of WebRiskSignal for each issue found.
        """
        signals: list[WebRiskSignal] = []

        logger.info("DNS security check for %s", domain)

        signals.extend(self._check_spf(domain))
        signals.extend(self._check_dmarc(domain))
        signals.extend(self._check_dnssec(domain))
        signals.extend(self._check_caa(domain))
        signals.extend(self._check_mx(domain))

        logger.info("DNS security: %d finding(s) for %s", len(signals), domain)
        return signals

    # ------------------------------------------------------------------
    # SPF
    # ------------------------------------------------------------------

    def _check_spf(self, domain: str) -> list[WebRiskSignal]:
        """Check SPF record presence and strength."""
        signals = []
        spf_record = self._get_spf(domain)

        if spf_record is None:
            signals.append(WebRiskSignal(
                signal_type="missing_dns_record",
                severity="high",
                title="No SPF record",
                detail=f"Domain {domain} has no SPF record. "
                       f"Any server can send email pretending to be @{domain}.",
                recommendation="Add a TXT record: v=spf1 include:_spf.yourprovider.com -all",
            ))
            return signals

        # Check for weak SPF policies
        if "~all" in spf_record:
            signals.append(WebRiskSignal(
                signal_type="weak_dns_config",
                severity="medium",
                title="SPF uses soft fail (~all)",
                detail=f"SPF record uses ~all (soft fail) instead of -all (hard fail). "
                       f"Spoofed emails may still be delivered. Record: {spf_record}",
                recommendation="Change ~all to -all for strict enforcement.",
            ))
        elif "?all" in spf_record:
            signals.append(WebRiskSignal(
                signal_type="weak_dns_config",
                severity="high",
                title="SPF uses neutral policy (?all)",
                detail=f"SPF record uses ?all (neutral) — effectively no protection. "
                       f"Record: {spf_record}",
                recommendation="Change ?all to -all for strict enforcement.",
            ))
        elif "+all" in spf_record:
            signals.append(WebRiskSignal(
                signal_type="weak_dns_config",
                severity="high",
                title="SPF allows all senders (+all)",
                detail=f"SPF record uses +all which allows ANY server to send as {domain}. "
                       f"This is worse than having no SPF. Record: {spf_record}",
                recommendation="Fix immediately: change +all to -all with proper includes.",
            ))

        return signals

    def _get_spf(self, domain: str) -> Optional[str]:
        """Query TXT records and extract SPF."""
        try:
            answers = self._resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    return txt
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException as exc:
            logger.debug("SPF lookup failed for %s: %s", domain, exc)
        return None

    # ------------------------------------------------------------------
    # DMARC
    # ------------------------------------------------------------------

    def _check_dmarc(self, domain: str) -> list[WebRiskSignal]:
        """Check DMARC record presence and policy strength."""
        signals = []
        dmarc_record = self._get_dmarc(domain)

        if dmarc_record is None:
            signals.append(WebRiskSignal(
                signal_type="missing_dns_record",
                severity="high",
                title="No DMARC record",
                detail=f"Domain {domain} has no DMARC record. "
                       f"Email receivers cannot verify if messages are legitimately from {domain}.",
                recommendation="Add TXT record at _dmarc.{}: v=DMARC1; p=reject; rua=mailto:dmarc@{}".format(domain, domain),
            ))
            return signals

        # Check for weak DMARC policy
        if "p=none" in dmarc_record:
            signals.append(WebRiskSignal(
                signal_type="weak_dns_config",
                severity="medium",
                title="DMARC policy set to 'none'",
                detail=f"DMARC record exists but policy is 'none' — no action taken on failures. "
                       f"This is monitoring-only mode. Record: {dmarc_record}",
                recommendation="Upgrade to p=quarantine or p=reject after reviewing DMARC reports.",
            ))

        return signals

    def _get_dmarc(self, domain: str) -> Optional[str]:
        """Query DMARC record at _dmarc.domain."""
        try:
            answers = self._resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    return txt
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.DNSException as exc:
            logger.debug("DMARC lookup failed for %s: %s", domain, exc)
        return None

    # ------------------------------------------------------------------
    # DNSSEC
    # ------------------------------------------------------------------

    def _check_dnssec(self, domain: str) -> list[WebRiskSignal]:
        """Check if DNSSEC is enabled."""
        signals = []

        try:
            self._resolver.resolve(domain, "DNSKEY")
            # DNSKEY exists → DNSSEC is enabled
            return signals
        except dns.resolver.NoAnswer:
            pass
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except dns.exception.DNSException as exc:
            logger.debug("DNSSEC check failed for %s: %s", domain, exc)
            return signals

        signals.append(WebRiskSignal(
            signal_type="missing_dns_config",
            severity="low",
            title="DNSSEC not enabled",
            detail=f"Domain {domain} does not have DNSSEC enabled. "
                   f"DNS responses can potentially be spoofed or tampered with.",
            recommendation="Enable DNSSEC through your DNS provider.",
        ))

        return signals

    # ------------------------------------------------------------------
    # CAA
    # ------------------------------------------------------------------

    def _check_caa(self, domain: str) -> list[WebRiskSignal]:
        """Check CAA (Certificate Authority Authorization) records."""
        signals = []

        try:
            answers = self._resolver.resolve(domain, "CAA")
            # CAA exists → good, CAs are restricted
            caa_records = [r.to_text() for r in answers]
            logger.debug("CAA records for %s: %s", domain, caa_records)
            return signals
        except dns.resolver.NoAnswer:
            pass
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return signals
        except dns.exception.DNSException as exc:
            logger.debug("CAA lookup failed for %s: %s", domain, exc)
            return signals

        signals.append(WebRiskSignal(
            signal_type="missing_dns_record",
            severity="low",
            title="No CAA records",
            detail=f"Domain {domain} has no CAA records. "
                   f"Any Certificate Authority can issue SSL certificates for this domain.",
            recommendation="Add CAA records to restrict which CAs can issue certs for your domain.",
        ))

        return signals

    # ------------------------------------------------------------------
    # MX
    # ------------------------------------------------------------------

    def _check_mx(self, domain: str) -> list[WebRiskSignal]:
        """Check MX records for potential issues."""
        signals = []

        try:
            answers = self._resolver.resolve(domain, "MX")
            mx_records = [(r.preference, r.exchange.to_text().rstrip(".")) for r in answers]
        except dns.resolver.NoAnswer:
            # No MX — domain probably doesn't handle email, not an issue
            return signals
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return signals
        except dns.exception.DNSException as exc:
            logger.debug("MX lookup failed for %s: %s", domain, exc)
            return signals

        if not mx_records:
            return signals

        # Check for catch-all / suspicious MX
        for priority, exchange in mx_records:
            # Localhost MX = misconfiguration
            if exchange in ("localhost", "127.0.0.1", ""):
                signals.append(WebRiskSignal(
                    signal_type="dns_misconfiguration",
                    severity="high",
                    title="MX points to localhost",
                    detail=f"MX record for {domain} points to {exchange} (priority {priority}). "
                           f"This is a misconfiguration — email will not be delivered.",
                    recommendation="Fix MX record to point to a valid mail server.",
                ))

            # MX pointing to IP instead of hostname
            if _is_ip(exchange):
                signals.append(WebRiskSignal(
                    signal_type="dns_misconfiguration",
                    severity="medium",
                    title="MX record points to IP address",
                    detail=f"MX record for {domain} points to IP {exchange} instead of a hostname. "
                           f"This violates RFC 5321 and may cause delivery issues.",
                    recommendation="Change MX to point to a hostname, not an IP.",
                ))

        return signals


def _is_ip(value: str) -> bool:
    """Check if a string looks like an IP address."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False
