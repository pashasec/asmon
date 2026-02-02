"""
services.py — Service fingerprinting via banner grabbing.

Safe, read-only probes:
- HTTP: Send HEAD request, read headers
- HTTPS: Extract TLS certificate
- SSH/FTP/SMTP: Read welcome banner

NO authentication attempts, NO fuzzing.
"""

import socket
import ssl
import logging

logger = logging.getLogger("asmon.active.services")


def grab_banner(ip: str, port: int, timeout: int = 3) -> dict:
    """
    Grab service banner from a port.

    Returns:
        {
            "banner": "SSH-2.0-OpenSSH_7.4",
            "service_name": "ssh",
            "product": "OpenSSH",
            "version": "7.4"
        }
    """
    result = {
        "banner": None,
        "service_name": None,
        "product": None,
        "version": None,
    }

    # Try HTTPS/TLS first for common ports
    if port in [443, 8443, 8444, 9443]:
        tls_info = _grab_tls_banner(ip, port, timeout)
        if tls_info:
            result.update(tls_info)
            return result

    # Try plaintext banner grab
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send HTTP probe for web ports
        if port in [80, 8000, 8008, 8080, 8081, 8888, 9000]:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")

        # Read response
        banner_bytes = sock.recv(1024)
        sock.close()

        banner = banner_bytes.decode("utf-8", errors="ignore").strip()
        result["banner"] = banner[:512]  # Truncate

        # Parse service info
        parsed = _parse_banner(banner, port)
        result.update(parsed)

    except Exception as exc:
        logger.debug("Banner grab failed for %s:%d - %s", ip, port, exc)

    return result


def _grab_tls_banner(ip: str, port: int, timeout: int) -> dict | None:
    """Extract TLS certificate and server info."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                # Get TLS version
                tls_version = ssock.version()

                # Get certificate
                cert = ssock.getpeercert()

                # Try to get server header
                ssock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                response = ssock.recv(1024).decode("utf-8", errors="ignore")

                return {
                    "banner": response[:512] if response else f"TLS {tls_version}",
                    "service_name": "https",
                    "product": _extract_server_header(response) if response else None,
                }
    except Exception as exc:
        logger.debug("TLS banner grab failed for %s:%d - %s", ip, port, exc)
        return None


def _parse_banner(banner: str, port: int) -> dict:
    """
    Parse banner to extract service name, product, version.

    Examples:
        "SSH-2.0-OpenSSH_7.4" → service=ssh, product=OpenSSH, version=7.4
        "220 ProFTPD 1.3.5" → service=ftp, product=ProFTPD, version=1.3.5
    """
    result = {"service_name": None, "product": None, "version": None}
    banner_lower = banner.lower()

    # SSH detection
    if banner.startswith("SSH-"):
        result["service_name"] = "ssh"
        # Parse: SSH-2.0-OpenSSH_7.4
        parts = banner.split("-")
        if len(parts) >= 3:
            product_version = parts[2].split("_")
            result["product"] = product_version[0]
            if len(product_version) > 1:
                result["version"] = product_version[1].split()[0]

    # HTTP detection
    elif "http" in banner_lower or banner.startswith("HTTP/"):
        result["service_name"] = "http"
        result["product"] = _extract_server_header(banner)

    # FTP detection
    elif "ftp" in banner_lower or banner.startswith("220"):
        result["service_name"] = "ftp"
        # Parse: "220 ProFTPD 1.3.5 Server"
        parts = banner.split()
        if len(parts) >= 3:
            result["product"] = parts[1]
            result["version"] = parts[2]

    # SMTP detection
    elif "smtp" in banner_lower or banner.startswith("220") and "mail" in banner_lower:
        result["service_name"] = "smtp"

    # MySQL detection
    elif "mysql" in banner_lower or port == 3306:
        result["service_name"] = "mysql"

    # Fallback: common port mapping
    else:
        result["service_name"] = _guess_service_by_port(port)

    return result


def _extract_server_header(http_response: str) -> str | None:
    """Extract Server header from HTTP response."""
    for line in http_response.split("\n"):
        if line.lower().startswith("server:"):
            return line.split(":", 1)[1].strip().split("/")[0]
    return None


def _guess_service_by_port(port: int) -> str:
    """Fallback: guess service by common port numbers."""
    port_map = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        5900: "vnc",
        6379: "redis",
        8080: "http",
        8443: "https",
    }
    return port_map.get(port, "unknown")
