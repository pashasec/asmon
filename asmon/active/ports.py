"""
ports.py — Safe TCP connect port scanner.

NO SYN floods, NO stealth scanning.
Uses standard TCP connect() for compatibility and safety.
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("asmon.active.ports")

# Common port lists
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 20, 69, 123, 137, 138,
    161, 162, 389, 636, 989, 990, 1433, 1521, 2049, 2121, 3268, 5432, 5631,
    5800, 5901, 6000, 6001, 8000, 8008, 8081, 8082, 8181, 8888, 9000, 9001,
    9080, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]


def parse_port_spec(spec: str) -> list[int]:
    """
    Parse port specification string.

    Examples:
        "top100" → first 100 common ports
        "1-1024" → range
        "22,80,443" → comma-separated list
        "all" → all 65535 ports (SLOW, not recommended)
    """
    spec = spec.strip().lower()

    if spec == "top100":
        return TOP_100_PORTS
    elif spec == "all":
        logger.warning("Scanning all 65535 ports - this will take a long time")
        return list(range(1, 65536))
    elif "-" in spec:
        # Range: "1-1024"
        try:
            start, end = spec.split("-")
            return list(range(int(start), int(end) + 1))
        except ValueError:
            logger.error("Invalid port range: %s", spec)
            return TOP_100_PORTS
    elif "," in spec:
        # Comma-separated: "22,80,443"
        try:
            return [int(p.strip()) for p in spec.split(",")]
        except ValueError:
            logger.error("Invalid port list: %s", spec)
            return TOP_100_PORTS
    else:
        logger.error("Unknown port spec: %s, using top100", spec)
        return TOP_100_PORTS


def scan_port(ip: str, port: int, timeout: int = 3) -> dict | None:
    """
    Attempt TCP connect to a single port.
    Returns dict if port is open, None if closed/filtered.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return {"port": port, "state": "open"}
        else:
            return None
    except socket.timeout:
        return None
    except Exception as exc:
        logger.debug("Port scan error %s:%d - %s", ip, port, exc)
        return None


def scan_host(ip: str, ports: list[int], rate_limit: int = 100, timeout: int = 3) -> list[dict]:
    """
    Scan multiple ports on a host.

    Args:
        ip: Target IP address
        ports: List of ports to scan
        rate_limit: Max concurrent connections (default: 100)
        timeout: Socket timeout in seconds (default: 3)

    Returns:
        List of dicts for open ports: [{"port": 80, "state": "open"}, ...]
    """
    open_ports = []
    max_workers = min(rate_limit, len(ports))

    logger.info("Scanning %s (%d ports, %d workers)", ip, len(ports), max_workers)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}

        for future in as_completed(futures):
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
                    logger.info("  → Open: %s:%d", ip, result["port"])
            except Exception as exc:
                port = futures[future]
                logger.debug("Scan error %s:%d - %s", ip, port, exc)

    return open_ports
