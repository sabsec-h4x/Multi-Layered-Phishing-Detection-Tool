"""
SSRF Protection & Safe HTTP Client
----------------------------------
Provides robust SSRF prevention, IP validation, redirect inspection,
and resource-capped fetching for untrusted attacker-controlled URLs.
"""

import socket
import ipaddress
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
import requests

from config import FETCH_TIMEOUT, MAX_FETCH_BYTES, MAX_REDIRECTS, ALLOW_PRIVATE_IPS, USER_AGENT

# Blocked IP Networks
PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (only valid as source)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space (Carrier-grade NAT)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Metadata
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Network Benchmark Testing
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 ranges
    ipaddress.ip_network("::1/128"),            # IPv6 Loopback
    ipaddress.ip_network("::/128"),             # IPv6 Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique Local (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "169.254.169.254",
    "100.100.100.200",
    "169.254.170.2",
}

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}


class SSRFValidationError(Exception):
    """Raised when a URL fails SSRF safety validation."""
    pass


def is_ip_blocked(ip_str: str) -> Tuple[bool, str]:
    """Check if an IP address string is blocked under SSRF policies."""
    if ALLOW_PRIVATE_IPS:
        return False, "Allowed by configuration"

    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    # Check for IPv4 mapped IPv6 (e.g., ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    for network in PRIVATE_NETWORKS:
        if ip in network:
            return True, f"IP {ip_str} belongs to blocked subnet {network}"

    if ip.is_loopback:
        return True, f"IP {ip_str} is loopback"
    if ip.is_private:
        return True, f"IP {ip_str} is private"
    if ip.is_link_local:
        return True, f"IP {ip_str} is link-local"
    if ip.is_multicast:
        return True, f"IP {ip_str} is multicast"
    if ip.is_reserved:
        return True, f"IP {ip_str} is reserved"
    if ip.is_unspecified:
        return True, f"IP {ip_str} is unspecified"

    return False, "IP is public and routable"


def resolve_hostname_ips(hostname: str, port: int = 80) -> List[str]:
    """Resolve a hostname to list of unique IP addresses."""
    try:
        addrinfo = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
        ips = list({entry[4][0] for entry in addrinfo})
        return ips
    except socket.gaierror as e:
        raise SSRFValidationError(f"DNS resolution failed for '{hostname}': {e}")
    except Exception as e:
        raise SSRFValidationError(f"Could not resolve '{hostname}': {e}")


def validate_url_safety(url: str) -> Dict[str, Any]:
    """
    Validate that a URL is safe to fetch:
    - Scheme must be http or https
    - Hostname must not be cloud metadata
    - Port must be standard/whitelisted
    - Resolved IP addresses must not be private/loopback/reserved
    """
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFValidationError(f"Unsupported or dangerous URL scheme: '{scheme}' (only HTTP/HTTPS allowed)")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("URL has no valid hostname")

    hostname_clean = hostname.lower().strip("[]")

    if hostname_clean in CLOUD_METADATA_HOSTS:
        raise SSRFValidationError(f"Access to cloud metadata endpoint '{hostname_clean}' is blocked")

    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SSRFValidationError(f"Port {port} is not in the allowed ports list {ALLOWED_PORTS}")

    # Check if host is direct IP
    try:
        ipaddress.ip_address(hostname_clean)
        is_direct_ip = True
        ips = [hostname_clean]
    except ValueError:
        is_direct_ip = False
        ips = resolve_hostname_ips(hostname_clean, port)

    if not ips:
        raise SSRFValidationError(f"Hostname '{hostname_clean}' did not resolve to any IP addresses")

    for ip in ips:
        blocked, reason = is_ip_blocked(ip)
        if blocked:
            raise SSRFValidationError(f"SSRF blocked: {reason} for host '{hostname_clean}'")

    return {
        "url": url,
        "scheme": scheme,
        "hostname": hostname_clean,
        "port": port,
        "ips": ips,
        "is_direct_ip": is_direct_ip,
    }


def safe_fetch_page(url: str,
                    timeout: int = FETCH_TIMEOUT,
                    max_bytes: int = MAX_FETCH_BYTES,
                    max_redirects: int = MAX_REDIRECTS) -> Dict[str, Any]:
    """
    Safely fetch an external webpage while enforcing SSRF defenses across all redirect hops.
    Never executes JavaScript or renders external code.
    """
    current_url = url
    redirect_chain: List[Dict[str, Any]] = []
    redirect_count = 0

    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })

    try:
        while True:
            # Validate current hop against SSRF rules
            try:
                safety = validate_url_safety(current_url)
            except SSRFValidationError as e:
                return {
                    "reachable": False,
                    "error": f"SSRF Blocked: {e}",
                    "blocked": True,
                    "final_url": current_url,
                    "redirect_count": redirect_count,
                    "redirect_chain": redirect_chain,
                    "resolved_ips": [],
                }

            # Fetch the current hop without automated redirects
            try:
                response = session.get(
                    current_url,
                    timeout=(timeout, timeout),
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                )
            except requests.exceptions.SSLError as e:
                return {
                    "reachable": False,
                    "error": f"TLS/SSL certificate error: {e}",
                    "blocked": False,
                    "final_url": current_url,
                    "redirect_count": redirect_count,
                    "redirect_chain": redirect_chain,
                    "resolved_ips": safety["ips"],
                }
            except requests.exceptions.Timeout:
                return {
                    "reachable": False,
                    "error": f"Connection timed out after {timeout}s",
                    "blocked": False,
                    "final_url": current_url,
                    "redirect_count": redirect_count,
                    "redirect_chain": redirect_chain,
                    "resolved_ips": safety["ips"],
                }
            except requests.exceptions.ConnectionError as e:
                return {
                    "reachable": False,
                    "error": f"Connection failed: {e}",
                    "blocked": False,
                    "final_url": current_url,
                    "redirect_count": redirect_count,
                    "redirect_chain": redirect_chain,
                    "resolved_ips": safety["ips"],
                }

            redirect_chain.append({
                "url": current_url,
                "status_code": response.status_code,
                "ips": safety["ips"],
                "headers": dict(response.headers),
            })

            # Check for HTTP redirect response codes
            if response.status_code in (301, 302, 303, 307, 308) and "Location" in response.headers:
                redirect_count += 1
                if redirect_count > max_redirects:
                    return {
                        "reachable": False,
                        "error": f"Exceeded maximum redirect limit of {max_redirects}",
                        "blocked": False,
                        "final_url": current_url,
                        "redirect_count": redirect_count,
                        "redirect_chain": redirect_chain,
                        "resolved_ips": safety["ips"],
                    }

                next_url = urllib.parse.urljoin(current_url, response.headers["Location"])
                current_url = next_url
                continue

            # Read response body up to max_bytes
            raw_content = b""
            for chunk in response.iter_content(chunk_size=8192):
                raw_content += chunk
                if len(raw_content) >= max_bytes:
                    break

            encoding = response.encoding or "utf-8"
            decoded_text = raw_content.decode(encoding, errors="replace")

            return {
                "reachable": True,
                "status_code": response.status_code,
                "final_url": current_url,
                "redirect_count": redirect_count,
                "redirect_chain": redirect_chain,
                "resolved_ips": safety["ips"],
                "content": decoded_text,
                "content_bytes_len": len(raw_content),
                "headers": dict(response.headers),
                "error": None,
                "blocked": False,
            }

    except Exception as e:
        return {
            "reachable": False,
            "error": f"Unexpected fetch error ({type(e).__name__}): {e}",
            "blocked": False,
            "final_url": current_url,
            "redirect_count": redirect_count,
            "redirect_chain": redirect_chain,
            "resolved_ips": [],
        }
    finally:
        session.close()
