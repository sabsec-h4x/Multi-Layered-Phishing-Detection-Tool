"""
Received Chain Investigation & Relay Hop Tracing
------------------------------------------------
Parses RFC-5322 Received headers chronologically to reconstruct
the email transmission relay path and identify the originating external IP.
"""

import re
import ipaddress
import email.utils
from typing import Dict, Any, List, Optional, Tuple

IP_REGEX = re.compile(r'\[?(\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:::ffff:)?(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b)\]?')
FROM_HOST_REGEX = re.compile(r'from\s+([^\s()]+)', re.IGNORECASE)
BY_HOST_REGEX = re.compile(r'by\s+([^\s()]+)', re.IGNORECASE)
WITH_PROTO_REGEX = re.compile(r'with\s+([^\s;]+)', re.IGNORECASE)


def is_private_ip(ip_str: str) -> bool:
    """Determine if IP address is internal / private / loopback."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def parse_single_received_header(received_str: str, hop_index: int) -> Dict[str, Any]:
    """Parse a single Received header line into a structured hop."""
    clean_str = " ".join(received_str.split())

    from_match = FROM_HOST_REGEX.search(clean_str)
    by_match = BY_HOST_REGEX.search(clean_str)
    with_match = WITH_PROTO_REGEX.search(clean_str)

    from_host = from_match.group(1).strip() if from_match else "unknown"
    by_host = by_match.group(1).strip() if by_match else "unknown"
    proto = with_match.group(1).strip() if with_match else None

    # Extract IPs in the header
    found_ips = IP_REGEX.findall(clean_str)
    hop_ip = found_ips[0] if found_ips else None

    is_internal = is_private_ip(hop_ip) if hop_ip else False

    # Extract timestamp after semicolon
    date_str = None
    if ";" in clean_str:
        date_part = clean_str.split(";")[-1].strip()
        try:
            parsed_date = email.utils.parsedate_to_datetime(date_part)
            date_str = parsed_date.isoformat()
        except Exception:
            date_str = date_part

    return {
        "hop_index": hop_index,
        "from_host": from_host,
        "by_host": by_host,
        "protocol": proto,
        "ip": hop_ip,
        "is_internal": is_internal,
        "timestamp": date_str,
        "raw": clean_str,
    }


def analyze_received_chain(msg: Any) -> Dict[str, Any]:
    """
    Parse all Received headers from an email message.
    Received headers are written top-to-bottom (most recent first).
    We order them from earliest originating hop to final delivery hop.
    """
    raw_headers = msg.get_all("Received") or []
    if not raw_headers:
        return {
            "hops": [],
            "total_hops": 0,
            "originating_ip": None,
            "originating_hop": None,
            "external_hops": [],
        }

    # Reverse to represent chronological order (earliest sender -> final recipient server)
    chronological_headers = list(reversed(raw_headers))
    hops = []
    external_hops = []

    for idx, raw_hdr in enumerate(chronological_headers, start=1):
        hop = parse_single_received_header(raw_hdr, idx)
        hops.append(hop)
        if hop["ip"] and not hop["is_internal"]:
            external_hops.append(hop)

    originating_hop = external_hops[0] if external_hops else (hops[0] if hops else None)
    originating_ip = originating_hop["ip"] if originating_hop else None

    return {
        "hops": hops,
        "total_hops": len(hops),
        "originating_ip": originating_ip,
        "originating_hop": originating_hop,
        "external_hops": external_hops,
    }
