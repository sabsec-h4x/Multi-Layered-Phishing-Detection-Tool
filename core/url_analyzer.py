"""
Advanced URL Normalization, Forensics & Heuristic Detection Engine
------------------------------------------------------------------
Analyzes URL structure, IP encodings (dec/hex/oct), IDN homographs/punycode,
typosquatting, userinfo (@) abuse, subdomain nesting, and open redirect parameters.
"""

import re
import socket
import ipaddress
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple, Set

from core.url_extractor import get_registrable_domain

# Common URL Shorteners
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "rb.gy", "tiny.one", "cutt.ly", "shorturl.at", "trib.al",
    "lnkd.in", "t.ly", "s.id", "v.gd", "clck.ru", "qr.ae", "adf.ly"
}

# High-Risk / Abused TLDs in Phishing Campaigns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".info", ".click", ".work", ".gq", ".cf",
    ".ml", ".tk", ".live", ".loan", ".buzz", ".cam", ".rest", ".fit",
    ".gdn", ".icu", ".monster", ".sbs", ".cfd", ".quest", ".beauty", ".skin"
}

# Suspicious Path / Query Keywords
CREDENTIAL_PATHS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "secure",
    "account", "update", "banking", "auth", "authorize", "recover", "security",
    "confirm", "validation", "wallet", "checkpoint", "password", "reset", "webscr"
]

OPEN_REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return", "return_to",
    "return_url", "next", "url", "target", "dest", "destination", "r",
    "goto", "checkout_url", "forward", "link", "out", "view"
]

# Unicode Cyrillic/Greek Confusables Map
CONFUSABLES = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
    'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X'
}

KEYBOARD_ADJACENT = {
    "q": "wa", "w": "qeas", "e": "wrsd", "r": "etdf", "t": "ryfg", "y": "tugh",
    "u": "yihj", "i": "uojk", "o": "ipkl", "p": "ol", "a": "qwsz", "s": "awedzx",
    "d": "serfxc", "f": "drtgcv", "g": "ftyhvb", "h": "gyujbn", "j": "huiknm",
    "k": "jiolm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb",
    "b": "vghn", "n": "bhjm", "m": "njk"
}


def parse_numeric_ip(host: str) -> Optional[str]:
    """
    Detect and normalize integer/hex/octal IP representations.
    e.g. 2130706433 -> 127.0.0.1, 0x7f000001 -> 127.0.0.1, 017700000001 -> 127.0.0.1
    """
    host_clean = host.split(":")[0].strip()

    # Pure integer decimal (e.g. 2130706433)
    if host_clean.isdigit():
        try:
            num = int(host_clean)
            if 0 <= num <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(num))
        except (ValueError, OverflowError):
            pass

    # Hex representation (e.g. 0x7f000001 or 0x7f.0x0.0x0.0x1)
    if host_clean.lower().startswith("0x"):
        try:
            num = int(host_clean, 16)
            if 0 <= num <= 0xFFFFFFFF:
                return str(ipaddress.IPv4Address(num))
        except (ValueError, OverflowError):
            pass

    # Dot-separated hex or octal (e.g. 0177.0.0.1 or 0x7f.0.0.1)
    parts = host_clean.split(".")
    if len(parts) == 4:
        try:
            octets = []
            for p in parts:
                if p.lower().startswith("0x"):
                    octets.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1 and p.isdigit():
                    octets.append(int(p, 8))
                elif p.isdigit():
                    octets.append(int(p, 10))
                else:
                    return None
            if all(0 <= octet <= 255 for octet in octets):
                return ".".join(str(o) for o in octets)
        except (ValueError, OverflowError):
            pass

    return None


def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_keyboard_typo(a: str, b: str) -> bool:
    """Check if string 'a' is a 1-character keyboard adjacency typo of 'b'."""
    if not a or not b or len(a) != len(b):
        return False
    diffs = 0
    match = True
    for ca, cb in zip(a, b):
        if ca != cb:
            diffs += 1
            if diffs > 1 or ca not in KEYBOARD_ADJACENT.get(cb, ""):
                match = False
                break
    return diffs == 1 and match


def check_homographs(domain: str) -> Tuple[bool, Optional[str]]:
    """Check for IDN homograph / punycode attack strings."""
    if not domain:
        return False, None

    if "xn--" in domain.lower():
        try:
            decoded = domain.encode("ascii").decode("idna")
            return True, f"Punycode encoded domain (decodes to '{decoded}')"
        except Exception:
            return True, "Punycode encoded domain"

    # Check for mixed Unicode confusables in Latin-looking domain
    confusable_hits = [char for char in domain if char in CONFUSABLES]
    if confusable_hits:
        normalized = "".join(CONFUSABLES.get(c, c) for c in domain)
        return True, f"Contains Unicode confusable character(s) '{''.join(set(confusable_hits))}' (spoofs '{normalized}')"

    return False, None


def analyze_url_structure(url: str) -> Dict[str, Any]:
    """
    Perform deep structural forensics on a single URL.
    Returns findings, indicators, normalized domains, and structural risk signals.
    """
    findings = []
    structural_risk_score = 0

    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc
    path = parsed.path
    query = parsed.query

    # 1. Userinfo / @ symbol abuse
    userinfo = ""
    host_port = netloc
    if "@" in netloc:
        userinfo, host_port = netloc.split("@", 1)
        findings.append({
            "flag": True, "weight": 30,
            "category": "userinfo_abuse",
            "text": f"URL uses '@' credential embedding to disguise destination: userinfo='{userinfo}', actual host='{host_port}'"
        })
        structural_risk_score += 30

    # 2. Port Forensics
    hostname = host_port.split(":")[0].strip("[]")
    port = parsed.port
    if port and port not in (80, 443):
        findings.append({
            "flag": True, "weight": 15,
            "category": "suspicious_port",
            "text": f"URL uses non-standard web port: :{port}"
        })
        structural_risk_score += 15

    # 3. Numeric / Encoded IP analysis
    normalized_ip = parse_numeric_ip(hostname)
    is_direct_ip = False
    if normalized_ip:
        is_direct_ip = True
        findings.append({
            "flag": True, "weight": 25,
            "category": "ip_host",
            "text": f"URL uses raw IP host format: '{hostname}' (normalized: {normalized_ip})"
        })
        structural_risk_score += 25
    else:
        try:
            ipaddress.ip_address(hostname)
            is_direct_ip = True
            findings.append({
                "flag": True, "weight": 25,
                "category": "ip_host",
                "text": f"URL points directly to raw IP address: {hostname}"
            })
            structural_risk_score += 25
        except ValueError:
            pass

    # 4. Registrable Domain & Subdomains
    domain = get_registrable_domain(hostname) if not is_direct_ip else hostname
    subdomain_parts = hostname.replace(f".{domain}", "").split(".") if domain and domain in hostname else []
    subdomain_depth = len([p for p in subdomain_parts if p])

    if subdomain_depth >= 4:
        findings.append({
            "flag": True, "weight": 15,
            "category": "excessive_subdomains",
            "text": f"Excessive subdomain depth ({subdomain_depth} levels) on domain '{domain}'"
        })
        structural_risk_score += 15

    # 5. Suspicious TLD
    if any(hostname.lower().endswith(tld) for tld in SUSPICIOUS_TLDS):
        matched_tld = next(tld for tld in SUSPICIOUS_TLDS if hostname.lower().endswith(tld))
        findings.append({
            "flag": True, "weight": 15,
            "category": "suspicious_tld",
            "text": f"High-abuse / suspicious TLD '{matched_tld}' in domain: {hostname}"
        })
        structural_risk_score += 15

    # 6. URL Shortener Detection
    is_shortener = hostname.lower() in SHORTENERS or any(hostname.lower().endswith("." + s) for s in SHORTENERS)
    if is_shortener:
        findings.append({
            "flag": True, "weight": 15,
            "category": "shortener",
            "text": f"URL uses shortener service '{hostname}' to obscure destination target"
        })
        structural_risk_score += 15

    # 7. Homograph & Punycode Detection
    is_homograph, homograph_detail = check_homographs(hostname)
    if is_homograph:
        findings.append({
            "flag": True, "weight": 35,
            "category": "homograph",
            "text": f"IDN Homograph / Lookalike detected: {homograph_detail}"
        })
        structural_risk_score += 35

    # 8. Credential Harvesting Path Indicators
    path_lower = path.lower()
    matched_paths = [kw for kw in CREDENTIAL_PATHS if kw in path_lower]
    if matched_paths:
        findings.append({
            "flag": True, "weight": 10,
            "category": "credential_path",
            "text": f"URL path matches sensitive credential/auth keywords: {', '.join(matched_paths[:3])}"
        })
        structural_risk_score += 10

    # 9. Open Redirect Parameter Indicators
    query_lower = query.lower()
    matched_redirect_params = []
    for param in OPEN_REDIRECT_PARAMS:
        if f"{param}=" in query_lower:
            matched_redirect_params.append(param)

    if matched_redirect_params:
        findings.append({
            "flag": True, "weight": 15,
            "category": "open_redirect_param",
            "text": f"URL contains potential open redirect / target forwarding parameter(s): {', '.join(matched_redirect_params)}"
        })
        structural_risk_score += 15

    return {
        "url": url,
        "hostname": hostname,
        "domain": domain,
        "is_direct_ip": is_direct_ip,
        "is_shortener": is_shortener,
        "subdomain_depth": subdomain_depth,
        "findings": findings,
        "structural_score": min(structural_risk_score, 100),
    }
