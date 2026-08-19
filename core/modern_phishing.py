"""
Modern Phishing Vectors & Evasion Detection Engine
--------------------------------------------------
Detects OAuth consent phishing, device-code abuse, QR-code phishing (quishing),
HTML smuggling, fake CAPTCHA flows, and credential harvesting lures.
"""

import re
import urllib.parse
from typing import Dict, Any, List, Optional, Set

# High-Risk OAuth Scopes
DANGEROUS_OAUTH_SCOPES = [
    "mail.readwrite", "mail.readwrite.all", "mail.send",
    "files.readwrite.all", "files.readwrite", "contacts.readwrite",
    "user.readwrite.all", "directory.readwrite.all", "offline_access",
    "https://mail.google.com/", "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send", "full_access"
]

# Device Code Phishing Endpoints
DEVICE_CODE_ENDPOINTS = [
    "microsoft.com/devicelogin",
    "login.microsoftonline.com/common/oauth2/deviceauth",
    "google.com/device",
]

# HTML Smuggling Signatures in HTML / JS scripts
HTML_SMUGGLING_PATTERNS = [
    (r"URL\.createObjectURL\s*\(", "URL.createObjectURL blob execution"),
    (r"new\s+Blob\s*\(", "JavaScript in-memory Blob payload construction"),
    (r"atob\s*\(", "Base64 payload decoding via atob()"),
    (r"window\.navigator\.msSaveOrOpenBlob", "msSaveOrOpenBlob file drop"),
    (r"\.setAttribute\s*\(\s*['\"]download['\"]", "Dynamic download attribute attachment smuggling"),
    (r"document\.createElement\s*\(\s*['\"]a['\"]\s*\).*\.click\s*\(", "Dynamic anchor click auto-download"),
]

# Fake CAPTCHA / Paste-Command Lure Patterns (ClickFix / PowerShell lure)
FAKE_CAPTCHA_LURES = [
    "press windows key + r", "press win + r", "paste the command into the run dialog",
    "verify you are human by pasting", "ctrl + v and press enter", "powershell -enc",
    "powershell.exe -w hidden"
]


def detect_oauth_consent_phishing(url: str) -> Optional[Dict[str, Any]]:
    """
    Inspect a URL for OAuth authorization parameters and sensitive scope requests.
    """
    if not url:
        return None

    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)

    is_auth_endpoint = any(p in parsed.path.lower() for p in ["/oauth2/v2.0/authorize", "/oauth/authorize", "/auth", "/login/oauth"])

    scope_val = query_params.get("scope", [""])[0].lower()
    client_id = query_params.get("client_id", [""])[0]
    redirect_uri = query_params.get("redirect_uri", [""])[0]

    requested_dangerous_scopes = []
    if scope_val:
        for s in DANGEROUS_OAUTH_SCOPES:
            if s in scope_val:
                requested_dangerous_scopes.append(s)

    if is_auth_endpoint or requested_dangerous_scopes:
        return {
            "is_oauth": True,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "dangerous_scopes": requested_dangerous_scopes,
            "evidence_type": "Observed" if requested_dangerous_scopes else "Potential",
            "text": f"OAuth Consent Flow requesting high-risk permissions: {', '.join(requested_dangerous_scopes)}" if requested_dangerous_scopes else "OAuth Authorization Endpoint detected",
        }

    return None


def detect_device_code_phishing(text: str, urls: List[str]) -> Optional[Dict[str, Any]]:
    """
    Detect Device Code Phishing attacks where victims are asked to visit
    legitimate /devicelogin portals and enter attacker-controlled codes.
    """
    lower_text = text.lower()
    has_endpoint = any(ep in lower_text or any(ep in u.lower() for u in urls) for ep in DEVICE_CODE_ENDPOINTS)

    # Check for user_code pattern (typically 8-9 alphanumeric characters)
    code_match = re.search(r'\b([A-Z0-9]{8,9})\b', text)

    if has_endpoint:
        return {
            "technique": "Device Code Phishing",
            "evidence_type": "Observed" if code_match else "Potential",
            "user_code": code_match.group(1) if code_match else None,
            "text": f"Device Code Phishing lure detected (directs user to /devicelogin with code '{code_match.group(1) if code_match else 'unspecified'}')"
        }

    return None


def detect_html_smuggling(html_content: str) -> List[Dict[str, Any]]:
    """
    Scan HTML content and embedded scripts for HTML Smuggling techniques.
    """
    if not html_content:
        return []

    smuggling_findings = []
    for pattern, description in HTML_SMUGGLING_PATTERNS:
        if re.search(pattern, html_content, re.IGNORECASE):
            smuggling_findings.append({
                "technique": "HTML Smuggling (T1027.006)",
                "evidence_type": "Observed",
                "description": description,
                "text": f"HTML Smuggling indicator detected: {description}"
            })

    return smuggling_findings


def detect_fake_captcha_lures(text: str) -> Optional[Dict[str, Any]]:
    """
    Detect fake human verification / ClickFix clipboard execution lures.
    """
    lower = text.lower()
    for lure in FAKE_CAPTCHA_LURES:
        if lure in lower:
            return {
                "technique": "Fake CAPTCHA / Clipboard Command Lure",
                "evidence_type": "Observed",
                "text": f"Fake CAPTCHA / Terminal execution lure detected: matching '{lure}'"
            }
    return None


def analyze_modern_threat_vectors(email_text: str,
                                   html_content: str,
                                   urls: List[str]) -> Dict[str, Any]:
    """
    Orchestrate modern phishing detection across OAuth, device-code, HTML smuggling, and fake CAPTCHAs.
    """
    findings = []
    threat_score = 0

    # 1. OAuth consent checks
    for u in urls:
        oauth_data = detect_oauth_consent_phishing(u)
        if oauth_data and oauth_data.get("dangerous_scopes"):
            findings.append({
                "flag": True, "weight": 35,
                "category": "oauth_phishing",
                "evidence_type": oauth_data["evidence_type"],
                "text": oauth_data["text"]
            })
            threat_score += 35

    # 2. Device Code check
    device_data = detect_device_code_phishing(email_text, urls)
    if device_data:
        findings.append({
            "flag": True, "weight": 30,
            "category": "device_code_phishing",
            "evidence_type": device_data["evidence_type"],
            "text": device_data["text"]
        })
        threat_score += 30

    # 3. HTML Smuggling checks
    smuggling_hits = detect_html_smuggling(html_content)
    for sm in smuggling_hits:
        findings.append({
            "flag": True, "weight": 35,
            "category": "html_smuggling",
            "evidence_type": sm["evidence_type"],
            "text": sm["text"]
        })
        threat_score += 35

    # 4. Fake CAPTCHA / ClickFix checks
    captcha_hit = detect_fake_captcha_lures(email_text)
    if captcha_hit:
        findings.append({
            "flag": True, "weight": 40,
            "category": "fake_captcha_lure",
            "evidence_type": captcha_hit["evidence_type"],
            "text": captcha_hit["text"]
        })
        threat_score += 40

    return {
        "findings": findings,
        "score": min(threat_score, 100),
    }
