"""
Phishing Kit Fingerprinting & Infrastructure Signature Engine
--------------------------------------------------------------
Identifies recurring phishing kits and exfiltration signatures from
safe static inspection of HTML, form actions, scripts, and parameter structures.
"""

import re
from typing import Dict, Any, List, Optional

KNOWN_PHISHING_KIT_SIGNATURES = [
    {
        "name": "Telegram Bot Exfiltration Kit",
        "patterns": [r"api\.telegram\.org/bot", r"sendmessage\?chat_id=", r"sendMessage\?parse_mode="],
        "category": "Exfiltration Backend",
        "confidence": "HIGH"
    },
    {
        "name": "Discord Webhook Exfiltration Kit",
        "patterns": [r"discord\.com/api/webhooks/", r"discordapp\.com/api/webhooks/"],
        "category": "Exfiltration Backend",
        "confidence": "HIGH"
    },
    {
        "name": "16Shop Multi-Brand Phishing Kit",
        "patterns": [r"assets/js/16shop", r"16shop_antibot", r"/includes/16shop"],
        "category": "Turnkey Phishing Kit",
        "confidence": "HIGH"
    },
    {
        "name": "Generic PHP Form Stealer",
        "patterns": [r"action=['\"][^'\"]*(?:send_login|post_data|login_submit|next\.php|process\.php|save\.php)['\"]"],
        "category": "Credential Receiver",
        "confidence": "MEDIUM"
    },
    {
        "name": "Adversary-in-the-Middle (Evilginx / Muraena Lure)",
        "patterns": [r"login\.microsoftonline\.com\.[a-zA-Z0-9-]+\.", r"accounts\.google\.com\.[a-zA-Z0-9-]+\."],
        "category": "AiTM Reverse Proxy",
        "confidence": "HIGH"
    },
    {
        "name": "LogoKIT Dynamic Branding Lure",
        "patterns": [r"img\.logo\.dev", r"logo\.clearbit\.com", r"\.setLogo\("],
        "category": "Dynamic Phishing Kit",
        "confidence": "MEDIUM"
    }
]


def fingerprint_phishing_kit(html_content: str, form_actions: List[str]) -> List[Dict[str, Any]]:
    """
    Search HTML content and form actions for signature matches of known phishing kits.
    """
    matches = []
    if not html_content and not form_actions:
        return matches

    combined_text = (html_content or "") + " " + " ".join(form_actions)

    for kit in KNOWN_PHISHING_KIT_SIGNATURES:
        for pat in kit["patterns"]:
            if re.search(pat, combined_text, re.IGNORECASE):
                matches.append({
                    "kit_name": kit["name"],
                    "category": kit["category"],
                    "confidence": kit["confidence"],
                    "matched_signature": pat,
                    "text": f"Phishing Kit / Exfiltration signature detected: '{kit['name']}' ({kit['category']})"
                })
                break

    return matches
