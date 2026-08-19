"""
Brand Impersonation & Lookalike Detection Engine
------------------------------------------------
Detects brand spoofing in domain names, subdomains, email display names,
page titles, and credential harvesting forms.
"""

import re
from typing import Dict, Any, List, Optional, Tuple, Set

from core.url_analyzer import levenshtein_distance, is_keyboard_typo

# Brand Catalog with Known Legitimate Domains
BRAND_CATALOG: Dict[str, Dict[str, Any]] = {
    "microsoft": {
        "display_name": "Microsoft",
        "domains": ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com", "azure.com", "windows.net", "sharepoint.com"],
        "keywords": ["microsoft", "office365", "office 365", "outlook", "onedrive", "sharepoint", "azure", "windows live"],
        "category": "Technology / Cloud",
    },
    "google": {
        "display_name": "Google",
        "domains": ["google.com", "googlemail.com", "gmail.com", "google.co.uk", "google.ca", "workspace.google.com"],
        "keywords": ["google", "gmail", "google drive", "google docs", "google workspace", "google security"],
        "category": "Technology / Cloud",
    },
    "apple": {
        "display_name": "Apple",
        "domains": ["apple.com", "icloud.com", "itunes.com", "appleid.apple.com"],
        "keywords": ["apple", "icloud", "apple id", "itunes", "app store"],
        "category": "Consumer Tech",
    },
    "amazon": {
        "display_name": "Amazon",
        "domains": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "aws.amazon.com"],
        "keywords": ["amazon", "amazon prime", "aws", "amazon order"],
        "category": "E-Commerce / Cloud",
    },
    "paypal": {
        "display_name": "PayPal",
        "domains": ["paypal.com", "paypal.me"],
        "keywords": ["paypal", "paypal account", "paypal security"],
        "category": "Financial",
    },
    "meta": {
        "display_name": "Meta / Facebook / Instagram",
        "domains": ["facebook.com", "instagram.com", "meta.com", "whatsapp.com", "fb.com"],
        "keywords": ["facebook", "instagram", "meta", "whatsapp", "meta business"],
        "category": "Social Media",
    },
    "netflix": {
        "display_name": "Netflix",
        "domains": ["netflix.com"],
        "keywords": ["netflix", "netflix billing", "netflix account"],
        "category": "Entertainment",
    },
    "linkedin": {
        "display_name": "LinkedIn",
        "domains": ["linkedin.com", "licdn.com"],
        "keywords": ["linkedin", "linkedin security", "linkedin message"],
        "category": "Professional Network",
    },
    "github": {
        "display_name": "GitHub",
        "domains": ["github.com", "github.io"],
        "keywords": ["github", "github security", "github support"],
        "category": "Developer Platform",
    },
    "docusign": {
        "display_name": "DocuSign",
        "domains": ["docusign.com", "docusign.net"],
        "keywords": ["docusign", "document completed", "review document", "sign document"],
        "category": "Document Services",
    },
    "chase": {
        "display_name": "JPMorgan Chase",
        "domains": ["chase.com", "jpmorgan.com"],
        "keywords": ["chase", "chase bank", "jpmorgan", "chase security"],
        "category": "Banking",
    },
    "wellsfargo": {
        "display_name": "Wells Fargo",
        "domains": ["wellsfargo.com"],
        "keywords": ["wells fargo", "wellsfargo", "wells fargo banking"],
        "category": "Banking",
    },
    "bankofamerica": {
        "display_name": "Bank of America",
        "domains": ["bankofamerica.com", "bofa.com"],
        "keywords": ["bank of america", "bofa", "bank of america online"],
        "category": "Banking",
    },
    "americanexpress": {
        "display_name": "American Express",
        "domains": ["americanexpress.com", "amex.com"],
        "keywords": ["american express", "amex"],
        "category": "Financial",
    },
    "dhl": {
        "display_name": "DHL",
        "domains": ["dhl.com", "dhl.de"],
        "keywords": ["dhl", "dhl express", "dhl parcel", "dhl tracking"],
        "category": "Logistics",
    },
    "fedex": {
        "display_name": "FedEx",
        "domains": ["fedex.com"],
        "keywords": ["fedex", "fedex delivery", "fedex tracking"],
        "category": "Logistics",
    },
    "dropbox": {
        "display_name": "Dropbox",
        "domains": ["dropbox.com", "dropboxstatic.com"],
        "keywords": ["dropbox", "dropbox file", "dropbox share"],
        "category": "Cloud Storage",
    },
    "adobe": {
        "display_name": "Adobe",
        "domains": ["adobe.com"],
        "keywords": ["adobe", "adobe acrobat", "adobe sign", "adobe creative cloud"],
        "category": "Software",
    },
    "okta": {
        "display_name": "Okta",
        "domains": ["okta.com", "oktapreview.com"],
        "keywords": ["okta", "okta verify", "okta login"],
        "category": "Identity Provider",
    },
    "irs": {
        "display_name": "Internal Revenue Service (IRS)",
        "domains": ["irs.gov"],
        "keywords": ["irs", "internal revenue service", "tax refund", "irs notification"],
        "category": "Government",
    },
    "coinbase": {
        "display_name": "Coinbase",
        "domains": ["coinbase.com"],
        "keywords": ["coinbase", "coinbase wallet", "coinbase pro"],
        "category": "Cryptocurrency",
    },
    "binance": {
        "display_name": "Binance",
        "domains": ["binance.com"],
        "keywords": ["binance", "binance exchange"],
        "category": "Cryptocurrency",
    },
}

ALL_LEGITIMATE_DOMAINS: Set[str] = {dom for brand in BRAND_CATALOG.values() for dom in brand["domains"]}


def is_known_legitimate_domain(domain: str) -> bool:
    """Check if domain is an exact match for known legitimate infrastructure."""
    domain_clean = domain.lower().strip()
    return domain_clean in ALL_LEGITIMATE_DOMAINS


def match_brand_keywords(text: str) -> List[Tuple[str, str]]:
    """Search text for brand keyword matches with word boundaries."""
    if not text:
        return []
    hits = []
    text_lower = text.lower()
    for brand_key, data in BRAND_CATALOG.items():
        for kw in data["keywords"]:
            if re.search(r"\b" + re.escape(kw) + r"\b", text_lower):
                hits.append((brand_key, data["display_name"]))
                break
    return hits


def check_domain_brand_impersonation(domain: str, hostname: str = "") -> Optional[Dict[str, Any]]:
    """
    Check if a domain or hostname is a typosquat, lookalike, or nested subdomain
    of a known brand while hosted on unrelated infrastructure.
    """
    if not domain:
        return None

    domain_lower = domain.lower()
    hostname_lower = (hostname or domain).lower()

    # Exact legitimate match -> Not impersonation
    if is_known_legitimate_domain(domain_lower):
        return None

    base_domain = domain_lower.split(".")[0]

    for brand_key, data in BRAND_CATALOG.items():
        legit_domains = data["domains"]

        for legit in legit_domains:
            legit_base = legit.split(".")[0]

            # 1. Typosquat: Keyboard neighbor distance
            if is_keyboard_typo(base_domain, legit_base):
                return {
                    "brand_key": brand_key,
                    "brand_name": data["display_name"],
                    "legitimate_domain": legit,
                    "actual_domain": domain,
                    "similarity": "HIGH",
                    "technique": "Keyboard Neighbor Typosquatting",
                    "reason": f"'{domain}' is a keyboard-neighbor typosquat of legitimate domain '{legit}'"
                }

            # 2. Typosquat: Levenshtein distance of 1-2 on non-short names
            if base_domain != legit_base and len(legit_base) >= 4:
                dist = levenshtein_distance(base_domain, legit_base)
                if dist == 1:
                    return {
                        "brand_key": brand_key,
                        "brand_name": data["display_name"],
                        "legitimate_domain": legit,
                        "actual_domain": domain,
                        "similarity": "HIGH",
                        "technique": "Character Substitution / Insertion Lookalike",
                        "reason": f"'{domain}' is an edit-distance lookalike of legitimate domain '{legit}' (distance 1)"
                    }
                elif dist == 2 and len(legit_base) >= 7:
                    return {
                        "brand_key": brand_key,
                        "brand_name": data["display_name"],
                        "legitimate_domain": legit,
                        "actual_domain": domain,
                        "similarity": "MEDIUM",
                        "technique": "Multi-Character Lookalike",
                        "reason": f"'{domain}' is structurally similar to legitimate domain '{legit}'"
                    }

            # 3. Brand keyword combined with hyphen in registrable domain (e.g., paypal-verification.com)
            if "-" in domain_lower and legit_base in domain_lower.replace("-", ""):
                return {
                    "brand_key": brand_key,
                    "brand_name": data["display_name"],
                    "legitimate_domain": legit,
                    "actual_domain": domain,
                    "similarity": "HIGH",
                    "technique": "Combo-squatting / Brand Prepending",
                    "reason": f"Registrable domain '{domain}' combines brand '{data['display_name']}' with suspicious hyphens"
                }

        # 4. Brand name placed in subdomains of an unrelated domain (e.g. microsoft.com.login-verify.xyz)
        if hostname_lower != domain_lower:
            for legit in legit_domains:
                if legit in hostname_lower and not hostname_lower.endswith("." + legit):
                    return {
                        "brand_key": brand_key,
                        "brand_name": data["display_name"],
                        "legitimate_domain": legit,
                        "actual_domain": domain,
                        "actual_hostname": hostname_lower,
                        "similarity": "HIGH",
                        "technique": "Subdomain Brand Masquerading",
                        "reason": f"Hostname '{hostname_lower}' embeds brand '{legit}' in subdomains, but actual destination is '{domain}'"
                    }

    return None


def evaluate_page_impersonation(domain: str,
                                page_title: Optional[str],
                                has_password_field: bool,
                                form_count: int = 0) -> Optional[Dict[str, Any]]:
    """
    Evaluate if a live web page claims the identity of a known brand via its title
    and form while hosted on unrelated infrastructure.
    """
    if not domain or is_known_legitimate_domain(domain):
        return None

    if not page_title:
        return None

    title_matches = match_brand_keywords(page_title)
    if not title_matches:
        return None

    brand_key, brand_display = title_matches[0]
    brand_data = BRAND_CATALOG.get(brand_key, {})
    legit_domains = brand_data.get("domains", [])

    # Check if current domain is related to brand
    if any(domain == d or domain.endswith("." + d) for d in legit_domains):
        return None

    verdict_text = f"Live page titled \"{page_title}\" impersonates {brand_display} on unrelated domain '{domain}'"
    confidence = "HIGH" if has_password_field else "MEDIUM"
    if has_password_field:
        verdict_text += " with credential harvesting password form"

    return {
        "brand_key": brand_key,
        "brand_name": brand_display,
        "actual_domain": domain,
        "page_title": page_title,
        "has_password_field": has_password_field,
        "confidence": confidence,
        "verdict": verdict_text,
    }
