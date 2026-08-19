"""
HTML URL Extraction & Link Forensics
-----------------------------------
Extracts URLs from plain text and rich HTML content, detects anchor text
mismatches, hidden links, suspicious schemes, and entity obfuscations.
"""

import re
import html
import urllib.parse
from typing import List, Dict, Any, Set, Tuple
from bs4 import BeautifulSoup
import tldextract

_TLD = tldextract.TLDExtract(suffix_list_urls=())

DANGEROUS_SCHEMES = {"javascript:", "data:", "vbscript:", "file:", "blob:", "about:"}
URL_REGEX = re.compile(r'https?://[^\s)>\]"\'<]+', re.IGNORECASE)
DOMAIN_LIKE_REGEX = re.compile(r'^(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?::\d+)?)(?:[/?#].*)?$', re.IGNORECASE)


def get_registrable_domain(host: str) -> str:
    """Extract registrable domain (eTLD+1) using tldextract."""
    if not host:
        return ""
    host_clean = host.split("@")[-1].split(":")[0].strip().lower()
    ext = _TLD(host_clean)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or host_clean


def extract_plain_text_urls(text: str) -> List[str]:
    """Extract and normalize all URLs found in plain text."""
    if not text:
        return []
    raw_urls = URL_REGEX.findall(text)
    cleaned = []
    seen = set()
    for u in raw_urls:
        u_clean = u.rstrip(".,;:!?'\")>]}")
        if u_clean and u_clean not in seen:
            seen.add(u_clean)
            cleaned.append(u_clean)
    return cleaned


def decode_html_url(raw_url: str) -> str:
    """Unescape HTML entities and strip control whitespace."""
    if not raw_url:
        return ""
    unescaped = html.unescape(raw_url).strip()
    unescaped = re.sub(r'[\r\n\t]+', '', unescaped)
    return unescaped


def extract_html_links_and_resources(html_content: str) -> Dict[str, Any]:
    """
    Parse HTML content to extract:
    - <a> anchor links with display text, href, mismatch detection, and hidden link flags
    - <img>, <form>, <iframe>, <script>, <embed>, <object> URLs
    - Suspicious protocol occurrences (javascript:, data:)
    """
    links: List[Dict[str, Any]] = []
    form_actions: List[Dict[str, Any]] = []
    iframe_sources: List[str] = []
    image_sources: List[str] = []
    suspicious_schemes: List[Dict[str, str]] = []
    all_extracted_urls: Set[str] = set()

    if not html_content:
        return {
            "links": [], "form_actions": [], "iframe_sources": [],
            "image_sources": [], "suspicious_schemes": [], "all_urls": []
        }

    soup = BeautifulSoup(html_content, "html.parser")

    # 1. Parse Anchor <a> tags
    for a_tag in soup.find_all("a"):
        raw_href = a_tag.get("href", "")
        if not raw_href:
            continue

        href = decode_html_url(raw_href)
        display_text = a_tag.get_text(separator=" ", strip=True)

        # Check for dangerous non-HTTP schemes
        lower_href = href.lower()
        for scheme in DANGEROUS_SCHEMES:
            if lower_href.startswith(scheme):
                suspicious_schemes.append({"scheme": scheme, "content": href[:120], "tag": "a"})

        # Only process HTTP/HTTPS links for structural network forensics
        if not (lower_href.startswith("http://") or lower_href.startswith("https://")):
            continue

        all_extracted_urls.add(href)

        # Check for hidden link CSS styles
        style = (a_tag.get("style") or "").lower()
        is_hidden = any(h in style for h in [
            "display:none", "display: none",
            "visibility:hidden", "visibility: hidden",
            "opacity:0", "opacity: 0",
            "font-size:0", "font-size: 0",
            "width:0", "height:0", "position:absolute;left:-9999px"
        ])

        # Parse destination hostname and domain
        parsed_dest = urllib.parse.urlparse(href)
        dest_host = parsed_dest.hostname or ""
        dest_domain = get_registrable_domain(dest_host)

        # Display text vs Destination mismatch detection
        display_domain = None
        is_mismatch = False
        mismatch_details = None

        m = DOMAIN_LIKE_REGEX.match(display_text.strip())
        if m:
            claimed_host = m.group(1).lower()
            claimed_domain = get_registrable_domain(claimed_host)
            display_domain = claimed_domain

            if claimed_domain and dest_domain and claimed_domain != dest_domain:
                is_mismatch = True
                mismatch_details = (
                    f"Anchor text displays '{display_text}' (domain: {claimed_domain}) "
                    f"but redirects to completely different domain: '{dest_domain}' ({href})"
                )

        links.append({
            "original_href": raw_href,
            "url": href,
            "display_text": display_text,
            "hostname": dest_host,
            "registrable_domain": dest_domain,
            "display_domain": display_domain,
            "is_mismatch": is_mismatch,
            "mismatch_details": mismatch_details,
            "is_hidden": is_hidden,
            "target": a_tag.get("target"),
        })

    # 2. Parse Form actions
    for form in soup.find_all("form"):
        action = decode_html_url(form.get("action", ""))
        method = (form.get("method") or "GET").upper()
        inputs = [inp.get("type", "text").lower() for inp in form.find_all("input")]
        has_password = "password" in inputs

        if action.startswith("http://") or action.startswith("https://"):
            all_extracted_urls.add(action)

        form_actions.append({
            "action": action,
            "method": method,
            "has_password": has_password,
            "input_count": len(inputs),
        })

    # 3. Parse Iframes
    for iframe in soup.find_all("iframe"):
        src = decode_html_url(iframe.get("src", ""))
        if src:
            iframe_sources.append(src)
            if src.startswith("http://") or src.startswith("https://"):
                all_extracted_urls.add(src)

    # 4. Parse Images
    for img in soup.find_all("img"):
        src = decode_html_url(img.get("src", ""))
        if src:
            image_sources.append(src)
            if src.startswith("http://") or src.startswith("https://"):
                all_extracted_urls.add(src)

    # 5. Parse plain text inside HTML for unlinked raw URLs
    body_text = soup.get_text(separator=" ", strip=True)
    plain_urls = extract_plain_text_urls(body_text)
    for u in plain_urls:
        all_extracted_urls.add(u)

    return {
        "links": links,
        "form_actions": form_actions,
        "iframe_sources": iframe_sources,
        "image_sources": image_sources,
        "suspicious_schemes": suspicious_schemes,
        "all_urls": sorted(list(all_extracted_urls)),
    }
