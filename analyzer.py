"""
PhishGuard Core Forensic & Orchestration Engine
-----------------------------------------------
Integrates all specialized sub-engines (SSRF-safe client, header forensics,
received hop chain, attachment static inspection, brand impersonation,
modern threat detection, DNS/TLS intelligence, categorized risk scoring,
and grounded MITRE ATT&CK mapping).
"""

import re
import socket
import hashlib
import ipaddress
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser, Parser
from typing import Dict, Any, List, Optional, Tuple, Set
from bs4 import BeautifulSoup
import tldextract

from core.ssrf import safe_fetch_page, is_ip_blocked
from core.url_extractor import (
    extract_plain_text_urls,
    extract_html_links_and_resources,
    get_registrable_domain,
)
from core.url_analyzer import (
    analyze_url_structure,
    levenshtein_distance,
    is_keyboard_typo,
)
from core.brand_engine import (
    check_domain_brand_impersonation,
    evaluate_page_impersonation,
    is_known_legitimate_domain,
    match_brand_keywords,
    BRAND_CATALOG,
)
from core.header_forensics import analyze_email_headers
from core.received_chain import analyze_received_chain
from core.attachment_forensics import analyze_email_attachments
from core.modern_phishing import analyze_modern_threat_vectors
from core.dns_tls import inspect_tls_certificate, query_dns_records
from core.risk_engine import evaluate_composite_risk
from core.mitre_mapper import map_mitre_techniques
from core.ioc_extractor import extract_normalized_iocs
from core.phishing_kit_fingerprint import fingerprint_phishing_kit
from core.ml_detector import extract_forensic_features, predict_ml_probability
import threat_intel

_TLD = tldextract.TLDExtract(suffix_list_urls=())

# Reference Constants & Linguistic Signatures
URGENCY = [
    "act now", "immediately", "verify your account", "confirm your identity",
    "account will be suspended", "account has been suspended", "unusual activity",
    "within 24 hours", "failure to comply", "urgent action required",
    "account will be locked", "click here to avoid", "suspended within",
    "action required", "unauthorized login", "security alert"
]

SENSITIVE_PHRASES = [
    "enter your password", "confirm your password", "verify your password",
    "type your password", "submit your password", "provide your password",
    "email your password", "reply with your password", "send your password",
    "enter your pin", "confirm your pin", "enter your otp", "share your otp",
    "provide your ssn", "enter your social security", "enter your card number",
    "provide your cvv", "confirm your card details", "enter your routing number",
    "click below to login", "click here to login", "login here to verify",
    "update your billing information", "verify your identity"
]

BEC_PHRASES = [
    "wire transfer", "bank details", "payment details", "remit payment",
    "process the payment", "are you available right now", "treat as confidential",
    "update our banking information", "change of payment instructions",
    "direct deposit", "payroll update", "gift card", "vendor payment"
]

TRUSTED_DOMAINS = {
    "paypal.com", "microsoft.com", "apple.com", "amazon.com", "google.com",
    "chase.com", "wellsfargo.com", "netflix.com", "dhl.com", "fedex.com",
    "linkedin.com", "instagram.com", "facebook.com", "bankofamerica.com",
    "americanexpress.com", "office.com", "docusign.com", "github.com",
    "microsoftonline.com", "live.com", "outlook.com", "office365.com",
    "okta.com", "auth0.com", "cloudflare.com", "slack.com", "zoom.us",
    "atlassian.com", "oracle.com", "dropbox.com", "adobe.com"
}


# ----------------------------------------------------------------------------
# Backward Compatibility Wrappers
# ----------------------------------------------------------------------------
def levenshtein(a: str, b: str) -> int:
    return levenshtein_distance(a, b)


def registrable_domain(host: str) -> str:
    return get_registrable_domain(host)


def is_trusted_host(host: str) -> bool:
    if not host:
        return False
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS)


def check_typosquat(domain: str) -> Optional[str]:
    res = check_domain_brand_impersonation(domain)
    return res.get("legitimate_domain") if res else None


def check_ssl(hostname: str, port: int = 443) -> Dict[str, Any]:
    return inspect_tls_certificate(hostname, port)


def check_domain_age(domain: str) -> Dict[str, Any]:
    res = threat_intel.query_whois_age(domain)
    if res.get("available"):
        details = res.get("details", {})
        return {
            "available": True,
            "created": details.get("created"),
            "age_days": details.get("age_days"),
        }
    return {"available": False, "reason": res.get("reason", "Lookup failed")}


# ----------------------------------------------------------------------------
# Email Parsing & Extraction
# ----------------------------------------------------------------------------
def parse_email_bytes(raw_bytes: bytes):
    return BytesParser(policy=policy.default).parsebytes(raw_bytes)


def parse_email_text(raw_text: str):
    try:
        return Parser(policy=policy.default).parsestr(raw_text)
    except Exception:
        return None


def extract_body_text(msg) -> str:
    """Extract combined plain-text representation from message."""
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
            elif ctype == "text/html":
                try:
                    html_text = part.get_content()
                    soup = BeautifulSoup(html_text, "html.parser")
                    parts.append(soup.get_text(" "))
                except Exception:
                    pass
    else:
        try:
            content = msg.get_content()
            if msg.get_content_type() == "text/html":
                content = BeautifulSoup(content, "html.parser").get_text(" ")
            parts.append(content)
        except Exception:
            pass
    return "\n".join(parts)


def extract_raw_html(msg) -> str:
    """Extract raw HTML payload if present."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    return part.get_content()
                except Exception:
                    pass
    elif msg.get_content_type() == "text/html":
        try:
            return msg.get_content()
        except Exception:
            pass
    return ""


def extract_attachments(msg) -> Tuple[List[Dict[str, Any]], Dict[str, bytes]]:
    """Extract attachment metadata and in-memory byte payloads."""
    meta_list = []
    payload_map = {}
    if not msg.is_multipart():
        return meta_list, payload_map

    for part in msg.walk():
        disp = str(part.get("Content-Disposition") or "")
        filename = part.get_filename()
        if "attachment" in disp.lower() or filename:
            fn = filename or "unnamed_attachment"
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            sha256 = hashlib.sha256(payload).hexdigest() if payload else None
            meta_list.append({
                "filename": fn,
                "size": len(payload),
                "sha256": sha256,
            })
            payload_map[fn] = payload
    return meta_list, payload_map


def extract_urls(text: str) -> List[str]:
    return extract_plain_text_urls(text)


# ----------------------------------------------------------------------------
# Content Forensics
# ----------------------------------------------------------------------------
def analyze_content(text: str) -> Dict[str, Any]:
    """Analyze email body text for urgency, credential lures, and BEC patterns."""
    findings = []
    score = 0
    lower = text.lower()

    hit_urgency = [p for p in URGENCY if p in lower]
    if hit_urgency:
        w = min(len(hit_urgency), 3) * 8
        findings.append({
            "flag": True, "weight": w, "category": "urgency_language",
            "text": f"Urgency/pressure language: {', '.join(repr(h) for h in hit_urgency[:3])}"
        })
        score += w

    hit_sensitive = [s for s in SENSITIVE_PHRASES if s in lower]
    if hit_sensitive:
        w = min(len(hit_sensitive), 3) * 12
        findings.append({
            "flag": True, "weight": w, "category": "credential_request",
            "text": f"Actively requests credentials/authentication data: {', '.join(repr(h) for h in hit_sensitive[:3])}"
        })
        score += w

    hit_bec = [p for p in BEC_PHRASES if p in lower]
    if hit_bec:
        findings.append({
            "flag": True, "weight": 25, "category": "bec_phrase",
            "text": f"Business Email Compromise (BEC) / Wire Transfer phrase: '{hit_bec[0]}'"
        })
        score += 25

    if not hit_urgency and not hit_sensitive and not hit_bec:
        findings.append({
            "flag": False, "weight": 0, "category": "content_benign",
            "text": "No urgency, credential solicitation, or BEC financial pressure phrases detected"
        })

    return {"findings": findings, "score": min(score, 100)}


# ----------------------------------------------------------------------------
# Live Web Page Fetch & Forensics
# ----------------------------------------------------------------------------
def fetch_page(url: str) -> Dict[str, Any]:
    """
    Safely fetch a URL using SSRF-protected client and parse HTML signals.
    """
    fetch_res = safe_fetch_page(url)
    if not fetch_res["reachable"]:
        return {
            "reachable": False,
            "error": fetch_res["error"],
            "has_password_field": False,
            "brand_mentions_title": [],
            "brand_mentions_body": [],
            "title": None,
            "final_url": fetch_res.get("final_url", url),
            "redirect_count": fetch_res.get("redirect_count", 0),
            "redirect_chain": fetch_res.get("redirect_chain", []),
            "resolved_ips": fetch_res.get("resolved_ips", []),
            "meta_refresh": False,
            "form_count": 0,
            "phishing_kits": [],
        }

    html_content = fetch_res["content"]
    soup = BeautifulSoup(html_content, "html.parser")
    title = soup.title.get_text(strip=True) if soup.title else None
    page_text_lower = soup.get_text(" ").lower()

    forms = soup.find_all("form")
    form_actions = [f.get("action", "") for f in forms if f.get("action")]
    has_password_field = any(soup.find_all("input", {"type": "password"}))

    title_lower = (title or "").lower()
    brand_mentions_title = [b for b, name in match_brand_keywords(title_lower)]
    brand_mentions_body = [b for b, name in match_brand_keywords(page_text_lower)]

    meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})

    # Phishing kit fingerprinting
    kit_hits = fingerprint_phishing_kit(html_content, form_actions)

    return {
        "reachable": True,
        "status_code": fetch_res["status_code"],
        "final_url": fetch_res["final_url"],
        "redirect_count": fetch_res["redirect_count"],
        "redirect_chain": fetch_res["redirect_chain"],
        "resolved_ips": fetch_res["resolved_ips"],
        "title": title,
        "form_count": len(forms),
        "has_password_field": has_password_field,
        "brand_mentions_title": brand_mentions_title,
        "brand_mentions_body": brand_mentions_body,
        "meta_refresh": bool(meta_refresh),
        "phishing_kits": kit_hits,
        "error": None,
    }


# ----------------------------------------------------------------------------
# Full URL Analysis Pipeline
# ----------------------------------------------------------------------------
def analyze_url(url: str, link_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Comprehensive analysis of a single URL: structure, live SSRF-safe fetch,
    brand impersonation, TLS inspection, WHOIS age, DNS records, and Threat Intelligence.
    """
    findings = []
    score = 0

    # 1. Structural Analysis
    struct = analyze_url_structure(url)
    findings.extend(struct["findings"])
    score += struct["structural_score"]

    hostname = struct["hostname"]
    domain = struct["domain"]
    is_direct_ip = struct["is_direct_ip"]

    # 2. Display text mismatch (from HTML parser if provided)
    if link_meta and link_meta.get("is_mismatch"):
        findings.append({
            "flag": True, "weight": 35, "category": "anchor_mismatch",
            "text": link_meta["mismatch_details"]
        })
        score += 35

    if link_meta and link_meta.get("is_hidden"):
        findings.append({
            "flag": True, "weight": 20, "category": "hidden_link",
            "text": f"Hidden link detected via zero-opacity or hidden CSS styling: '{url}'"
        })
        score += 20

    # 3. Brand Typosquat / Subdomain Impersonation
    brand_squat = check_domain_brand_impersonation(domain, hostname) if not is_direct_ip else None
    if brand_squat:
        findings.append({
            "flag": True, "weight": 30, "category": "brand_impersonation",
            "text": brand_squat["reason"]
        })
        score += 30

    # 4. Live Safe Fetch
    page = fetch_page(url)

    if page["reachable"]:
        final_host = page["final_url"].replace("https://", "").replace("http://", "").split("/")[0]
        final_domain = get_registrable_domain(final_host)

        if final_host != hostname and not is_trusted_host(final_host):
            findings.append({
                "flag": True, "weight": 10, "category": "redirect_destination",
                "text": f"Redirects across hostnames: initial='{hostname}' -> final='{final_host}'"
            })
            score += 10

        # Page Brand Impersonation vs Credential Form
        page_impersonation = evaluate_page_impersonation(domain, page["title"], page["has_password_field"], page["form_count"])
        if page_impersonation:
            findings.append({
                "flag": True, "weight": 40, "category": "credential_harvesting",
                "text": page_impersonation["verdict"]
            })
            score += 40
        elif page["has_password_field"]:
            if is_trusted_host(domain):
                findings.append({
                    "flag": False, "weight": 0, "category": "trusted_login_form",
                    "text": f"Login password form detected on verified trusted domain: {domain}"
                })
            else:
                findings.append({
                    "flag": True, "weight": 15, "category": "unverified_login_form",
                    "text": f"Password login form hosted on unverified domain: '{domain}' (Title: \"{page['title'] or 'untitled'}\")"
                })
                score += 15

        # Phishing Kit Fingerprints
        for kit in page.get("phishing_kits", []):
            findings.append({
                "flag": True, "weight": 35, "category": "phishing_kit",
                "text": kit["text"]
            })
            score += 35

        # Meta refresh
        if page["meta_refresh"]:
            findings.append({
                "flag": True, "weight": 10, "category": "meta_refresh",
                "text": "Page uses client-side meta-refresh redirect technique"
            })
            score += 10
    else:
        findings.append({
            "flag": None, "weight": 0, "category": "live_fetch_skipped",
            "text": f"Live fetch result: {page['error']}"
        })

    # 5. TLS Certificate Inspection
    ssl_info = None
    if not is_direct_ip and (url.startswith("https://") or page.get("reachable")):
        ssl_info = inspect_tls_certificate(hostname)
        if not ssl_info["valid"]:
            findings.append({
                "flag": True, "weight": 15, "category": "tls_invalid",
                "text": f"TLS Certificate validation issue: {ssl_info.get('error')}"
            })
            score += 15
        elif ssl_info.get("is_expired"):
            findings.append({
                "flag": True, "weight": 15, "category": "tls_expired",
                "text": "TLS certificate is expired"
            })
            score += 15
        else:
            findings.append({
                "flag": False, "weight": 0, "category": "tls_valid",
                "text": f"Valid TLS certificate issued to {ssl_info.get('subject_cn')} by {ssl_info.get('issuer')}"
            })

    # 6. RDAP / WHOIS Domain Age
    age_info = threat_intel.query_whois_age(domain) if not is_direct_ip else {"available": False}
    if age_info.get("available"):
        details = age_info.get("details", {})
        age_days = details.get("age_days", 999)
        if age_days < 30:
            findings.append({
                "flag": True, "weight": 30, "category": "newly_registered_domain",
                "text": f"High-risk newly registered domain: created only {age_days} days ago ({details.get('created')})"
            })
            score += 30
        elif age_days < 90:
            findings.append({
                "flag": True, "weight": 20, "category": "new_domain",
                "text": f"Recently registered domain: {age_days} days old ({details.get('created')})"
            })
            score += 20
        else:
            findings.append({
                "flag": False, "weight": 0, "category": "established_domain",
                "text": f"Established domain registered {details.get('created')} ({age_days} days ago)"
            })

    # 7. VirusTotal Reputation
    vt = threat_intel.query_virustotal(url)
    if vt.get("available"):
        if vt.get("malicious", 0) >= 3:
            w = min(30 + vt["malicious"], 50)
            findings.append({
                "flag": True, "weight": w, "category": "virustotal_malicious",
                "text": f"VirusTotal Threat Intel: {vt['summary']}"
            })
            score += w
        elif vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0:
            findings.append({
                "flag": True, "weight": 15, "category": "virustotal_suspicious",
                "text": f"VirusTotal Threat Intel: {vt['summary']}"
            })
            score += 15
        else:
            findings.append({
                "flag": False, "weight": 0, "category": "virustotal_clean",
                "text": f"VirusTotal Threat Intel: 0/{vt.get('total_engines', 0)} engines flag URL"
            })

    # 8. URLScan.io Browser Sandbox
    urlscan = threat_intel.query_urlscan(url)
    if urlscan.get("available"):
        if urlscan.get("malicious"):
            findings.append({
                "flag": True, "weight": 35, "category": "urlscan_malicious",
                "text": f"URLScan.io sandbox confirmed malicious verdict: {urlscan.get('summary')}"
            })
            score += 35
        else:
            findings.append({
                "flag": False, "weight": 0, "category": "urlscan_clean",
                "text": f"URLScan.io sandbox: {urlscan.get('summary')}"
            })

    # URL Verdict
    if score >= 55:
        verdict = "MALICIOUS"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY LEGITIMATE"

    return {
        "url": url,
        "domain": domain,
        "hostname": hostname,
        "score": min(score, 100),
        "verdict": verdict,
        "findings": findings,
        "page": page,
        "ssl": ssl_info,
        "whois": age_info,
        "virustotal": vt,
        "urlscan": urlscan,
        "resolved_ips": page.get("resolved_ips", []),
    }


# ----------------------------------------------------------------------------
# Master Email Triage Pipeline
# ----------------------------------------------------------------------------
def analyze_email(msg) -> Dict[str, Any]:
    """
    Master Email Triage Entry Point.
    Executes full multi-stage forensic analysis across headers, Received chain,
    attachments, URLs, modern attack vectors, categorized risk scoring,
    MITRE ATT&CK mapping, and IOC normalization.
    """
    subject = msg.get("Subject", "(no subject)")
    body_text = extract_body_text(msg)
    raw_html = extract_raw_html(msg)

    # 1. Attachment extraction and safe inspection
    raw_attachments, payload_map = extract_attachments(msg)
    attachment_result = analyze_email_attachments(raw_attachments, payload_map)

    # 2. Header and Relay Hop Forensics
    header_result = analyze_email_headers(msg)
    received_chain_result = analyze_received_chain(msg)

    # 3. Content Analysis
    content_result = analyze_content(body_text)

    # 4. Deep HTML & URL Extraction
    html_data = extract_html_links_and_resources(raw_html) if raw_html else {"links": [], "all_urls": []}
    plain_urls = extract_plain_text_urls(body_text)

    # Build unique URL list with metadata mapping
    url_meta_map = {l["url"]: l for l in html_data.get("links", [])}
    combined_urls = []
    seen_urls = set()
    for u in html_data.get("all_urls", []) + plain_urls:
        if u not in seen_urls:
            seen_urls.add(u)
            combined_urls.append(u)

    # 5. URL Forensics Pipeline
    url_results = [analyze_url(u, url_meta_map.get(u)) for u in combined_urls]

    # 6. Modern Phishing Vector Detection (OAuth, Device Code, HTML Smuggling, ClickFix)
    modern_threats = analyze_modern_threat_vectors(body_text, raw_html, combined_urls)

    # 7. Sender Trust & Authentication Evaluation
    from_domain = header_result.get("from_reg_domain") or ""
    is_trusted_sender = is_trusted_host(from_domain)
    auth_results = header_result.get("auth_results", {})
    auth_pass_all = (
        auth_results.get("spf") == "pass" and
        auth_results.get("dkim") == "pass" and
        auth_results.get("dmarc") == "pass"
    )

    # 8. Threat Intel Aggregate Score
    ti_score = 0
    for u in url_results:
        vt = u.get("virustotal", {})
        if vt.get("available") and vt.get("malicious", 0) >= 3:
            ti_score += 45
        urlscan = u.get("urlscan", {})
        if urlscan.get("available") and urlscan.get("malicious"):
            ti_score += 40

    # 9. Categorized Risk Scoring
    risk_evaluation = evaluate_composite_risk(
        header_analysis=header_result,
        content_analysis=content_result,
        attachment_analysis=attachment_result,
        url_analysis=url_results,
        modern_threats=modern_threats,
        threat_intel_score=ti_score,
        is_trusted_sender=is_trusted_sender,
        auth_pass_all=auth_pass_all,
    )

    # 10. MITRE ATT&CK Mapping
    evidence_flags = {
        "has_risky_attachments": bool(attachment_result.get("risky_attachments")),
        "has_malicious_urls": any(u["verdict"] in ("MALICIOUS", "PHISHING") for u in url_results),
        "has_lookalike_urls": any("lookalike" in f.get("text", "").lower() for u in url_results for f in u.get("findings", [])),
        "has_credential_form": any(u.get("page", {}).get("has_password_field") for u in url_results if u.get("page")),
        "has_lookalike_domain": any("lookalike" in f.get("text", "").lower() for f in header_result.get("findings", [])),
        "has_display_spoofing": any("impersonates" in f.get("text", "").lower() for f in header_result.get("findings", [])),
        "has_oauth_phishing": any(f.get("category") == "oauth_phishing" for f in modern_threats.get("findings", [])),
        "has_html_smuggling": any(f.get("category") == "html_smuggling" for f in modern_threats.get("findings", [])),
        "has_device_code": any(f.get("category") == "device_code_phishing" for f in modern_threats.get("findings", [])),
    }
    mitre_mappings = map_mitre_techniques(evidence_flags)

    # 11. Legacy Compatible and Normalized IOC extraction
    legacy_domains = sorted(list(set(u["domain"] for u in url_results if u.get("domain"))))
    legacy_hashes = [a["sha256"] for a in attachment_result.get("attachments", []) if a.get("sha256")]

    partial_result = {
        "subject": subject,
        "from_addr": header_result.get("from_addr"),
        "score": risk_evaluation["final_score"],
        "raw_score": risk_evaluation["raw_score"],
        "trust_discount": risk_evaluation["trust_discount"],
        "severity": risk_evaluation["severity"],
        "verdict": risk_evaluation["verdict"],
        "confidence": risk_evaluation["confidence"],
        "header_analysis": header_result,
        "received_chain": received_chain_result,
        "content_analysis": content_result,
        "attachment_analysis": attachment_result,
        "url_analysis": url_results,
        "modern_threats": modern_threats,
        "risk_pillars": risk_evaluation["risk_pillars"],
        "why_suspicious": risk_evaluation["why_suspicious"],
        "recommendations": risk_evaluation["recommendations"],
        "mitre": mitre_mappings,
        "iocs": {"domains": legacy_domains, "hashes": legacy_hashes},
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }

    # Extract full normalized IOC list
    full_iocs = extract_normalized_iocs(partial_result)
    partial_result["normalized_iocs"] = full_iocs

    # 12. Optional Explainable ML Prediction
    features = extract_forensic_features(partial_result)
    ml_res = predict_ml_probability(features)
    partial_result["ml_prediction"] = ml_res

    return partial_result


def analyze_headers(msg) -> Dict[str, Any]:
    return analyze_email_headers(msg)


def analyze_attachments(attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
    return analyze_email_attachments(attachments)
