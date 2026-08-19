"""
Email Header Forensics & Authentication Analysis
------------------------------------------------
Performs deep RFC-5322 header inspection, mismatch detection,
and RFC-7489 SPF/DKIM/DMARC/ARC authentication and alignment verification.
"""

import re
import email.utils
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from core.url_extractor import get_registrable_domain
from core.brand_engine import check_domain_brand_impersonation, match_brand_keywords


def parse_address_field(header_val: str) -> Tuple[str, str, str]:
    """
    Parse an email address header into (display_name, email_address, domain).
    """
    if not header_val:
        return "", "", ""
    realname, address = email.utils.parseaddr(header_val)
    domain = address.split("@")[-1].lower().strip() if "@" in address else ""
    return realname.strip(), address.strip(), domain


def parse_authentication_results(auth_header: str) -> Dict[str, str]:
    """Extract SPF, DKIM, DMARC, and ARC results from Authentication-Results header."""
    results = {}
    if not auth_header:
        return results

    for proto in ["spf", "dkim", "dmarc", "arc"]:
        match = re.search(rf"\b{proto}=([a-zA-Z0-9_-]+)", auth_header, re.IGNORECASE)
        if match:
            results[proto] = match.group(1).lower()

    return results


def analyze_email_headers(msg: Any) -> Dict[str, Any]:
    """
    Full forensic pipeline for email headers.
    Returns findings, authentication status, domain alignments, and header risk score.
    """
    findings = []
    header_risk_score = 0

    from_raw = msg.get("From", "")
    reply_to_raw = msg.get("Reply-To", "")
    return_path_raw = msg.get("Return-Path", "")
    sender_raw = msg.get("Sender", "")
    msg_id_raw = msg.get("Message-ID", "")
    date_raw = msg.get("Date", "")
    auth_results_raw = msg.get("Authentication-Results", "") or ""
    received_spf_raw = msg.get("Received-SPF", "") or ""
    arc_auth_raw = msg.get("ARC-Authentication-Results", "") or ""

    from_name, from_addr, from_domain = parse_address_field(from_raw)
    from_reg_domain = get_registrable_domain(from_domain)

    reply_name, reply_addr, reply_domain = parse_address_field(reply_to_raw)
    reply_reg_domain = get_registrable_domain(reply_domain)

    return_name, return_addr, return_domain = parse_address_field(return_path_raw)
    return_reg_domain = get_registrable_domain(return_domain)

    # 1. From Display Name Brand Impersonation
    if from_name:
        brand_matches = match_brand_keywords(from_name)
        if brand_matches:
            brand_key, brand_display = brand_matches[0]
            # If the display name claims a brand, but the From domain does not contain it
            if from_domain and brand_key.replace(" ", "") not in from_domain:
                findings.append({
                    "flag": True, "weight": 25,
                    "category": "display_name_spoofing",
                    "text": f"Display name impersonates '{brand_display}' but From domain is '{from_domain}'"
                })
                header_risk_score += 25

    # 2. Lookalike / Typosquatted From Domain
    if from_domain:
        squat_info = check_domain_brand_impersonation(from_reg_domain, from_domain)
        if squat_info:
            findings.append({
                "flag": True, "weight": 30,
                "category": "sender_domain_lookalike",
                "text": f"Sender domain '{from_domain}' is a {squat_info['technique']} of '{squat_info['legitimate_domain']}'"
            })
            header_risk_score += 30
        else:
            findings.append({
                "flag": False, "weight": 0,
                "category": "sender_domain",
                "text": f"Sender domain: {from_domain}"
            })

    # 3. From vs Reply-To Mismatch
    if reply_domain and from_domain:
        if reply_reg_domain != from_reg_domain:
            findings.append({
                "flag": True, "weight": 20,
                "category": "reply_to_mismatch",
                "text": f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}' (replies route elsewhere)"
            })
            header_risk_score += 20

    # 4. From vs Return-Path (Envelope Sender) Mismatch
    if return_domain and from_domain:
        if return_reg_domain != from_reg_domain:
            findings.append({
                "flag": True, "weight": 15,
                "category": "return_path_mismatch",
                "text": f"Return-Path (envelope sender) domain '{return_domain}' differs from From domain '{from_domain}'"
            })
            header_risk_score += 15

    # 5. Message-ID Validation
    if msg_id_raw:
        msg_id_clean = msg_id_raw.strip()
        if not (msg_id_clean.startswith("<") and msg_id_clean.endswith(">")):
            findings.append({
                "flag": True, "weight": 10,
                "category": "malformed_message_id",
                "text": f"Malformed Message-ID format (missing standard RFC angle brackets): '{msg_id_clean[:60]}'"
            })
            header_risk_score += 10
        else:
            msg_id_domain = msg_id_clean.strip("<>").split("@")[-1].lower() if "@" in msg_id_clean else ""
            msg_id_reg_domain = get_registrable_domain(msg_id_domain)
            if from_reg_domain and msg_id_reg_domain and from_reg_domain != msg_id_reg_domain:
                findings.append({
                    "flag": True, "weight": 10,
                    "category": "message_id_domain_mismatch",
                    "text": f"Message-ID domain '{msg_id_domain}' does not align with sender domain '{from_domain}'"
                })
                header_risk_score += 10
    else:
        findings.append({
            "flag": True, "weight": 15,
            "category": "missing_message_id",
            "text": "Message-ID header is missing completely"
        })
        header_risk_score += 15

    # 6. Timestamp Skew Inspection
    if date_raw:
        try:
            parsed_date = email.utils.parsedate_to_datetime(date_raw)
            now_utc = datetime.now(timezone.utc)
            if parsed_date > now_utc:
                skew_hours = (parsed_date - now_utc).total_seconds() / 3600
                if skew_hours > 2:
                    findings.append({
                        "flag": True, "weight": 10,
                        "category": "future_date_skew",
                        "text": f"Message date is in the future: {parsed_date.isoformat()} (skew: +{skew_hours:.1f} hours)"
                    })
                    header_risk_score += 10
        except Exception:
            findings.append({
                "flag": True, "weight": 10,
                "category": "malformed_date",
                "text": f"Malformed Date header format: '{date_raw}'"
            })
            header_risk_score += 10

    # 7. Authentication Protocols & Alignment
    auth_parsed = parse_authentication_results(auth_results_raw)
    if not auth_parsed and arc_auth_raw:
        auth_parsed = parse_authentication_results(arc_auth_raw)

    spf_verdict = auth_parsed.get("spf")
    dkim_verdict = auth_parsed.get("dkim")
    dmarc_verdict = auth_parsed.get("dmarc")
    arc_verdict = auth_parsed.get("arc")

    if not auth_parsed and received_spf_raw:
        if "pass" in received_spf_raw.lower():
            spf_verdict = "pass"
        elif "fail" in received_spf_raw.lower():
            spf_verdict = "fail"
        elif "softfail" in received_spf_raw.lower():
            spf_verdict = "softfail"

    # Evaluate SPF
    if spf_verdict == "fail":
        findings.append({"flag": True, "weight": 25, "category": "spf_fail", "text": "SPF authentication: FAIL (sender IP not authorized)"})
        header_risk_score += 25
    elif spf_verdict == "softfail":
        findings.append({"flag": True, "weight": 15, "category": "spf_softfail", "text": "SPF authentication: SOFTFAIL (IP doubtful authorization)"})
        header_risk_score += 15
    elif spf_verdict == "pass":
        findings.append({"flag": False, "weight": 0, "category": "spf_pass", "text": "SPF authentication: pass"})
    elif spf_verdict:
        findings.append({"flag": None, "weight": 0, "category": "spf_neutral", "text": f"SPF authentication: {spf_verdict}"})

    # Evaluate DKIM
    if dkim_verdict == "fail":
        findings.append({"flag": True, "weight": 25, "category": "dkim_fail", "text": "DKIM cryptographic signature verification: FAIL"})
        header_risk_score += 25
    elif dkim_verdict == "pass":
        findings.append({"flag": False, "weight": 0, "category": "dkim_pass", "text": "DKIM cryptographic signature verification: pass"})
    elif dkim_verdict:
        findings.append({"flag": None, "weight": 0, "category": "dkim_neutral", "text": f"DKIM verification: {dkim_verdict}"})

    # Evaluate DMARC
    if dmarc_verdict == "fail":
        findings.append({"flag": True, "weight": 25, "category": "dmarc_fail", "text": "DMARC policy enforcement: FAIL (SPF/DKIM alignment violated)"})
        header_risk_score += 25
    elif dmarc_verdict == "pass":
        findings.append({"flag": False, "weight": 0, "category": "dmarc_pass", "text": "DMARC policy enforcement: pass"})
    elif dmarc_verdict:
        findings.append({"flag": None, "weight": 0, "category": "dmarc_neutral", "text": f"DMARC policy: {dmarc_verdict}"})

    if not auth_parsed and not received_spf_raw:
        findings.append({
            "flag": None, "weight": 0,
            "category": "auth_missing",
            "text": "No Authentication-Results or Received-SPF headers present in message"
        })

    return {
        "from_addr": from_addr,
        "from_name": from_name,
        "from_domain": from_domain,
        "from_reg_domain": from_reg_domain,
        "reply_to_addr": reply_addr,
        "return_path_addr": return_addr,
        "message_id": msg_id_raw,
        "date": date_raw,
        "auth_results": {
            "spf": spf_verdict,
            "dkim": dkim_verdict,
            "dmarc": dmarc_verdict,
            "arc": arc_verdict,
        },
        "findings": findings,
        "header_score": min(header_risk_score, 100),
    }
