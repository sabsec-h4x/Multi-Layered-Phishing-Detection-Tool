"""
Explainable Categorized Risk Scoring Engine
-------------------------------------------
Calculates composite risk scores across 6 distinct forensic pillars:
Identity Risk, URL Risk, Content Risk, Attachment Risk, Threat Intel Risk, Behavioral Risk.
Provides structured positive/negative evidence, confidence ratings, and analyst recommendations.
"""

from typing import Dict, Any, List, Optional, Tuple


def calculate_url_aggregate_score(url_results: List[Dict[str, Any]]) -> int:
    """
    Prevent multiple URLs from artificially inflating the final score.
    Takes the highest URL score plus a dampened contribution from additional risky URLs.
    """
    if not url_results:
        return 0
    scores = sorted([u.get("score", 0) for u in url_results], reverse=True)
    if not scores or scores[0] == 0:
        return 0
    max_score = scores[0]
    secondary_sum = sum(s for s in scores[1:] if s > 0)
    aggregate = max_score + int(secondary_sum * 0.15)
    return min(aggregate, 100)


def determine_severity(score: int) -> str:
    """Map 0-100 risk score to SOC severity rating."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    elif score >= 15:
        return "LOW"
    return "INFO"


def determine_verdict(score: int, critical_override: bool = False) -> str:
    """Map score and critical overrides to triage verdict."""
    if critical_override or score >= 65:
        return "MALICIOUS" if score >= 85 else "PHISHING"
    elif score >= 30:
        return "SUSPICIOUS"
    return "CLEAN"


def determine_confidence(positive_signals_count: int,
                         negative_signals_count: int,
                         ti_available: bool,
                         auth_verified: bool) -> str:
    """Calculate analyst confidence rating based on available evidence density."""
    total_signals = positive_signals_count + negative_signals_count
    if total_signals >= 4 and (ti_available or auth_verified):
        return "VERY_HIGH"
    elif total_signals >= 3:
        return "HIGH"
    elif total_signals >= 1:
        return "MEDIUM"
    return "LOW"


def generate_analyst_recommendations(verdict: str,
                                     findings: List[Dict[str, Any]],
                                     has_attachments: bool,
                                     has_credentials_lure: bool) -> List[str]:
    """Generate prioritized, evidence-based SOC analyst playbooks and response actions."""
    recs = []
    if verdict in ("PHISHING", "MALICIOUS"):
        recs.append("1. Isolate and purge matching email message across tenant mailboxes (Search & Purge).")
        recs.append("2. Extract and block identified domain/URL/IP IOCs on perimeter firewall, proxy, and DNS sinkhole.")
        if has_credentials_lure:
            recs.append("3. Review user sign-in logs for targeted recipients; initiate password reset and revoke active session tokens if access is suspected.")
        if has_attachments:
            recs.append("4. Query EDR / SIEM telemetry for attachment SHA256 hashes on user endpoints.")
        recs.append("5. Submit suspicious URLs and attachment hashes to Threat Intelligence platforms for community tracking.")
    elif verdict == "SUSPICIOUS":
        recs.append("1. Contact sender via out-of-band channel (phone/Slack) to confirm message authenticity.")
        recs.append("2. Inspect destination landing pages in an isolated sandbox browser before permitting user access.")
        recs.append("3. Monitor recipient account for unusual authentication or email forwarding rules.")
    else:
        recs.append("1. Sender authentication and link reputation appear consistent with legitimate traffic.")
        recs.append("2. No further containment action required; close case as Benign / Clean.")

    return recs


def evaluate_composite_risk(header_analysis: Dict[str, Any],
                            content_analysis: Dict[str, Any],
                            attachment_analysis: Dict[str, Any],
                            url_analysis: List[Dict[str, Any]],
                            modern_threats: Dict[str, Any],
                            threat_intel_score: int = 0,
                            is_trusted_sender: bool = False,
                            auth_pass_all: bool = False) -> Dict[str, Any]:
    """
    Comprehensive multi-pillar risk evaluation engine.
    """
    identity_risk = header_analysis.get("header_score", 0)
    url_risk = calculate_url_aggregate_score(url_analysis)
    content_risk = content_analysis.get("score", 0)
    attachment_risk = attachment_analysis.get("score", 0)
    behavioral_risk = modern_threats.get("score", 0)
    ti_risk = min(threat_intel_score, 100)

    # Multi-Pillar Risk Aggregation:
    # The primary risk driver provides the baseline, while corroborating evidence from secondary pillars elevates the score.
    pillar_scores = [identity_risk, url_risk, attachment_risk, content_risk, behavioral_risk, ti_risk]
    sorted_pillars = sorted(pillar_scores, reverse=True)
    primary_pillar = sorted_pillars[0]
    secondary_corroboration = sum(s * 0.20 for s in sorted_pillars[1:])

    raw_composite = min(primary_pillar + secondary_corroboration, 100)

    # Hard Evidence Triggers (Critical Override Flags)
    has_credential_harvesting = any(
        "credential harvesting" in f.get("text", "").lower() or "password form" in f.get("text", "").lower()
        for u in url_analysis for f in u.get("findings", [])
    )
    has_masqueraded_attachment = any(
        "masquerading" in f.get("text", "").lower() or f.get("category") == "file_masquerading"
        for f in attachment_analysis.get("findings", [])
    )
    has_ti_malicious_hit = ti_risk >= 40

    critical_override = has_credential_harvesting or has_masqueraded_attachment or has_ti_malicious_hit

    # Trust Discount (applied only if sender is verified and no hard attack evidence exists)
    trust_discount = 0
    if is_trusted_sender and auth_pass_all and not critical_override:
        trust_discount = 45
    elif is_trusted_sender and not critical_override:
        trust_discount = 25

    final_score = max(0, int(raw_composite - trust_discount))
    if critical_override and final_score < 70:
        final_score = 75

    final_score = min(final_score, 100)

    # Compile positive and negative evidence
    positive_evidence = []
    negative_evidence = []
    suspicion_summary = []

    # Gather all findings
    all_findings = []
    all_findings.extend(header_analysis.get("findings", []))
    all_findings.extend(content_analysis.get("findings", []))
    all_findings.extend(attachment_analysis.get("findings", []))
    for u in url_analysis:
        all_findings.extend(u.get("findings", []))
    all_findings.extend(modern_threats.get("findings", []))

    for f in all_findings:
        flag = f.get("flag")
        text = f.get("text", "")
        if flag is True:
            negative_evidence.append(text)
            suspicion_summary.append(text)
        elif flag is False:
            positive_evidence.append(text)

    severity = determine_severity(final_score)
    verdict = determine_verdict(final_score, critical_override)
    confidence = determine_confidence(
        len(positive_evidence),
        len(negative_evidence),
        ti_risk > 0,
        auth_pass_all
    )

    recommendations = generate_analyst_recommendations(
        verdict,
        all_findings,
        has_attachments=bool(attachment_analysis.get("attachments")),
        has_credentials_lure=has_credential_harvesting
    )

    return {
        "final_score": final_score,
        "raw_score": int(raw_composite),
        "trust_discount": trust_discount,
        "severity": severity,
        "verdict": verdict,
        "confidence": confidence,
        "critical_override": critical_override,
        "risk_pillars": {
            "identity_risk": identity_risk,
            "url_risk": url_risk,
            "content_risk": content_risk,
            "attachment_risk": attachment_risk,
            "threat_intel_risk": ti_risk,
            "behavioral_risk": behavioral_risk,
        },
        "negative_evidence": negative_evidence,
        "positive_evidence": positive_evidence,
        "why_suspicious": suspicion_summary[:8],
        "recommendations": recommendations,
    }
