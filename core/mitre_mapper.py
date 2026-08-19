"""
Evidence-Grounded MITRE ATT&CK Mapping Engine
---------------------------------------------
Maps observed email forensic evidence directly to MITRE ATT&CK techniques,
differentiating between Observed, Potential, and Follow-on techniques.
"""

from typing import Dict, Any, List


def map_mitre_techniques(evidence: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Generate rigorous MITRE ATT&CK mappings based strictly on available evidence.
    """
    mappings = []

    has_attachments = evidence.get("has_risky_attachments", False)
    has_links = evidence.get("has_malicious_urls", False) or evidence.get("has_lookalike_urls", False)
    has_credential_form = evidence.get("has_credential_form", False)
    has_lookalike_domain = evidence.get("has_lookalike_domain", False)
    has_display_spoofing = evidence.get("has_display_spoofing", False)
    has_oauth_phishing = evidence.get("has_oauth_phishing", False)
    has_html_smuggling = evidence.get("has_html_smuggling", False)
    has_device_code = evidence.get("has_device_code", False)

    # 1. T1566.001 — Spearphishing Attachment
    if has_attachments:
        mappings.append({
            "id": "T1566.001",
            "name": "Phishing: Spearphishing Attachment",
            "tactic": "Initial Access",
            "status": "Observed",
            "confidence": "HIGH",
            "evidence": "Email contains high-risk, masqueraded, or executable attachment payload."
        })

    # 2. T1566.002 — Spearphishing Link
    if has_links or has_credential_form:
        mappings.append({
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "status": "Observed",
            "confidence": "HIGH",
            "evidence": "Email contains links directing recipients to external credential harvesting or lookalike landing pages."
        })

    # 3. T1598.003 — Phishing for Information: Spearphishing Link
    if has_credential_form or has_oauth_phishing or has_device_code:
        mappings.append({
            "id": "T1598.003",
            "name": "Phishing for Information: Spearphishing Link",
            "tactic": "Reconnaissance / Credential Access",
            "status": "Observed",
            "confidence": "HIGH",
            "evidence": "Destination page actively requests credentials or sensitive OAuth authorization scopes."
        })

    # 4. T1036.005 — Masquerading: Match Legitimate Name or Location
    if has_lookalike_domain or has_display_spoofing:
        mappings.append({
            "id": "T1036.005",
            "name": "Masquerading: Match Legitimate Name or Location",
            "tactic": "Defense Evasion",
            "status": "Observed",
            "confidence": "HIGH",
            "evidence": "Attacker utilizes typosquatted domain, brand prepending, or spoofed display name matching a trusted organization."
        })

    # 5. T1027.006 — HTML Smuggling
    if has_html_smuggling:
        mappings.append({
            "id": "T1027.006",
            "name": "Obfuscated Files or Information: HTML Smuggling",
            "tactic": "Defense Evasion",
            "status": "Observed",
            "confidence": "HIGH",
            "evidence": "Email or landing page contains JavaScript constructs (Blob / createObjectURL) to construct payload dynamically."
        })

    # 6. T1204.001 / T1204.002 — User Execution (Follow-on only)
    if has_links:
        mappings.append({
            "id": "T1204.001",
            "name": "User Execution: Malicious Link",
            "tactic": "Execution",
            "status": "Potential (Follow-on)",
            "confidence": "MEDIUM",
            "evidence": "Potential victim interaction with delivered spearphishing link."
        })

    if has_attachments:
        mappings.append({
            "id": "T1204.002",
            "name": "User Execution: Malicious File",
            "tactic": "Execution",
            "status": "Potential (Follow-on)",
            "confidence": "MEDIUM",
            "evidence": "Potential victim execution of delivered suspicious attachment payload."
        })

    return mappings
