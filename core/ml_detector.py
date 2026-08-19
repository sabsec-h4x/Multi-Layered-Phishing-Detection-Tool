"""
Optional Explainable Machine Learning Classifier Layer
------------------------------------------------------
Extracts interpretable forensic feature vectors and provides secondary
supervised classification without overriding deterministic rule evidence.
"""

from typing import Dict, Any, List, Optional, Tuple

FEATURE_NAMES = [
    "has_password_field",
    "has_typosquat_domain",
    "has_display_spoofing",
    "spf_failed",
    "dkim_failed",
    "dmarc_failed",
    "has_risky_attachment",
    "has_masqueraded_attachment",
    "has_shortener_url",
    "has_suspicious_tld",
    "has_open_redirect",
    "has_html_smuggling",
    "urgency_phrases_count",
    "credential_phrases_count",
    "total_urls_count",
]


def extract_forensic_features(analysis_data: Dict[str, Any]) -> Dict[str, float]:
    """
    Extract a normalized dictionary of interpretable numerical features for ML models.
    """
    headers = analysis_data.get("header_analysis", {})
    content = analysis_data.get("content_analysis", {})
    attachments = analysis_data.get("attachment_analysis", {})
    urls = analysis_data.get("url_analysis", [])
    modern = analysis_data.get("modern_threats", {})

    header_findings_text = " ".join(f.get("text", "") for f in headers.get("findings", []))
    content_findings_text = " ".join(f.get("text", "") for f in content.get("findings", []))
    attach_findings_text = " ".join(f.get("text", "") for f in attachments.get("findings", []))
    url_findings_text = " ".join(f.get("text", "") for u in urls for f in u.get("findings", []))

    features = {
        "has_password_field": 1.0 if any(u.get("page", {}).get("has_password_field") for u in urls) else 0.0,
        "has_typosquat_domain": 1.0 if "lookalike" in url_findings_text or "lookalike" in header_findings_text else 0.0,
        "has_display_spoofing": 1.0 if "impersonates" in header_findings_text else 0.0,
        "spf_failed": 1.0 if "SPF" in header_findings_text and "FAIL" in header_findings_text else 0.0,
        "dkim_failed": 1.0 if "DKIM" in header_findings_text and "FAIL" in header_findings_text else 0.0,
        "dmarc_failed": 1.0 if "DMARC" in header_findings_text and "FAIL" in header_findings_text else 0.0,
        "has_risky_attachment": 1.0 if bool(attachments.get("risky_attachments")) else 0.0,
        "has_masqueraded_attachment": 1.0 if "MASQUERADING" in attach_findings_text else 0.0,
        "has_shortener_url": 1.0 if any(u.get("is_shortener") for u in urls) else 0.0,
        "has_suspicious_tld": 1.0 if "High-abuse / suspicious TLD" in url_findings_text else 0.0,
        "has_open_redirect": 1.0 if "open redirect" in url_findings_text else 0.0,
        "has_html_smuggling": 1.0 if "HTML Smuggling" in str(modern) else 0.0,
        "urgency_phrases_count": float(content_findings_text.count("Urgency")),
        "credential_phrases_count": float(content_findings_text.count("credential")),
        "total_urls_count": float(len(urls)),
    }
    return features


def predict_ml_probability(features: Dict[str, float]) -> Dict[str, Any]:
    """
    Lightweight heuristic ensemble simulating trained logistic weights
    providing an explainable ML score (0.0 to 1.0) and top contributing features.
    """
    weights = {
        "has_password_field": 2.5,
        "has_typosquat_domain": 2.8,
        "has_display_spoofing": 2.2,
        "spf_failed": 1.8,
        "dkim_failed": 1.5,
        "dmarc_failed": 1.6,
        "has_risky_attachment": 2.6,
        "has_masqueraded_attachment": 3.5,
        "has_shortener_url": 1.2,
        "has_suspicious_tld": 1.4,
        "has_open_redirect": 1.3,
        "has_html_smuggling": 3.0,
        "urgency_phrases_count": 0.8,
        "credential_phrases_count": 1.5,
        "total_urls_count": 0.2,
    }

    raw_sum = sum(features.get(k, 0.0) * w for k, w in weights.items())
    # Logistic sigmoid
    import math
    try:
        prob = 1.0 / (1.0 + math.exp(-(raw_sum - 2.5)))
    except OverflowError:
        prob = 1.0 if raw_sum > 0 else 0.0

    contributions = [
        {"feature": k, "value": features.get(k, 0.0), "weight": w, "impact": round(features.get(k, 0.0) * w, 2)}
        for k, w in weights.items() if features.get(k, 0.0) > 0
    ]
    contributions.sort(key=lambda x: x["impact"], reverse=True)

    return {
        "probability_phishing": round(prob, 3),
        "predicted_class": "PHISHING" if prob >= 0.6 else ("SUSPICIOUS" if prob >= 0.35 else "CLEAN"),
        "top_features": contributions[:5],
        "is_available": True,
    }
