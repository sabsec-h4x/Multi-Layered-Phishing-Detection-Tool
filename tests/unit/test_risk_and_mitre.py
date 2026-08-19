"""Unit tests for Risk Engine, MITRE ATT&CK Mapping, and IOC Extraction."""

from core.risk_engine import determine_severity, determine_verdict, calculate_url_aggregate_score
from core.mitre_mapper import map_mitre_techniques
from core.modern_phishing import detect_oauth_consent_phishing, detect_html_smuggling


def test_url_aggregate_score_damping():
    urls = [
        {"score": 80},
        {"score": 20},
        {"score": 10},
    ]
    agg = calculate_url_aggregate_score(urls)
    # Highest score 80 + damped contribution (30 * 0.15 = 4) = 84, not 110
    assert agg == 84


def test_severity_and_verdict_mapping():
    assert determine_severity(90) == "CRITICAL"
    assert determine_severity(70) == "HIGH"
    assert determine_severity(40) == "MEDIUM"
    assert determine_severity(10) == "INFO"

    assert determine_verdict(90) == "MALICIOUS"
    assert determine_verdict(70) == "PHISHING"
    assert determine_verdict(40) == "SUSPICIOUS"
    assert determine_verdict(10) == "CLEAN"


def test_mitre_attack_mapping():
    evidence = {
        "has_risky_attachments": True,
        "has_malicious_urls": True,
        "has_credential_form": True,
        "has_lookalike_domain": True,
    }
    mappings = map_mitre_techniques(evidence)
    ids = [m["id"] for m in mappings]
    assert "T1566.001" in ids
    assert "T1566.002" in ids
    assert "T1598.003" in ids
    assert "T1036.005" in ids


def test_oauth_and_smuggling_detection():
    oauth_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=123&scope=Mail.ReadWrite.All%20offline_access"
    res = detect_oauth_consent_phishing(oauth_url)
    assert res is not None
    assert "mail.readwrite.all" in res["dangerous_scopes"]

    js_html = '<script>var b = new Blob(["data"]); var u = URL.createObjectURL(b);</script>'
    sm_res = detect_html_smuggling(js_html)
    assert len(sm_res) >= 1
