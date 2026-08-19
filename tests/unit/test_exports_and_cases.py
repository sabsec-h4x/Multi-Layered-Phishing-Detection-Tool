"""Unit tests for STIX 2.1, Sigma Rule, CSV Exports, and Case Workflow."""

import json
from exports.stix_export import export_case_to_stix_bundle
from exports.sigma_export import export_case_to_sigma_rule
from exports.csv_json_export import export_iocs_to_csv
from core.case_manager import validate_status_transition, format_case_id, CaseWorkflowError
import pytest


def test_stix_bundle_export():
    mock_case = {
        "id": 42,
        "case_number": "CASE-0042",
        "title": "Credential Harvest Phish",
        "verdict": "PHISHING",
        "score": 85,
        "iocs": [
            {"ioc_type": "url", "ioc_value": "https://evil.com/login"},
            {"ioc_type": "domain", "ioc_value": "evil.com"},
            {"ioc_type": "ip", "ioc_value": "198.51.100.1"},
            {"ioc_type": "sha256", "ioc_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        ]
    }
    bundle = export_case_to_stix_bundle(mock_case)
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) >= 5

    types = [obj["type"] for obj in bundle["objects"]]
    assert "identity" in types
    assert "report" in types
    assert "indicator" in types


def test_sigma_rule_export():
    mock_case = {
        "id": 10,
        "case_number": "CASE-0010",
        "title": "Phishing Activity",
        "verdict": "MALICIOUS",
        "severity": "HIGH",
        "iocs": [
            {"ioc_type": "domain", "ioc_value": "phishing-bank.xyz"}
        ]
    }
    sigma_yaml = export_case_to_sigma_rule(mock_case)
    assert "title: PhishGuard Detection" in sigma_yaml
    assert "phishing-bank.xyz" in sigma_yaml
    assert "attack.t1566.002" in sigma_yaml


def test_csv_ioc_export():
    iocs = [
        {"type": "domain", "value": "evil.com", "source": "Body", "reputation": "MALICIOUS", "confidence": "HIGH", "created_at": "2026-08-19"},
        {"type": "ip", "value": "198.51.100.5", "source": "Hop", "reputation": "SUSPICIOUS", "confidence": "MEDIUM", "created_at": "2026-08-19"}
    ]
    csv_str = export_iocs_to_csv(iocs)
    assert "Type,Value,Source,Reputation,Confidence,Created At" in csv_str
    assert "evil.com" in csv_str
    assert "198.51.100.5" in csv_str


def test_case_status_transitions():
    assert validate_status_transition("OPEN", "INVESTIGATING") is True
    assert validate_status_transition("INVESTIGATING", "CONTAINED") is True
    assert validate_status_transition("CONTAINED", "CLOSED") is True

    with pytest.raises(CaseWorkflowError):
        validate_status_transition("OPEN", "INVALID_STATUS")

    assert format_case_id(7) == "CASE-0007"
