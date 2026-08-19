"""Integration tests for Master Email Triage Pipeline and REST API."""

import json
import email
from analyzer import analyze_email, parse_email_text
from database.repository import GLOBAL_REPO
from app import app


def test_full_pipeline_clean_email():
    raw_email = """From: GitHub <notifications@github.com>
Subject: [GitHub] Security advisory notification
Authentication-Results: spf=pass dkim=pass dmarc=pass
Message-ID: <notification-123@github.com>
Date: Mon, 1 Jan 2026 12:00:00 +0000

Hello Developer,
A new version of your dependency is available.
"""
    msg = parse_email_text(raw_email)
    result = analyze_email(msg)
    assert result["verdict"] in ("CLEAN", "LIKELY CLEAN")
    assert result["score"] <= 30
    assert result["trust_discount"] > 0


def test_full_pipeline_phishing_email():
    raw_email = """From: "Microsoft Account Team" <security@micros0ft-support.xyz>
Subject: URGENT: Account Suspended within 24 hours
Authentication-Results: spf=fail dkim=fail dmarc=fail
Reply-To: credential-drop@evil-stealer.com
Message-ID: <bad-id>

Dear User,
Your Microsoft account has been suspended immediately.
Click here to confirm your identity: https://micros0ft-support.xyz/login.php
"""
    msg = parse_email_text(raw_email)
    result = analyze_email(msg)
    assert result["verdict"] in ("PHISHING", "MALICIOUS")
    assert result["score"] >= 60
    assert len(result["why_suspicious"]) >= 2
    assert any(m["id"] == "T1036.005" for m in result["mitre"])


def test_rest_api_endpoints():
    client = app.test_client()

    # Health Check
    health_resp = client.get("/api/v1/health")
    assert health_resp.status_code == 200
    assert health_resp.json["status"] == "healthy"

    # API Analyze
    sample_text = """From: test@example.com
Subject: Test Email

Hello test.
"""
    analyze_resp = client.post("/api/v1/analyze", json={"raw_text": sample_text})
    assert analyze_resp.status_code == 201
    case_id = analyze_resp.json["case_id"]

    # Get Case
    case_resp = client.get(f"/api/v1/cases/{case_id}")
    assert case_resp.status_code == 200
    assert case_resp.json["case"]["id"] == case_id
