"""Unit tests for Header Forensics & Authentication."""

import email
from core.header_forensics import analyze_email_headers


def test_clean_authenticated_headers():
    raw = """From: Security Team <security@microsoft.com>
Subject: Security Alert
Authentication-Results: spf=pass dkim=pass dmarc=pass
Message-ID: <12345@microsoft.com>
Date: Mon, 1 Jan 2026 12:00:00 +0000

Hello
"""
    msg = email.message_from_string(raw)
    res = analyze_email_headers(msg)
    assert res["from_domain"] == "microsoft.com"
    assert res["auth_results"]["spf"] == "pass"
    assert res["auth_results"]["dkim"] == "pass"
    assert res["auth_results"]["dmarc"] == "pass"
    assert res["header_score"] == 0


def test_display_name_spoofing():
    raw = """From: "PayPal Support" <attacker@free-mailer.xyz>
Subject: Account Alert
Authentication-Results: spf=fail dkim=fail dmarc=fail
Message-ID: <bad-id>

Hello
"""
    msg = email.message_from_string(raw)
    res = analyze_email_headers(msg)
    cats = [f.get("category") for f in res["findings"]]
    assert "display_name_spoofing" in cats
    assert "spf_fail" in cats
    assert res["header_score"] >= 40


def test_reply_to_mismatch():
    raw = """From: Billing <billing@trusted-company.com>
Reply-To: evil-drop@attacker-domain.com
Subject: Invoice

Hello
"""
    msg = email.message_from_string(raw)
    res = analyze_email_headers(msg)
    cats = [f.get("category") for f in res["findings"]]
    assert "reply_to_mismatch" in cats
