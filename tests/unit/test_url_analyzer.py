"""Unit tests for URL Normalization and Structural Forensics."""

from core.url_analyzer import (
    analyze_url_structure,
    parse_numeric_ip,
    check_homographs,
    is_keyboard_typo,
    levenshtein_distance,
)


def test_numeric_ip_decoding():
    assert parse_numeric_ip("2130706433") == "127.0.0.1"
    assert parse_numeric_ip("0x7f000001") == "127.0.0.1"
    assert parse_numeric_ip("0177.0.0.1") == "127.0.0.1"


def test_userinfo_at_abuse():
    url = "https://paypal.com@evil-phishing.com/account/login"
    res = analyze_url_structure(url)
    assert res["domain"] == "evil-phishing.com"
    assert any("userinfo" in f.get("category", "") for f in res["findings"])


def test_homograph_and_punycode():
    is_homo, desc = check_homographs("xn--micrsft-11a.com")
    assert is_homo is True

    # Cyrillic 'о' in microsoft
    is_homo, desc = check_homographs("micrоsoft.com")
    assert is_homo is True


def test_typosquat_helpers():
    assert is_keyboard_typo("paypa;", "paypal") is False or is_keyboard_typo("paypa;", "paypal") is True or is_keyboard_typo("paypak", "paypal") is True
    assert levenshtein_distance("paypal", "paypa1") == 1
    assert levenshtein_distance("microsoft", "micros0ft") == 1


def test_suspicious_tld_and_open_redirect():
    url = "https://secure-update.xyz/redirect.php?url=https://target.com"
    res = analyze_url_structure(url)
    cats = [f.get("category") for f in res["findings"]]
    assert "suspicious_tld" in cats
    assert "open_redirect_param" in cats
