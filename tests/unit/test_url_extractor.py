"""Unit tests for HTML Link Extraction and Mismatch Detection."""

from core.url_extractor import extract_html_links_and_resources, extract_plain_text_urls, get_registrable_domain


def test_plain_text_extraction():
    text = "Visit our site at https://example.com/login for details. Or see http://test.org."
    urls = extract_plain_text_urls(text)
    assert "https://example.com/login" in urls
    assert "http://test.org" in urls


def test_registrable_domain_parsing():
    assert get_registrable_domain("login.microsoft.com") == "microsoft.com"
    assert get_registrable_domain("evil.co.uk") == "evil.co.uk"
    assert get_registrable_domain("sub.domain.paypal-verify.xyz") == "paypal-verify.xyz"


def test_display_text_destination_mismatch():
    html_content = """
    <p>Please log in here:
       <a href="https://evil-attacker.xyz/login">https://microsoft.com/security</a>
    </p>
    """
    res = extract_html_links_and_resources(html_content)
    links = res["links"]
    assert len(links) == 1
    assert links[0]["is_mismatch"] is True
    assert "microsoft.com" in links[0]["mismatch_details"]
    assert "evil-attacker.xyz" in links[0]["mismatch_details"]


def test_hidden_link_detection():
    html_content = """
    <a href="https://stealth-phish.com" style="display:none">Click</a>
    <a href="https://normal-link.com">Normal</a>
    """
    res = extract_html_links_and_resources(html_content)
    links = res["links"]
    assert len(links) == 2
    assert links[0]["is_hidden"] is True
    assert links[1]["is_hidden"] is False


def test_dangerous_schemes_extraction():
    html_content = """
    <a href="javascript:alert(1)">Exploit</a>
    <a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Data URI</a>
    """
    res = extract_html_links_and_resources(html_content)
    assert len(res["suspicious_schemes"]) == 2
