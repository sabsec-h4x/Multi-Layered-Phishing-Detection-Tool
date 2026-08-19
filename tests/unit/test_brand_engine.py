"""Unit tests for Brand Impersonation Engine."""

from core.brand_engine import (
    check_domain_brand_impersonation,
    evaluate_page_impersonation,
    is_known_legitimate_domain,
)


def test_legitimate_brand_domains():
    assert is_known_legitimate_domain("microsoft.com") is True
    assert is_known_legitimate_domain("paypal.com") is True
    assert is_known_legitimate_domain("evil-site.com") is False


def test_typosquatted_brand_domain():
    res = check_domain_brand_impersonation("paypa1.com")
    assert res is not None
    assert res["brand_key"] == "paypal"
    assert res["similarity"] == "HIGH"


def test_brand_in_subdomains_of_unrelated_domain():
    res = check_domain_brand_impersonation("evil-hacker.xyz", "microsoft.com.login.evil-hacker.xyz")
    assert res is not None
    assert res["brand_key"] == "microsoft"
    assert "Subdomain Brand Masquerading" in res["technique"]


def test_page_title_credential_impersonation():
    res = evaluate_page_impersonation(
        domain="evil-phishing.com",
        page_title="Microsoft OneDrive - Sign in to your account",
        has_password_field=True
    )
    assert res is not None
    assert res["brand_key"] == "microsoft"
    assert res["confidence"] == "HIGH"
    assert "credential harvesting" in res["verdict"].lower()
