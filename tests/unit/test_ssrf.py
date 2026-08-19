"""Unit tests for SSRF Protection & Safe HTTP Client."""

import pytest
from core.ssrf import is_ip_blocked, validate_url_safety, SSRFValidationError


def test_private_ips_blocked():
    blocked, reason = is_ip_blocked("127.0.0.1")
    assert blocked is True
    assert "loopback" in reason.lower() or "blocked subnet" in reason.lower()

    blocked, reason = is_ip_blocked("10.0.0.1")
    assert blocked is True

    blocked, reason = is_ip_blocked("172.16.5.10")
    assert blocked is True

    blocked, reason = is_ip_blocked("192.168.1.1")
    assert blocked is True

    blocked, reason = is_ip_blocked("169.254.169.254")
    assert blocked is True


def test_public_ips_allowed():
    blocked, reason = is_ip_blocked("8.8.8.8")
    assert blocked is False

    blocked, reason = is_ip_blocked("93.184.216.34")
    assert blocked is False


def test_cloud_metadata_blocked():
    with pytest.raises(SSRFValidationError) as excinfo:
        validate_url_safety("http://169.254.169.254/latest/meta-data/")
    assert "blocked" in str(excinfo.value).lower()

    with pytest.raises(SSRFValidationError) as excinfo:
        validate_url_safety("http://metadata.google.internal/computeMetadata/v1/")
    assert "metadata" in str(excinfo.value).lower()


def test_invalid_schemes_blocked():
    with pytest.raises(SSRFValidationError):
        validate_url_safety("file:///etc/passwd")

    with pytest.raises(SSRFValidationError):
        validate_url_safety("gopher://127.0.0.1:6379")

    with pytest.raises(SSRFValidationError):
        validate_url_safety("dict://127.0.0.1:11211")
