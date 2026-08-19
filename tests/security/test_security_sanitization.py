"""Security tests for SSRF, path traversal, and secret sanitization."""

import pytest
from core.ssrf import is_ip_blocked, validate_url_safety, SSRFValidationError
from werkzeug.utils import secure_filename


def test_ssrf_ipv6_loopback_and_link_local():
    blocked, _ = is_ip_blocked("::1")
    assert blocked is True

    blocked, _ = is_ip_blocked("fe80::1")
    assert blocked is True


def test_ssrf_ipv4_mapped_ipv6():
    # ::ffff:127.0.0.1
    blocked, _ = is_ip_blocked("::ffff:127.0.0.1")
    assert blocked is True

    blocked, _ = is_ip_blocked("::ffff:10.0.0.1")
    assert blocked is True


def test_ssrf_multicast_and_broadcast():
    blocked, _ = is_ip_blocked("224.0.0.1")
    assert blocked is True

    blocked, _ = is_ip_blocked("255.255.255.255")
    assert blocked is True


def test_ssrf_unsupported_port_rejection():
    with pytest.raises(SSRFValidationError) as excinfo:
        validate_url_safety("http://example.com:22/payload")
    assert "port" in str(excinfo.value).lower()


def test_path_traversal_filename_sanitization():
    malicious_filenames = [
        "../../../etc/passwd",
        "..\\..\\windows\\system32\\cmd.exe",
        "nested/path/sample.eml"
    ]
    for fn in malicious_filenames:
        cleaned = secure_filename(fn)
        assert "/" not in cleaned
        assert "\\" not in cleaned
        assert not cleaned.startswith("/")
        assert not cleaned.startswith("\\")
