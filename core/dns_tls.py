"""
DNS & TLS / Certificate Forensics Engine
----------------------------------------
Inspects DNS infrastructure records (A/MX/NS/TXT/DMARC) and
TLS certificates (Subject, Issuer, SANs, Age, Expiry, Fingerprints).
"""

import ssl
import socket
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def query_dns_records(domain: str) -> Dict[str, Any]:
    """
    Query DNS records (A, AAAA, MX, NS, TXT, DMARC) for a domain.
    """
    if not DNS_AVAILABLE or not domain:
        return {"available": False, "reason": "dnspython not available or empty domain"}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0

    records = {
        "A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "DMARC": [],
        "available": True, "error": None
    }

    try:
        # A records
        try:
            answers = resolver.resolve(domain, "A")
            records["A"] = [r.to_text() for r in answers]
        except Exception:
            pass

        # MX records
        try:
            answers = resolver.resolve(domain, "MX")
            records["MX"] = [r.exchange.to_text().rstrip(".") for r in answers]
        except Exception:
            pass

        # NS records
        try:
            answers = resolver.resolve(domain, "NS")
            records["NS"] = [r.target.to_text().rstrip(".") for r in answers]
        except Exception:
            pass

        # TXT records (SPF)
        try:
            answers = resolver.resolve(domain, "TXT")
            records["TXT"] = [r.to_text().strip('"') for r in answers]
        except Exception:
            pass

        # DMARC TXT record
        try:
            dmarc_host = f"_dmarc.{domain}"
            answers = resolver.resolve(dmarc_host, "TXT")
            records["DMARC"] = [r.to_text().strip('"') for r in answers]
        except Exception:
            pass

        return records
    except Exception as e:
        return {"available": False, "reason": str(e), "records": records}


def inspect_tls_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Open a direct TLS handshake with the destination host to extract
    certificate subject, issuer, SANs, age, expiry, and SHA256 fingerprint.
    """
    if not hostname:
        return {"valid": False, "error": "No hostname provided"}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                der_cert = ssock.getpeercert(binary_form=True)

        if not cert or not der_cert:
            return {"valid": False, "error": "No certificate returned"}

        # Extract Subject and Issuer
        subject_dict = dict(x[0] for x in cert.get("subject", []))
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))

        subject_cn = subject_dict.get("commonName", "unknown")
        issuer_org = issuer_dict.get("organizationName", issuer_dict.get("commonName", "unknown"))

        # SANs
        sans = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]

        # Validity Dates
        not_before_str = cert.get("notBefore")
        not_after_str = cert.get("notAfter")

        not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_before_str else None
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_after_str else None

        now_utc = datetime.now(timezone.utc)
        is_expired = not_after < now_utc if not_after else False
        cert_age_days = (now_utc - not_before).days if not_before else None

        # SHA256 Fingerprint
        fingerprint_sha256 = hashlib.sha256(der_cert).hexdigest()

        # Self-signed check
        is_self_signed = (subject_dict == issuer_dict)

        return {
            "valid": True,
            "subject_cn": subject_cn,
            "issuer": issuer_org,
            "sans": sans,
            "not_before": not_before.isoformat() if not_before else None,
            "not_after": not_after.isoformat() if not_after else None,
            "cert_age_days": cert_age_days,
            "is_expired": is_expired,
            "is_self_signed": is_self_signed,
            "fingerprint_sha256": fingerprint_sha256,
            "error": None,
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"TLS Certificate verification failed: {e}"}
    except Exception as e:
        return {"valid": False, "error": f"TLS handshake failed: {e}"}
