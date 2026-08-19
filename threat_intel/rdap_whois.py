"""
RDAP & WHOIS Domain Intelligence Provider
-----------------------------------------
Extracts domain creation date, registration age, registrar, and expiration dates
using RDAP protocols with WHOIS fallback.
"""

import requests
from datetime import datetime, timezone
from typing import Dict, Any, Optional

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

from threat_intel.base import ThreatIntelProvider
from threat_intel.cache import GLOBAL_TI_CACHE
from config import FETCH_TIMEOUT, WHOIS_CACHE_TTL_HOURS


class RDAPWhoisProvider(ThreatIntelProvider):
    """RDAP and WHOIS domain age intelligence provider."""

    def __init__(self):
        super().__init__("RDAP_WHOIS", None)

    def is_configured(self) -> bool:
        return True

    def query(self, indicator: str, indicator_type: str = "domain") -> Dict[str, Any]:
        """Query domain age and registration metadata."""
        if indicator_type != "domain":
            return self.format_result(indicator, indicator_type, available=False, reason="RDAP/WHOIS only supports domain indicators")

        cached = GLOBAL_TI_CACHE.get(self.name, indicator, indicator_type)
        if cached:
            return cached

        # 1. Try RDAP lookup via ICANN / bootstrap
        rdap_res = self._query_rdap(indicator)
        if rdap_res.get("available"):
            GLOBAL_TI_CACHE.set(self.name, indicator, rdap_res, indicator_type, custom_ttl_hours=WHOIS_CACHE_TTL_HOURS)
            return rdap_res

        # 2. Fallback to python-whois
        if WHOIS_AVAILABLE:
            whois_res = self._query_whois_lib(indicator)
            GLOBAL_TI_CACHE.set(self.name, indicator, whois_res, indicator_type, custom_ttl_hours=WHOIS_CACHE_TTL_HOURS)
            return whois_res

        return self.format_result(indicator, indicator_type, available=False, reason="RDAP and WHOIS both unavailable")

    def _query_rdap(self, domain: str) -> Dict[str, Any]:
        import socket
        try:
            try:
                socket.getaddrinfo(domain, 80)
            except Exception:
                return {"available": False}

            url = f"https://rdap.org/domain/{domain}"
            resp = requests.get(url, timeout=2.0, headers={"Accept": "application/rdap+json"})
            if resp.status_code == 200:
                data = resp.json()
                events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
                created_str = events.get("registration") or events.get("created")
                if created_str:
                    created_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                    now_utc = datetime.now(timezone.utc)
                    age_days = (now_utc - created_dt).days

                    return self.format_result(
                        indicator=domain,
                        indicator_type="domain",
                        available=True,
                        summary=f"Domain registered {created_dt.strftime('%Y-%m-%d')} ({age_days} days ago)",
                        details={
                            "created": str(created_dt.date()),
                            "age_days": age_days,
                            "is_newly_registered": age_days < 90,
                            "source": "RDAP",
                        }
                    )
        except Exception:
            pass
        return {"available": False}

    def _query_whois_lib(self, domain: str) -> Dict[str, Any]:
        import socket
        try:
            # Fast DNS pre-check so non-resolving synthetic domains fail in 50ms instead of 30s socket timeout
            try:
                socket.getaddrinfo(domain, 80)
            except Exception:
                return self.format_result(domain, "domain", available=False, reason="Domain does not resolve in DNS")

            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(3.0)
            try:
                w = whois_lib.whois(domain)
            finally:
                socket.setdefaulttimeout(old_timeout)

            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if not created:
                return self.format_result(domain, "domain", available=False, reason="No creation date returned in WHOIS")

            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            now_utc = datetime.now(timezone.utc)
            age_days = (now_utc - created).days

            return self.format_result(
                indicator=domain,
                indicator_type="domain",
                available=True,
                summary=f"Domain registered {created.strftime('%Y-%m-%d')} ({age_days} days ago)",
                details={
                    "created": str(created.date()),
                    "age_days": age_days,
                    "is_newly_registered": age_days < 90,
                    "registrar": str(w.registrar or "unknown"),
                    "source": "WHOIS",
                }
            )
        except Exception as e:
            return self.format_result(domain, "domain", available=False, reason=f"WHOIS error: {e}")
