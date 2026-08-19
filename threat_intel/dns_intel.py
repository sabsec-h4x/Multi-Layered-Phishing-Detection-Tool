"""
DNS Threat Intelligence Provider
--------------------------------
Wraps DNS record querying into the standardized ThreatIntelProvider interface with caching.
"""

from typing import Dict, Any, Optional
from threat_intel.base import ThreatIntelProvider
from threat_intel.cache import GLOBAL_TI_CACHE
from core.dns_tls import query_dns_records
from config import DNS_CACHE_TTL_HOURS


class DNSIntelProvider(ThreatIntelProvider):
    """DNS Infrastructure Intelligence Provider."""

    def __init__(self):
        super().__init__("DNS_Intel", None)

    def is_configured(self) -> bool:
        return True

    def query(self, indicator: str, indicator_type: str = "domain") -> Dict[str, Any]:
        """Query DNS records for a domain."""
        if indicator_type != "domain":
            return self.format_result(indicator, indicator_type, available=False, reason="DNS provider only supports domain indicators")

        cached = GLOBAL_TI_CACHE.get(self.name, indicator, indicator_type)
        if cached:
            return cached

        res = query_dns_records(indicator)
        if not res.get("available"):
            return self.format_result(indicator, indicator_type, available=False, reason=res.get("reason"))

        has_mx = bool(res.get("MX"))
        has_spf = any("v=spf1" in txt.lower() for txt in res.get("TXT", []))
        has_dmarc = bool(res.get("DMARC"))

        summary = f"MX: {len(res.get('MX', []))}, NS: {len(res.get('NS', []))}, SPF: {'yes' if has_spf else 'no'}, DMARC: {'yes' if has_dmarc else 'no'}"

        output = self.format_result(
            indicator=indicator,
            indicator_type=indicator_type,
            available=True,
            summary=summary,
            details={
                "A": res.get("A", []),
                "AAAA": res.get("AAAA", []),
                "MX": res.get("MX", []),
                "NS": res.get("NS", []),
                "TXT": res.get("TXT", []),
                "DMARC": res.get("DMARC", []),
                "has_mx": has_mx,
                "has_spf": has_spf,
                "has_dmarc": has_dmarc,
            }
        )
        GLOBAL_TI_CACHE.set(self.name, indicator, output, indicator_type, custom_ttl_hours=DNS_CACHE_TTL_HOURS)
        return output
