"""
VirusTotal Threat Intelligence Provider Adapter
------------------------------------------------
Enriches URLs, domains, and file SHA256 hashes against ~70 AV and URL reputation engines.
"""

import base64
import time
import requests
from typing import Dict, Any, Optional

from threat_intel.base import ThreatIntelProvider
from threat_intel.cache import GLOBAL_TI_CACHE
from config import VT_API_KEY, FETCH_TIMEOUT

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal API v3 Adapter."""

    def __init__(self, api_key: Optional[str] = VT_API_KEY):
        super().__init__("VirusTotal", api_key or VT_API_KEY)

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _url_to_id(self, url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def query(self, indicator: str, indicator_type: str = "url") -> Dict[str, Any]:
        """Query VT for a URL, domain, IP, or file hash with automatic caching."""
        if not self.is_configured():
            return self.format_result(indicator, indicator_type, available=False, reason="VT_API_KEY not configured in .env")

        # Check cache
        cached = GLOBAL_TI_CACHE.get(self.name, indicator, indicator_type)
        if cached:
            return cached

        headers = {"x-apikey": self.api_key}

        try:
            if indicator_type == "url":
                url_id = self._url_to_id(indicator)
                endpoint = f"{VT_BASE}/urls/{url_id}"
            elif indicator_type == "domain":
                endpoint = f"{VT_BASE}/domains/{indicator}"
            elif indicator_type == "ip":
                endpoint = f"{VT_BASE}/ip_addresses/{indicator}"
            elif indicator_type in ("hash", "sha256", "md5"):
                endpoint = f"{VT_BASE}/files/{indicator}"
            else:
                return self.format_result(indicator, indicator_type, available=False, reason=f"Unsupported indicator type: {indicator_type}")

            resp = requests.get(endpoint, headers=headers, timeout=FETCH_TIMEOUT)

            # URL 404 -> Submit for initial analysis
            if resp.status_code == 404 and indicator_type == "url":
                submit = requests.post(f"{VT_BASE}/urls", headers=headers, data={"url": indicator}, timeout=FETCH_TIMEOUT)
                if submit.status_code in (200, 201):
                    analysis_id = submit.json().get("data", {}).get("id")
                    for _ in range(3):
                        time.sleep(2)
                        check = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=FETCH_TIMEOUT)
                        if check.status_code == 200:
                            attr = check.json().get("data", {}).get("attributes", {})
                            if attr.get("status") == "completed":
                                stats = attr.get("stats", {})
                                res = self._format_vt_stats(indicator, indicator_type, stats)
                                GLOBAL_TI_CACHE.set(self.name, indicator, res, indicator_type)
                                return res
                return self.format_result(indicator, indicator_type, available=False, reason="URL newly submitted to VirusTotal, scan pending")

            if resp.status_code == 429:
                return self.format_result(indicator, indicator_type, available=False, reason="VirusTotal rate limit exceeded (free tier: 4 req/min)")

            if resp.status_code != 200:
                return self.format_result(indicator, indicator_type, available=False, reason=f"VirusTotal API returned status {resp.status_code}")

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            res = self._format_vt_stats(indicator, indicator_type, stats)
            GLOBAL_TI_CACHE.set(self.name, indicator, res, indicator_type)
            return res

        except requests.exceptions.RequestException as e:
            return self.format_result(indicator, indicator_type, available=False, reason=f"VirusTotal request error: {e}")

    def _format_vt_stats(self, indicator: str, indicator_type: str, stats: Dict[str, int]) -> Dict[str, Any]:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = sum(stats.values()) or 1

        summary = f"{malicious}/{total} security vendors flag this as malicious"
        if suspicious:
            summary += f", {suspicious} as suspicious"

        confidence = "HIGH" if malicious >= 3 else ("MEDIUM" if (malicious > 0 or suspicious > 0) else "HIGH")

        return self.format_result(
            indicator=indicator,
            indicator_type=indicator_type,
            available=True,
            malicious=malicious,
            suspicious=suspicious,
            total_engines=total,
            confidence=confidence,
            summary=summary,
            details={
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
            }
        )
