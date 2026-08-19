"""
Fallback & Community Threat Intelligence Provider Adapters
----------------------------------------------------------
Optional adapters for AbuseIPDB, URLHaus, and AlienVault OTX.
"""

import requests
from typing import Dict, Any, Optional

from threat_intel.base import ThreatIntelProvider
from threat_intel.cache import GLOBAL_TI_CACHE
from config import ABUSEIPDB_API_KEY, OTX_API_KEY, FETCH_TIMEOUT


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB IP Reputation Adapter."""

    def __init__(self, api_key: Optional[str] = ABUSEIPDB_API_KEY):
        super().__init__("AbuseIPDB", api_key or ABUSEIPDB_API_KEY)

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def query(self, indicator: str, indicator_type: str = "ip") -> Dict[str, Any]:
        if not self.is_configured():
            return self.format_result(indicator, indicator_type, available=False, reason="ABUSEIPDB_API_KEY not configured")

        if indicator_type != "ip":
            return self.format_result(indicator, indicator_type, available=False, reason="AbuseIPDB only supports IP indicators")

        cached = GLOBAL_TI_CACHE.get(self.name, indicator, indicator_type)
        if cached:
            return cached

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": self.api_key, "Accept": "application/json"}
            params = {"ipAddress": indicator, "maxAgeInDays": "90"}
            resp = requests.get(url, headers=headers, params=params, timeout=FETCH_TIMEOUT)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                is_threat = score >= 25

                result = self.format_result(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    available=True,
                    malicious=1 if score >= 50 else 0,
                    suspicious=1 if (score >= 25 and score < 50) else 0,
                    confidence="HIGH" if reports >= 5 else "MEDIUM",
                    summary=f"Abuse Confidence Score: {score}%, Total Reports: {reports}",
                    details=data
                )
                GLOBAL_TI_CACHE.set(self.name, indicator, result, indicator_type)
                return result

            return self.format_result(indicator, indicator_type, available=False, reason=f"AbuseIPDB returned {resp.status_code}")
        except Exception as e:
            return self.format_result(indicator, indicator_type, available=False, reason=str(e))


class URLHausProvider(ThreatIntelProvider):
    """URLHaus (abuse.ch) Community Malware/Phishing Feed Adapter."""

    def __init__(self):
        super().__init__("URLHaus", None)

    def is_configured(self) -> bool:
        return True

    def query(self, indicator: str, indicator_type: str = "url") -> Dict[str, Any]:
        if indicator_type not in ("url", "domain"):
            return self.format_result(indicator, indicator_type, available=False, reason="URLHaus supports URL/domain indicators")

        cached = GLOBAL_TI_CACHE.get(self.name, indicator, indicator_type)
        if cached:
            return cached

        try:
            url = "https://urlhaus-api.abuse.ch/v1/url/"
            data = {"url": indicator}
            resp = requests.post(url, data=data, timeout=FETCH_TIMEOUT)

            if resp.status_code == 200:
                res = resp.json()
                query_status = res.get("query_status")
                if query_status == "ok":
                    url_status = res.get("url_status")
                    threat = res.get("threat")
                    result = self.format_result(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        available=True,
                        malicious=1,
                        confidence="HIGH",
                        summary=f"URLHaus flags this as malicious payload source: threat={threat}, status={url_status}",
                        details=res
                    )
                    GLOBAL_TI_CACHE.set(self.name, indicator, result, indicator_type)
                    return result
                elif query_status == "no_results":
                    result = self.format_result(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        available=True,
                        malicious=0,
                        summary="Not listed in URLHaus malware dataset",
                        details={}
                    )
                    GLOBAL_TI_CACHE.set(self.name, indicator, result, indicator_type)
                    return result

            return self.format_result(indicator, indicator_type, available=False, reason=f"URLHaus returned status {resp.status_code}")
        except Exception as e:
            return self.format_result(indicator, indicator_type, available=False, reason=str(e))
