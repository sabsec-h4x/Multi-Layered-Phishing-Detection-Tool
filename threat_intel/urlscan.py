"""
URLScan.io Threat Intelligence Provider Adapter
-----------------------------------------------
Interacts with the URLScan.io automated browser sandbox for live DOM analysis and screenshots.
"""

import time
import requests
from typing import Dict, Any, Optional

from threat_intel.base import ThreatIntelProvider
from threat_intel.cache import GLOBAL_TI_CACHE
from config import URLSCAN_API_KEY, FETCH_TIMEOUT

URLSCAN_BASE = "https://urlscan.io/api/v1"


class URLScanProvider(ThreatIntelProvider):
    """URLScan.io Browser Sandbox Adapter."""

    def __init__(self, api_key: Optional[str] = URLSCAN_API_KEY):
        super().__init__("URLScan.io", api_key or URLSCAN_API_KEY)

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def query(self, indicator: str, indicator_type: str = "url") -> Dict[str, Any]:
        """Submit URL to URLScan.io sandbox and return verdict."""
        if not self.is_configured():
            return self.format_result(indicator, indicator_type, available=False, reason="URLSCAN_API_KEY not configured in .env")

        if indicator_type != "url":
            return self.format_result(indicator, indicator_type, available=False, reason="URLScan provider only supports URL indicators")

        cached = GLOBAL_TI_CACHE.get(self.name, indicator, indicator_type)
        if cached:
            return cached

        headers = {"API-Key": self.api_key, "Content-Type": "application/json"}
        try:
            submit = requests.post(
                f"{URLSCAN_BASE}/scan/",
                headers=headers,
                json={"url": indicator, "visibility": "unlisted"},
                timeout=FETCH_TIMEOUT
            )

            if submit.status_code == 400:
                return self.format_result(indicator, indicator_type, available=False, reason="URLScan rejected the URL format")
            if submit.status_code == 401:
                return self.format_result(indicator, indicator_type, available=False, reason="URLScan API Key rejected (401 Unauthorized)")
            if submit.status_code != 200:
                return self.format_result(indicator, indicator_type, available=False, reason=f"URLScan returned {submit.status_code}")

            res_json = submit.json()
            api_result_url = res_json.get("api")
            screenshot_url = res_json.get("screenshot")
            report_url = res_json.get("result")

            # Poll for fast completion (up to ~10s)
            for _ in range(3):
                time.sleep(3)
                check = requests.get(api_result_url, timeout=FETCH_TIMEOUT)
                if check.status_code == 200:
                    data = check.json()
                    verdicts = data.get("verdicts", {}).get("overall", {})
                    page = data.get("page", {})
                    malicious = 1 if verdicts.get("malicious") else 0
                    score = verdicts.get("score", 0)
                    categories = verdicts.get("categories", [])

                    result = self.format_result(
                        indicator=indicator,
                        indicator_type=indicator_type,
                        available=True,
                        malicious=malicious,
                        suspicious=1 if score > 0 and not malicious else 0,
                        total_engines=1,
                        confidence="HIGH" if malicious else "MEDIUM",
                        summary=f"URLScan score: {score}, malicious: {bool(malicious)}" + (f", categories: {', '.join(categories)}" if categories else ""),
                        details={
                            "score": score,
                            "categories": categories,
                            "final_url": page.get("url"),
                            "final_domain": page.get("domain"),
                            "ip": page.get("ip"),
                            "server": page.get("server"),
                            "screenshot_url": data.get("task", {}).get("screenshotURL", screenshot_url),
                            "report_url": data.get("task", {}).get("reportURL", report_url),
                        }
                    )
                    GLOBAL_TI_CACHE.set(self.name, indicator, result, indicator_type)
                    return result

            # Still processing
            return self.format_result(
                indicator=indicator,
                indicator_type=indicator_type,
                available=False,
                summary="Scan submitted to sandbox, processing in background",
                details={"report_url": report_url, "screenshot_url": screenshot_url},
                reason="URLScan sandbox scan in progress"
            )

        except requests.exceptions.RequestException as e:
            return self.format_result(indicator, indicator_type, available=False, reason=f"URLScan request failed: {e}")
