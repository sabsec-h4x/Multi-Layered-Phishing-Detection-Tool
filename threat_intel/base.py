"""
Threat Intelligence Provider Interface & Data Contracts
--------------------------------------------------------
Defines the base abstraction class and standardized result structures for all TI adapters.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime, timezone


class ThreatIntelProvider(ABC):
    """Abstract Base Class for all Threat Intelligence adapters."""

    def __init__(self, name: str, api_key: Optional[str] = None):
        self.name = name
        self.api_key = api_key

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if required API keys and dependencies are present."""
        pass

    @abstractmethod
    def query(self, indicator: str, indicator_type: str = "url") -> Dict[str, Any]:
        """Query the provider for a specific indicator (url, domain, ip, hash)."""
        pass

    def format_result(self,
                      indicator: str,
                      indicator_type: str,
                      available: bool,
                      malicious: int = 0,
                      suspicious: int = 0,
                      total_engines: int = 0,
                      confidence: str = "MEDIUM",
                      summary: str = "",
                      details: Optional[Dict[str, Any]] = None,
                      reason: Optional[str] = None) -> Dict[str, Any]:
        """Generate standardized TI result payload."""
        return {
            "provider": self.name,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "available": available,
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total_engines,
            "is_threat": (malicious > 0 or suspicious > 0),
            "confidence": confidence,
            "summary": summary,
            "details": details or {},
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
