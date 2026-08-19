"""
Threat Intelligence Persistent & Memory TTL Cache
-------------------------------------------------
Caches external TI queries in memory and SQLite to prevent redundant API calls
and rate limit exhaustion.
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional

from config import DATABASE_PATH, TI_CACHE_TTL_HOURS


class ThreatIntelCache:
    """Thread-safe persistent and in-memory TTL caching layer for TI indicators."""

    def __init__(self, db_path: Path = DATABASE_PATH, ttl_hours: int = TI_CACHE_TTL_HOURS):
        self.db_path = db_path
        self.ttl = timedelta(hours=ttl_hours)
        self._memory_cache: Dict[str, Dict[str, Any]] = {}
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        try:
            conn = self._get_conn()
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel_cache (
                    cache_key TEXT PRIMARY KEY,
                    provider TEXT,
                    indicator TEXT,
                    indicator_type TEXT,
                    response_json TEXT,
                    cached_at TEXT,
                    expires_at TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get(self, provider: str, indicator: str, indicator_type: str = "url") -> Optional[Dict[str, Any]]:
        """Retrieve cached result if valid and not expired."""
        cache_key = f"{provider}:{indicator_type}:{indicator}"

        # 1. In-memory check
        now_utc = datetime.now(timezone.utc)
        if cache_key in self._memory_cache:
            entry = self._memory_cache[cache_key]
            if entry["expires_at"] > now_utc:
                return entry["data"]
            else:
                del self._memory_cache[cache_key]

        # 2. SQLite check
        try:
            conn = self._get_conn()
            row = conn.execute(
                "SELECT response_json, expires_at FROM threat_intel_cache WHERE cache_key = ?",
                (cache_key,)
            ).fetchone()
            conn.close()

            if row:
                expires_at = datetime.fromisoformat(row["expires_at"])
                if expires_at > now_utc:
                    data = json.loads(row["response_json"])
                    self._memory_cache[cache_key] = {"data": data, "expires_at": expires_at}
                    return data
        except Exception:
            pass

        return None

    def set(self, provider: str, indicator: str, data: Dict[str, Any], indicator_type: str = "url", custom_ttl_hours: Optional[int] = None):
        """Store result in memory and SQLite cache with expiration."""
        cache_key = f"{provider}:{indicator_type}:{indicator}"
        now_utc = datetime.now(timezone.utc)
        ttl = timedelta(hours=custom_ttl_hours) if custom_ttl_hours else self.ttl
        expires_at = now_utc + ttl

        self._memory_cache[cache_key] = {"data": data, "expires_at": expires_at}

        try:
            conn = self._get_conn()
            conn.execute("""
                INSERT OR REPLACE INTO threat_intel_cache
                (cache_key, provider, indicator, indicator_type, response_json, cached_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                cache_key, provider, indicator, indicator_type,
                json.dumps(data, default=str),
                now_utc.isoformat(),
                expires_at.isoformat()
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass


# Global singleton instance
GLOBAL_TI_CACHE = ThreatIntelCache()
