"""
PhishGuard Configuration Module
-------------------------------
Loads and validates application settings, security policies, and API keys.
"""

import os
import secrets
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = Path(__file__).resolve().parent

# Application Environment
ENV = os.environ.get("PHISHGUARD_ENV", "development").lower()
IS_PRODUCTION = ENV == "production"

# Secret Key (Auto-generated if not provided in dev, required in production)
_default_secret = os.environ.get("SECRET_KEY")
if not _default_secret:
    if IS_PRODUCTION:
        raise ValueError("SECRET_KEY environment variable must be set in production mode!")
    _default_secret = secrets.token_hex(32)

SECRET_KEY = _default_secret

# Database Configuration
DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", BASE_DIR / "phishguard.db"))

# Threat Intelligence Keys
VT_API_KEY = os.environ.get("VT_API_KEY", "").strip() or None
URLSCAN_API_KEY = os.environ.get("URLSCAN_API_KEY", "").strip() or None
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "").strip() or None
OTX_API_KEY = os.environ.get("OTX_API_KEY", "").strip() or None
GSB_API_KEY = os.environ.get("GSB_API_KEY", "").strip() or None

# SSRF and Network Security Policies
FETCH_TIMEOUT = int(os.environ.get("FETCH_TIMEOUT", 8))
MAX_FETCH_BYTES = int(os.environ.get("MAX_FETCH_BYTES", 500_000))
MAX_REDIRECTS = int(os.environ.get("MAX_REDIRECTS", 5))
ALLOW_PRIVATE_IPS = os.environ.get("ALLOW_PRIVATE_IPS", "false").lower() in ("true", "1", "yes")

# Caching TTL (hours)
TI_CACHE_TTL_HOURS = int(os.environ.get("TI_CACHE_TTL_HOURS", 24))
DNS_CACHE_TTL_HOURS = int(os.environ.get("DNS_CACHE_TTL_HOURS", 12))
WHOIS_CACHE_TTL_HOURS = int(os.environ.get("WHOIS_CACHE_TTL_HOURS", 48))

# Concurrency and Rate Limits
MAX_CONCURRENT_ENRICHMENTS = int(os.environ.get("MAX_CONCURRENT_ENRICHMENTS", 5))
DEFAULT_IMAP_INTERVAL = int(os.environ.get("DEFAULT_IMAP_INTERVAL", 30))

# User Agent
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard/2.0 (+security-triage-tool)"
