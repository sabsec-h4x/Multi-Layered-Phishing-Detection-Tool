"""PhishGuard Threat Intelligence Package"""

from threat_intel.virustotal import VirusTotalProvider
from threat_intel.urlscan import URLScanProvider
from threat_intel.rdap_whois import RDAPWhoisProvider
from threat_intel.dns_intel import DNSIntelProvider
from threat_intel.fallback_providers import AbuseIPDBProvider, URLHausProvider
from config import VT_API_KEY, URLSCAN_API_KEY

_vt_provider = VirusTotalProvider(VT_API_KEY)
_urlscan_provider = URLScanProvider(URLSCAN_API_KEY)
_rdap_provider = RDAPWhoisProvider()
_dns_provider = DNSIntelProvider()
_abuseipdb_provider = AbuseIPDBProvider()
_urlhaus_provider = URLHausProvider()


def query_virustotal(url: str, api_key: str = None):
    provider = VirusTotalProvider(api_key) if api_key else _vt_provider
    return provider.query(url, indicator_type="url")


def query_virustotal_domain(domain: str, api_key: str = None):
    provider = VirusTotalProvider(api_key) if api_key else _vt_provider
    return provider.query(domain, indicator_type="domain")


def query_virustotal_hash(file_hash: str, api_key: str = None):
    provider = VirusTotalProvider(api_key) if api_key else _vt_provider
    return provider.query(file_hash, indicator_type="hash")


def query_urlscan(url: str, api_key: str = None, wait_seconds: int = 15):
    provider = URLScanProvider(api_key) if api_key else _urlscan_provider
    return provider.query(url, indicator_type="url")


def query_whois_age(domain: str):
    return _rdap_provider.query(domain, indicator_type="domain")


def query_dns(domain: str):
    return _dns_provider.query(domain, indicator_type="domain")
