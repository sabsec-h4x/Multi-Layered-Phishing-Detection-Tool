"""
Normalized IOC Extraction & Deduplication Engine
------------------------------------------------
Extracts, normalizes, and categorizes Indicators of Compromise (IOCs)
across URLs, domains, IPv4/IPv6, email addresses, file hashes, and certificate fingerprints.
"""

from typing import Dict, Any, List, Set


def extract_normalized_iocs(analysis_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract a clean, deduplicated list of structured IOC objects from an analysis result.
    """
    iocs: List[Dict[str, Any]] = []
    seen_keys: Set[str] = set()

    def add_ioc(ioc_type: str, value: str, source: str, reputation: str = "Unknown", confidence: str = "HIGH"):
        if not value:
            return
        val_clean = value.strip().lower() if ioc_type != "url" else value.strip()
        key = f"{ioc_type}:{val_clean}"
        if key not in seen_keys:
            seen_keys.add(key)
            iocs.append({
                "type": ioc_type,
                "value": val_clean,
                "source": source,
                "reputation": reputation,
                "confidence": confidence,
            })

    # 1. Sender and Header Emails & Domains
    headers = analysis_result.get("header_analysis", {})
    from_addr = headers.get("from_addr")
    if from_addr:
        add_ioc("email", from_addr, "Header: From", "Observed")
    from_domain = headers.get("from_domain")
    if from_domain:
        add_ioc("domain", from_domain, "Header: From Domain", "Observed")

    reply_to = headers.get("reply_to_addr")
    if reply_to:
        add_ioc("email", reply_to, "Header: Reply-To", "Observed")

    return_path = headers.get("return_path_addr")
    if return_path:
        add_ioc("email", return_path, "Header: Return-Path", "Observed")

    # 2. Received Chain IPs
    received = analysis_result.get("received_chain", {})
    for hop in received.get("hops", []):
        ip = hop.get("ip")
        if ip and not hop.get("is_internal"):
            add_ioc("ip", ip, f"Received Hop #{hop.get('hop_index')}", "External Relay")

    # 3. URLs and Domains
    urls = analysis_result.get("url_analysis", [])
    for u in urls:
        raw_url = u.get("url")
        if raw_url:
            rep = u.get("verdict", "Unknown")
            add_ioc("url", raw_url, "Body Link", rep)

        dom = u.get("domain")
        if dom:
            rep = u.get("verdict", "Unknown")
            add_ioc("domain", dom, "Extracted Domain", rep)

        # Extracted IPs from DNS / Safe Fetch
        for ip in u.get("resolved_ips", []):
            add_ioc("ip", ip, f"Resolved IP for {dom}", "Infrastructure")

        # Certificate fingerprint
        ssl_info = u.get("ssl", {})
        if ssl_info and ssl_info.get("fingerprint_sha256"):
            add_ioc("certificate_fingerprint", ssl_info["fingerprint_sha256"], f"TLS Cert for {dom}", "Infrastructure")

    # 4. Attachment Hashes and Filenames
    attachments = analysis_result.get("attachment_analysis", {}).get("attachments", [])
    for att in attachments:
        fn = att.get("filename")
        if fn:
            add_ioc("filename", fn, "Attachment", "Suspicious" if att.get("is_risky") else "Unknown")
        sha256 = att.get("sha256")
        if sha256:
            add_ioc("sha256", sha256, "Attachment SHA256", "Suspicious" if att.get("is_risky") else "Unknown")
        sha1 = att.get("sha1")
        if sha1:
            add_ioc("sha1", sha1, "Attachment SHA1", "Suspicious" if att.get("is_risky") else "Unknown")
        md5 = att.get("md5")
        if md5:
            add_ioc("md5", md5, "Attachment MD5", "Suspicious" if att.get("is_risky") else "Unknown")

    return iocs
