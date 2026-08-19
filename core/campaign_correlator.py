"""
Historical Case & Threat Campaign Correlation Engine
-----------------------------------------------------
Clusters historical email triage cases into threat campaigns based on
shared domains, IP relays, attachment hashes, and certificate fingerprints.
"""

from typing import Dict, Any, List, Set
from collections import defaultdict


def correlate_cases(case_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Given a list of case records, cluster them by common indicators to identify campaigns.
    """
    indicator_to_cases: Dict[str, Set[int]] = defaultdict(set)
    case_map: Dict[int, Dict[str, Any]] = {}

    for c in case_records:
        cid = c.get("id")
        if not cid:
            continue
        case_map[cid] = c

        # Extract indicators from case
        iocs = c.get("iocs", [])
        if isinstance(iocs, dict):
            for dom in iocs.get("domains", []):
                indicator_to_cases[f"domain:{dom}"].add(cid)
            for h in iocs.get("hashes", []):
                indicator_to_cases[f"hash:{h}"].add(cid)
        elif isinstance(iocs, list):
            for item in iocs:
                val = item.get("value")
                itype = item.get("type")
                if val and itype in ("domain", "ip", "sha256", "email"):
                    # Ignore common generic domains
                    if val not in ("gmail.com", "outlook.com", "yahoo.com", "microsoft.com", "google.com"):
                        indicator_to_cases[f"{itype}:{val}"].add(cid)

    # Build clusters
    campaigns = []
    processed_clusters: Set[frozenset] = set()

    for ind, cids in indicator_to_cases.items():
        if len(cids) >= 2:
            cluster_key = frozenset(cids)
            if cluster_key in processed_clusters:
                continue
            processed_clusters.add(cluster_key)

            related_cases = [case_map[cid] for cid in cids if cid in case_map]
            all_shared_indicators = [
                k for k, linked_cids in indicator_to_cases.items()
                if linked_cids & cluster_key
            ]

            timestamps = [c.get("created_at") or c.get("analyzed_at") for c in related_cases if c.get("created_at") or c.get("analyzed_at")]
            first_seen = min(timestamps) if timestamps else "unknown"
            last_seen = max(timestamps) if timestamps else "unknown"

            ind_type, ind_val = ind.split(":", 1)
            campaign_title = f"Campaign: {ind_val}"

            campaigns.append({
                "name": campaign_title,
                "primary_indicator": ind,
                "case_count": len(related_cases),
                "case_ids": sorted(list(cids)),
                "shared_indicators": all_shared_indicators[:10],
                "first_seen": first_seen,
                "last_seen": last_seen,
                "severity": "HIGH" if any(c.get("verdict") in ("PHISHING", "MALICIOUS") for c in related_cases) else "MEDIUM"
            })

    return sorted(campaigns, key=lambda x: x["case_count"], reverse=True)
