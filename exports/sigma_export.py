"""
Sigma Detection Rule Exporter
-----------------------------
Generates Sigma-compatible YAML detection rules from observed phishing indicators.
"""

from typing import Dict, Any
from datetime import datetime, timezone


def export_case_to_sigma_rule(case_record: Dict[str, Any]) -> str:
    """
    Generate a Sigma detection rule YAML string from case indicators.
    """
    case_id = case_record.get("id", 1)
    case_number = case_record.get("case_number", f"CASE-{case_id:04d}")
    title = case_record.get("title", "Phishing Campaign Activity")
    verdict = case_record.get("verdict", "SUSPICIOUS")
    severity = case_record.get("severity", "medium").lower()

    now_date = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    iocs = case_record.get("iocs", [])
    domains = [i["ioc_value"] for i in iocs if i.get("ioc_type") == "domain"]
    urls = [i["ioc_value"] for i in iocs if i.get("ioc_type") == "url"]
    senders = [i["ioc_value"] for i in iocs if i.get("ioc_type") == "email"]

    yaml_lines = [
        f"title: PhishGuard Detection — {title}",
        f"id: 5f{case_id:06d}-c4a1-4d92-9e20-7b1e8432a109",
        f"status: experimental",
        f"description: Detects network and mail activity matching {case_number} ({verdict})",
        f"references:",
        f"    - https://phishguard.local/cases/{case_id}",
        f"author: PhishGuard SOC Platform",
        f"date: {now_date}",
        f"tags:",
        f"    - attack.initial_access",
        f"    - attack.t1566.002",
        f"logsource:",
        f"    category: proxy",
        f"detection:",
        f"    selection_domains:",
    ]

    if domains:
        yaml_lines.append("        c-uri-domain:")
        for dom in domains[:10]:
            yaml_lines.append(f"            - '{dom}'")
    elif urls:
        yaml_lines.append("        c-uri:")
        for u in urls[:5]:
            yaml_lines.append(f"            - '{u}'")
    else:
        yaml_lines.append("        c-uri-domain:")
        yaml_lines.append("            - 'example-placeholder.com'")

    yaml_lines.extend([
        f"    condition: selection_domains",
        f"falsepositives:",
        f"    - Legitimate user navigation to newly registered business partner domains",
        f"level: {severity}",
    ])

    return "\n".join(yaml_lines)
