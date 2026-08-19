"""
STIX 2.1 Threat Intelligence Bundle Exporter
--------------------------------------------
Generates standardized OASIS STIX 2.1 JSON bundles representing
email messages, URLs, domains, IP addresses, file hashes, and SDO relationships.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List


def export_case_to_stix_bundle(case_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a PhishGuard SOC case into a valid STIX 2.1 JSON Bundle.
    """
    case_id = case_record.get("id", 1)
    case_number = case_record.get("case_number", f"CASE-{case_id:04d}")
    title = case_record.get("title", "Phishing Triage Case")
    verdict = case_record.get("verdict", "SUSPICIOUS")
    score = case_record.get("score", 0)

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    bundle_id = f"bundle--{uuid.uuid4()}"

    objects: List[Dict[str, Any]] = []

    # 1. Identity Object (Organization / Analyst reporting)
    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'phishguard.local')}"
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_iso,
        "modified": now_iso,
        "name": "PhishGuard SOC Triage Platform",
        "identity_class": "system",
    })

    # 2. Report / Case Object
    report_id = f"report--{uuid.uuid4()}"
    report_object_refs = [identity_id]

    # 3. Extract Indicators & Observables
    analysis = case_record.get("analysis", {}).get("result", {})
    iocs = case_record.get("iocs", [])

    for ioc in iocs:
        itype = ioc.get("ioc_type")
        val = ioc.get("ioc_value")
        if not val:
            continue

        ind_id = f"indicator--{uuid.uuid4()}"
        pattern = None

        if itype == "url":
            pattern = f"[url:value = '{val}']"
        elif itype == "domain":
            pattern = f"[domain-name:value = '{val}']"
        elif itype == "ip":
            pattern = f"[ipv4-addr:value = '{val}']"
        elif itype == "sha256":
            pattern = f"[file:hashes.'SHA-256' = '{val}']"
        elif itype == "email":
            pattern = f"[email-addr:value = '{val}']"

        if pattern:
            ind_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created": now_iso,
                "modified": now_iso,
                "name": f"PhishGuard IOC: {val}",
                "description": f"Extracted during email phishing triage for {case_number}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now_iso,
                "confidence": 85 if verdict in ("PHISHING", "MALICIOUS") else 50,
                "indicator_types": ["malicious-activity" if verdict in ("PHISHING", "MALICIOUS") else "anomalous-activity"],
                "created_by_ref": identity_id,
            }
            objects.append(ind_obj)
            report_object_refs.append(ind_id)

    # Final Report Object
    report_obj = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now_iso,
        "modified": now_iso,
        "name": f"Email Phishing Investigation [{case_number}] - {title}",
        "description": f"PhishGuard SOC Triage Report with score {score}/100 and verdict {verdict}",
        "published": now_iso,
        "report_types": ["threat-report"],
        "object_refs": report_object_refs,
        "created_by_ref": identity_id,
    }
    objects.append(report_obj)

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects
    }
