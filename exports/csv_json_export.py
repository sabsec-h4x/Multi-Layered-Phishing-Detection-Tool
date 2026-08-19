"""
CSV and JSON IOC & Case Exporter
--------------------------------
Generates clean CSV tables and formatted JSON files for IOC extraction and case dumps.
"""

import io
import csv
import json
from typing import List, Dict, Any


def export_iocs_to_csv(iocs: List[Dict[str, Any]]) -> str:
    """Generate CSV string from list of IOC objects."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Type", "Value", "Source", "Reputation", "Confidence", "Created At"])
    for ioc in iocs:
        writer.writerow([
            ioc.get("ioc_type") or ioc.get("type", ""),
            ioc.get("ioc_value") or ioc.get("value", ""),
            ioc.get("source", ""),
            ioc.get("reputation", ""),
            ioc.get("confidence", ""),
            ioc.get("created_at", ""),
        ])
    return output.getvalue()


def export_case_to_json(case_record: Dict[str, Any]) -> str:
    """Generate pretty-printed JSON representation of full case record."""
    return json.dumps(case_record, indent=2, default=str)
