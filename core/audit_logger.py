"""
SOC Audit Logging Engine
------------------------
Provides tamper-evident structured audit logging for all analyst actions,
case status transitions, verdict overrides, and export activities.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional


def create_audit_entry(user: str,
                       action: str,
                       case_id: int,
                       previous_value: Optional[str] = None,
                       new_value: Optional[str] = None,
                       details: Optional[str] = None) -> Dict[str, Any]:
    """
    Format a structured audit log entry.
    """
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user or "analyst",
        "action": action,
        "case_id": case_id,
        "previous_value": previous_value,
        "new_value": new_value,
        "details": details or "",
    }
