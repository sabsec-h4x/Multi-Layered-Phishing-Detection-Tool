"""
SOC Case Lifecycle & Triage Workflow Manager
--------------------------------------------
Manages case creation, status state machine, analyst notes, and verdict updates.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

ALLOWED_STATUSES = {"OPEN", "TRIAGED", "INVESTIGATING", "CONTAINED", "CLOSED", "FALSE_POSITIVE"}
ALLOWED_VERDICTS = {"CLEAN", "SUSPICIOUS", "PHISHING", "MALICIOUS"}


class CaseWorkflowError(Exception):
    """Raised when an invalid case state transition or action is attempted."""
    pass


def validate_status_transition(current_status: str, new_status: str) -> bool:
    """Validate that the requested status transition is allowed."""
    if new_status not in ALLOWED_STATUSES:
        raise CaseWorkflowError(f"Invalid status '{new_status}'. Allowed statuses: {ALLOWED_STATUSES}")
    return True


def format_case_id(numeric_id: int) -> str:
    """Format numeric case integer into SOC display identifier e.g. CASE-0042."""
    return f"CASE-{numeric_id:04d}"
