"""
PhishGuard Storage Integration Bridge
-------------------------------------
Maintains backward compatibility for legacy app.py and CLI calls
while routing through the normalized SOCRepository database layer.
"""

from database.repository import GLOBAL_REPO
from database.schema import init_database


def init_db():
    """Initialize database schema and run migrations."""
    init_database()


def save_analysis(result, source="manual"):
    """Save an analysis and auto-generate corresponding SOC case and normalized IOCs."""
    return GLOBAL_REPO.save_analysis_and_case(result, source=source)


def get_analysis(analysis_id):
    """Retrieve an analysis by ID."""
    return GLOBAL_REPO.get_analysis_by_id(analysis_id)


def list_analyses(limit=50):
    """List recent analyses for the dashboard."""
    return GLOBAL_REPO.list_analyses(limit=limit)


def stats():
    """Retrieve dashboard summary metrics."""
    return GLOBAL_REPO.get_stats()
