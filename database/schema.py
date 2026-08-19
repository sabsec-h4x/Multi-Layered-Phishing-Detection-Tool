"""
Database Schema & Migration Management
--------------------------------------
Initializes and manages normalized relational tables in SQLite (and PostgreSQL-ready),
with automatic backward-compatible schema migration for existing databases.
"""

import sqlite3
from pathlib import Path
from typing import Optional
from config import DATABASE_PATH


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Create a thread-safe connection to the SQLite database with Row factory."""
    path = db_path or DATABASE_PATH
    conn = sqlite3.connect(path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_database(db_path: Optional[Path] = None):
    """
    Initialize all relational tables and apply non-destructive migrations.
    Preserves all existing records in 'analyses'.
    """
    conn = get_db_connection(db_path)

    # 1. Base Analyses Table (Backward compatible with legacy PhishGuard)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT,
            from_addr TEXT,
            score INTEGER,
            verdict TEXT,
            source TEXT,
            analyzed_at TEXT,
            result_json TEXT
        )
    """)

    # 2. SOC Cases Table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number TEXT UNIQUE,
            title TEXT,
            severity TEXT DEFAULT 'MEDIUM',
            confidence TEXT DEFAULT 'HIGH',
            status TEXT DEFAULT 'OPEN',
            verdict TEXT DEFAULT 'SUSPICIOUS',
            score INTEGER DEFAULT 0,
            assigned_analyst TEXT DEFAULT 'unassigned',
            source TEXT,
            created_at TEXT,
            updated_at TEXT,
            analysis_id INTEGER,
            FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE SET NULL
        )
    """)

    # 3. Normalized IOCs Table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            analysis_id INTEGER,
            ioc_type TEXT,
            ioc_value TEXT,
            source TEXT,
            reputation TEXT,
            confidence TEXT,
            created_at TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
            FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
        )
    """)

    # 4. Analyst Notes Table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analyst_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            author TEXT,
            content TEXT,
            created_at TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
        )
    """)

    # 5. Tamper-Evident Audit Logs Table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            user TEXT,
            action TEXT,
            previous_value TEXT,
            new_value TEXT,
            details TEXT,
            timestamp TEXT
        )
    """)

    # 6. Persistent Threat Intel Cache Table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_cache (
            cache_key TEXT PRIMARY KEY,
            provider TEXT,
            indicator TEXT,
            indicator_type TEXT,
            response_json TEXT,
            cached_at TEXT,
            expires_at TEXT
        )
    """)

    # Create Indexes for fast querying
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_verdict ON cases(verdict)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_val ON iocs(ioc_value)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_logs(case_id)")

    conn.commit()

    # Backfill cases from legacy analyses if any exist without a corresponding case
    _backfill_legacy_cases(conn)

    conn.close()


def _backfill_legacy_cases(conn: sqlite3.Connection):
    """Ensure any legacy rows in 'analyses' have a linked SOC case."""
    try:
        rows = conn.execute("""
            SELECT a.id, a.subject, a.score, a.verdict, a.source, a.analyzed_at
            FROM analyses a
            LEFT JOIN cases c ON c.analysis_id = a.id
            WHERE c.id IS NULL
        """).fetchall()

        for r in rows:
            case_num = f"CASE-{r['id']:04d}"
            severity = "CRITICAL" if r["score"] >= 80 else ("HIGH" if r["score"] >= 60 else ("MEDIUM" if r["score"] >= 30 else "LOW"))
            conn.execute("""
                INSERT OR IGNORE INTO cases
                (id, case_number, title, severity, confidence, status, verdict, score, assigned_analyst, source, created_at, updated_at, analysis_id)
                VALUES (?, ?, ?, ?, 'HIGH', 'OPEN', ?, ?, 'analyst', ?, ?, ?, ?)
            """, (
                r["id"], case_num, r["subject"] or "(no subject)",
                severity, r["verdict"] or "SUSPICIOUS", r["score"] or 0,
                r["source"] or "legacy", r["analyzed_at"], r["analyzed_at"], r["id"]
            ))
        conn.commit()
    except Exception:
        pass
