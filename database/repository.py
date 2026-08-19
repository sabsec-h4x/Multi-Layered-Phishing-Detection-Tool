"""
Database Repository & Data Access Layer
---------------------------------------
Provides high-level repository operations for analyses, cases, IOCs,
analyst notes, and audit logs.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from database.schema import get_db_connection, init_database
from core.ioc_extractor import extract_normalized_iocs
from core.audit_logger import create_audit_entry


class SOCRepository:
    """Central Data Access Repository."""

    def __init__(self):
        init_database()

    def save_analysis_and_case(self, analysis_result: Dict[str, Any], source: str = "manual") -> int:
        """
        Atomically save analysis JSON, create a corresponding SOC Case,
        extract normalized IOCs, and record an audit log entry.
        """
        conn = get_db_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        subject = analysis_result.get("subject", "(no subject)")
        from_addr = analysis_result.get("from_addr", "unknown")
        score = analysis_result.get("score", 0)
        verdict = analysis_result.get("verdict", "SUSPICIOUS")
        severity = analysis_result.get("severity", "MEDIUM")
        confidence = analysis_result.get("confidence", "HIGH")

        # 1. Insert analysis record
        cur = conn.execute("""
            INSERT INTO analyses (subject, from_addr, score, verdict, source, analyzed_at, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (subject, from_addr, score, verdict, source, now_iso, json.dumps(analysis_result, default=str)))
        analysis_id = cur.lastrowid

        # 2. Insert SOC Case record
        case_number = f"CASE-{analysis_id:04d}"
        cur_case = conn.execute("""
            INSERT INTO cases (id, case_number, title, severity, confidence, status, verdict, score, assigned_analyst, source, created_at, updated_at, analysis_id)
            VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, 'analyst', ?, ?, ?, ?)
        """, (analysis_id, case_number, subject, severity, confidence, verdict, score, source, now_iso, now_iso, analysis_id))
        case_id = analysis_id

        # 3. Extract and insert normalized IOCs
        iocs = extract_normalized_iocs(analysis_result)
        for ioc in iocs:
            conn.execute("""
                INSERT INTO iocs (case_id, analysis_id, ioc_type, ioc_value, source, reputation, confidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (case_id, analysis_id, ioc["type"], ioc["value"], ioc["source"], ioc["reputation"], ioc["confidence"], now_iso))

        # 4. Insert initial audit log
        audit = create_audit_entry(
            user="system",
            action="CASE_CREATED",
            case_id=case_id,
            new_value=f"Status: OPEN, Verdict: {verdict}, Score: {score}",
            details=f"Email ingested via {source} from {from_addr}"
        )
        conn.execute("""
            INSERT INTO audit_logs (case_id, user, action, previous_value, new_value, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (case_id, audit["user"], audit["action"], audit["previous_value"], audit["new_value"], audit["details"], audit["timestamp"]))

        conn.commit()
        conn.close()
        return analysis_id

    def get_analysis_by_id(self, analysis_id: int) -> Optional[Dict[str, Any]]:
        """Fetch full analysis record with parsed JSON."""
        conn = get_db_connection()
        row = conn.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        conn.close()
        if not row:
            return None
        result = json.loads(row["result_json"])
        return {
            "id": row["id"],
            "subject": row["subject"],
            "from_addr": row["from_addr"],
            "score": row["score"],
            "verdict": row["verdict"],
            "source": row["source"],
            "analyzed_at": row["analyzed_at"],
            "result": result,
        }

    def get_case_by_id(self, case_id: int) -> Optional[Dict[str, Any]]:
        """Fetch detailed case record including analysis JSON, notes, audit logs, and IOCs."""
        conn = get_db_connection()
        case_row = conn.execute("SELECT * FROM cases WHERE id = ? OR case_number = ?", (case_id, f"CASE-{case_id:04d}")).fetchone()
        if not case_row:
            conn.close()
            return None

        cid = case_row["id"]
        # Fetch analysis
        analysis_record = None
        if case_row["analysis_id"]:
            a_row = conn.execute("SELECT * FROM analyses WHERE id = ?", (case_row["analysis_id"],)).fetchone()
            if a_row:
                analysis_record = {
                    "id": a_row["id"],
                    "source": a_row["source"],
                    "analyzed_at": a_row["analyzed_at"],
                    "result": json.loads(a_row["result_json"]),
                }

        # Fetch IOCs
        iocs_rows = conn.execute("SELECT * FROM iocs WHERE case_id = ? ORDER BY id ASC", (cid,)).fetchall()
        iocs = [dict(r) for r in iocs_rows]

        # Fetch Notes
        notes_rows = conn.execute("SELECT * FROM analyst_notes WHERE case_id = ? ORDER BY id DESC", (cid,)).fetchall()
        notes = [dict(r) for r in notes_rows]

        # Fetch Audit Logs
        audit_rows = conn.execute("SELECT * FROM audit_logs WHERE case_id = ? ORDER BY id DESC", (cid,)).fetchall()
        audit_logs = [dict(r) for r in audit_rows]

        conn.close()

        case_dict = dict(case_row)
        case_dict["analysis"] = analysis_record
        case_dict["iocs"] = iocs
        case_dict["notes"] = notes
        case_dict["audit_logs"] = audit_logs
        return case_dict

    def update_case_verdict(self, case_id: int, new_verdict: str, user: str = "analyst", reason: str = "") -> bool:
        """Update case verdict and record audit log."""
        conn = get_db_connection()
        case_row = conn.execute("SELECT verdict, score FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not case_row:
            conn.close()
            return False

        prev_verdict = case_row["verdict"]
        now_iso = datetime.now(timezone.utc).isoformat()

        conn.execute("UPDATE cases SET verdict = ?, updated_at = ? WHERE id = ?", (new_verdict, now_iso, case_id))
        conn.execute("UPDATE analyses SET verdict = ? WHERE id = ?", (new_verdict, case_id))

        audit = create_audit_entry(
            user=user,
            action="VERDICT_OVERRIDE",
            case_id=case_id,
            previous_value=prev_verdict,
            new_value=new_dict if 'new_dict' in locals() else new_verdict,
            details=reason or f"Analyst changed verdict from {prev_verdict} to {new_verdict}"
        )
        conn.execute("""
            INSERT INTO audit_logs (case_id, user, action, previous_value, new_value, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (case_id, audit["user"], audit["action"], audit["previous_value"], audit["new_value"], audit["details"], audit["timestamp"]))

        conn.commit()
        conn.close()
        return True

    def update_case_status(self, case_id: int, new_status: str, user: str = "analyst", reason: str = "") -> bool:
        """Update case status (OPEN, TRIAGED, INVESTIGATING, CONTAINED, CLOSED, FALSE_POSITIVE)."""
        conn = get_db_connection()
        case_row = conn.execute("SELECT status FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not case_row:
            conn.close()
            return False

        prev_status = case_row["status"]
        now_iso = datetime.now(timezone.utc).isoformat()

        conn.execute("UPDATE cases SET status = ?, updated_at = ? WHERE id = ?", (new_status, now_iso, case_id))

        audit = create_audit_entry(
            user=user,
            action="STATUS_CHANGE",
            case_id=case_id,
            previous_value=prev_status,
            new_value=new_status,
            details=reason or f"Case status updated from {prev_status} to {new_status}"
        )
        conn.execute("""
            INSERT INTO audit_logs (case_id, user, action, previous_value, new_value, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (case_id, audit["user"], audit["action"], audit["previous_value"], audit["new_value"], audit["details"], audit["timestamp"]))

        conn.commit()
        conn.close()
        return True

    def add_case_note(self, case_id: int, content: str, author: str = "analyst") -> bool:
        """Add an analyst investigation note to a case."""
        if not content:
            return False
        conn = get_db_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute("""
            INSERT INTO analyst_notes (case_id, author, content, created_at)
            VALUES (?, ?, ?, ?)
        """, (case_id, author, content.strip(), now_iso))

        audit = create_audit_entry(
            user=author,
            action="NOTE_ADDED",
            case_id=case_id,
            details=f"Analyst note added: {content[:80]}"
        )
        conn.execute("""
            INSERT INTO audit_logs (case_id, user, action, previous_value, new_value, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (case_id, audit["user"], audit["action"], audit["previous_value"], audit["new_value"], audit["details"], audit["timestamp"]))

        conn.commit()
        conn.close()
        return True

    def list_cases(self, limit: int = 50, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """List cases with optional status filter."""
        conn = get_db_connection()
        if status_filter:
            rows = conn.execute("""
                SELECT * FROM cases WHERE status = ? ORDER BY id DESC LIMIT ?
            """, (status_filter, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM cases ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def list_analyses(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List analyses for backward-compatibility with legacy dashboard."""
        conn = get_db_connection()
        rows = conn.execute("""
            SELECT id, subject, from_addr, score, verdict, source, analyzed_at
            FROM analyses ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        """Compute aggregate triage and case metrics."""
        conn = get_db_connection()
        stats_row = conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN verdict = 'PHISHING' THEN 1 ELSE 0 END) as phishing,
                SUM(CASE WHEN verdict = 'MALICIOUS' THEN 1 ELSE 0 END) as malicious,
                SUM(CASE WHEN verdict = 'SUSPICIOUS' THEN 1 ELSE 0 END) as suspicious,
                SUM(CASE WHEN verdict IN ('LIKELY CLEAN', 'CLEAN', 'LIKELY LEGITIMATE') THEN 1 ELSE 0 END) as clean
            FROM analyses
        """).fetchone()

        case_stats = conn.execute("""
            SELECT
                SUM(CASE WHEN status = 'OPEN' THEN 1 ELSE 0 END) as open_cases,
                SUM(CASE WHEN severity = 'CRITICAL' AND status != 'CLOSED' THEN 1 ELSE 0 END) as critical_alerts,
                SUM(CASE WHEN status = 'INVESTIGATING' THEN 1 ELSE 0 END) as investigating_cases
            FROM cases
        """).fetchone()

        conn.close()

        total = stats_row["total"] or 0
        phishing = (stats_row["phishing"] or 0) + (stats_row["malicious"] or 0)
        suspicious = stats_row["suspicious"] or 0
        clean = stats_row["clean"] or 0

        return {
            "total": total,
            "phishing": phishing,
            "suspicious": suspicious,
            "clean": clean,
            "open_cases": case_stats["open_cases"] or 0,
            "critical_alerts": case_stats["critical_alerts"] or 0,
            "investigating_cases": case_stats["investigating_cases"] or 0,
        }

    def list_all_iocs(self, limit: int = 100, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """List normalized IOCs with optional type filtering."""
        conn = get_db_connection()
        if ioc_type:
            rows = conn.execute("SELECT * FROM iocs WHERE ioc_type = ? ORDER BY id DESC LIMIT ?", (ioc_type, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM iocs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]


GLOBAL_REPO = SOCRepository()
