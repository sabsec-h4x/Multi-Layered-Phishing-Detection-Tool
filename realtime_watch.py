"""
Near-Real-Time Inbox Monitoring & IMAP Poller
---------------------------------------------
Connects securely via IMAP4_SSL, checks for unseen messages at configured intervals,
runs the full PhishGuard triage engine, persists cases and IOCs to the database,
and streams real-time alerts.
"""

import time
import imaplib
import email as email_lib
from datetime import datetime, timezone
from typing import Optional, Any

from analyzer import analyze_email
from database.repository import GLOBAL_REPO
from config import DEFAULT_IMAP_INTERVAL


def watch_inbox(imap_server: str,
                user: str,
                password: str,
                folder: str = "INBOX",
                interval: int = DEFAULT_IMAP_INTERVAL,
                stop_event: Optional[Any] = None,
                status_dict: Optional[dict] = None):
    """
    Monitor an IMAP mailbox continuously.
    """
    print(f"[PhishGuard] Connecting to IMAP server {imap_server} as {user} ...")
    try:
        conn = imaplib.IMAP4_SSL(imap_server)
        conn.login(user, password)
        print(f"[PhishGuard] Connected. Monitoring '{folder}' every {interval}s. Press Ctrl+C to stop.\n")
        if status_dict:
            status_dict["running"] = True
            status_dict["error"] = None
    except Exception as e:
        err_msg = f"IMAP connection/login failed: {e}"
        print(f"[PhishGuard] Error: {err_msg}")
        if status_dict:
            status_dict["running"] = False
            status_dict["error"] = err_msg
        return

    try:
        while True:
            if stop_event and stop_event.is_set():
                break

            try:
                conn.select(folder)
                status, data = conn.search(None, "UNSEEN")
                if status == "OK" and data[0]:
                    msg_ids = data[0].split()
                    for msg_id in msg_ids:
                        status, msg_data = conn.fetch(msg_id, "(RFC822)")
                        if status != "OK":
                            continue

                        raw_bytes = msg_data[0][1]
                        msg = email_lib.message_from_bytes(raw_bytes)
                        result = analyze_email(msg)

                        # Save to database repository
                        case_id = GLOBAL_REPO.save_analysis_and_case(result, source=f"imap_watch:{user}")

                        ts = datetime.now().strftime("%H:%M:%S")
                        verdict = result.get("verdict", "SUSPICIOUS")
                        tag = "🚨 MALICIOUS" if verdict == "MALICIOUS" else (
                            "🚨 PHISHING" if verdict == "PHISHING" else (
                                "⚠️  SUSPICIOUS" if verdict == "SUSPICIOUS" else "✅ CLEAN"
                            )
                        )
                        print(f"[{ts}] [CASE-{case_id:04d}] {tag} (score: {result.get('score'):>3}) "
                              f"From: {result.get('from_addr')} | Subject: \"{result.get('subject')[:50]}\"")

                if status_dict:
                    status_dict["last_check"] = datetime.now(timezone.utc).isoformat()
                    status_dict["error"] = None

            except Exception as e:
                err = f"Inbox check error: {e}"
                print(f"[PhishGuard] {err}")
                if status_dict:
                    status_dict["error"] = err

            if stop_event:
                stop_event.wait(interval)
            else:
                time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[PhishGuard] Inbox watcher stopped by user.")
    finally:
        try:
            conn.logout()
        except Exception:
            pass
        if status_dict:
            status_dict["running"] = False
