#!/usr/bin/env python3
"""
PhishGuard Enterprise SOC Triage & Threat Intelligence Platform
----------------------------------------------------------------
Web Application & REST API v1.
"""

import os
import json
import threading
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, Response, make_response
from werkzeug.utils import secure_filename

from config import SECRET_KEY, IS_PRODUCTION
from analyzer import parse_email_bytes, parse_email_text, analyze_email
from database.repository import GLOBAL_REPO
from core.campaign_correlator import correlate_cases
from exports.stix_export import export_case_to_stix_bundle
from exports.sigma_export import export_case_to_sigma_rule
from exports.csv_json_export import export_iocs_to_csv, export_case_to_json
from realtime_watch import watch_inbox

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max upload

# In-memory IMAP Watcher State
watcher_state = {
    "running": False,
    "thread": None,
    "stop_event": None,
    "config": {},
    "last_check": None,
    "error": None
}


# ----------------------------------------------------------------------------
# Security Headers Middleware
# ----------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ----------------------------------------------------------------------------
# Web UI Routes
# ----------------------------------------------------------------------------
@app.route("/")
def dashboard():
    cases = GLOBAL_REPO.list_cases(limit=50)
    summary = GLOBAL_REPO.get_stats()
    all_cases_data = [GLOBAL_REPO.get_case_by_id(c["id"]) for c in cases if GLOBAL_REPO.get_case_by_id(c["id"])]
    campaigns = correlate_cases(all_cases_data)
    return render_template("index.html", analyses=cases, cases=cases, summary=summary, campaigns=campaigns, watcher=watcher_state)


@app.route("/cases")
def cases_view():
    status_filter = request.args.get("status")
    cases = GLOBAL_REPO.list_cases(limit=100, status_filter=status_filter)
    summary = GLOBAL_REPO.get_stats()
    return render_template("cases.html", cases=cases, summary=summary, current_status=status_filter)


@app.route("/analyze", methods=["POST"])
def analyze():
    msg = None
    source = "manual"

    uploaded = request.files.get("eml_file")
    pasted = request.form.get("raw_text", "").strip()

    if uploaded and uploaded.filename:
        filename = secure_filename(uploaded.filename)
        data = uploaded.read()
        try:
            msg = parse_email_bytes(data)
        except Exception:
            msg = parse_email_text(data.decode("utf-8", errors="replace"))
        source = f"upload:{filename}"
    elif pasted:
        msg = parse_email_text(pasted)
        source = "pasted"

    if msg is None:
        flash("Could not parse input as an email. Please upload a valid .eml file or paste raw RFC-5322 headers and body.", "error")
        return redirect(url_for("dashboard"))

    result = analyze_email(msg)
    case_id = GLOBAL_REPO.save_analysis_and_case(result, source=source)
    flash(f"Analysis complete! Created Case CASE-{case_id:04d}", "success")
    return redirect(url_for("report", analysis_id=case_id))


@app.route("/report/<int:analysis_id>")
@app.route("/cases/<int:analysis_id>")
def report(analysis_id):
    case = GLOBAL_REPO.get_case_by_id(analysis_id)
    if not case:
        flash("Case report not found.", "error")
        return redirect(url_for("dashboard"))

    # Fetch correlated campaign if any
    all_cases = [GLOBAL_REPO.get_case_by_id(c["id"]) for c in GLOBAL_REPO.list_cases(limit=50)]
    campaigns = correlate_cases([c for c in all_cases if c])
    linked_campaign = next((camp for camp in campaigns if analysis_id in camp["case_ids"]), None)

    return render_template("report.html", case=case, record=case.get("analysis", {}), linked_campaign=linked_campaign)


@app.route("/cases/<int:case_id>/verdict", methods=["POST"])
def update_verdict(case_id):
    new_verdict = request.form.get("verdict", "").strip()
    reason = request.form.get("reason", "").strip()
    analyst = request.form.get("analyst", "analyst").strip()

    if new_verdict in ("CLEAN", "SUSPICIOUS", "PHISHING", "MALICIOUS"):
        GLOBAL_REPO.update_case_verdict(case_id, new_verdict, user=analyst, reason=reason)
        flash(f"Case CASE-{case_id:04d} verdict updated to {new_verdict}.", "success")
    else:
        flash("Invalid verdict specified.", "error")

    return redirect(url_for("report", analysis_id=case_id))


@app.route("/cases/<int:case_id>/status", methods=["POST"])
def update_status(case_id):
    new_status = request.form.get("status", "").strip()
    reason = request.form.get("reason", "").strip()
    analyst = request.form.get("analyst", "analyst").strip()

    if new_status in ("OPEN", "TRIAGED", "INVESTIGATING", "CONTAINED", "CLOSED", "FALSE_POSITIVE"):
        GLOBAL_REPO.update_case_status(case_id, new_status, user=analyst, reason=reason)
        flash(f"Case CASE-{case_id:04d} status updated to {new_status}.", "success")
    else:
        flash("Invalid status specified.", "error")

    return redirect(url_for("report", analysis_id=case_id))


@app.route("/cases/<int:case_id>/notes", methods=["POST"])
def add_note(case_id):
    content = request.form.get("note", "").strip()
    author = request.form.get("author", "analyst").strip()
    if content:
        GLOBAL_REPO.add_case_note(case_id, content, author=author)
        flash("Investigation note added.", "success")
    return redirect(url_for("report", analysis_id=case_id))


# ----------------------------------------------------------------------------
# Export Routes
# ----------------------------------------------------------------------------
@app.route("/cases/<int:case_id>/export/stix")
def export_stix(case_id):
    case = GLOBAL_REPO.get_case_by_id(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    bundle = export_case_to_stix_bundle(case)
    return Response(
        json.dumps(bundle, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=CASE_{case_id:04d}_stix2.1.json"}
    )


@app.route("/cases/<int:case_id>/export/sigma")
def export_sigma(case_id):
    case = GLOBAL_REPO.get_case_by_id(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    yaml_text = export_case_to_sigma_rule(case)
    return Response(
        yaml_text,
        mimetype="text/yaml",
        headers={"Content-Disposition": f"attachment;filename=CASE_{case_id:04d}_detection_rule.yml"}
    )


@app.route("/cases/<int:case_id>/export/csv")
def export_csv(case_id):
    case = GLOBAL_REPO.get_case_by_id(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    csv_text = export_iocs_to_csv(case.get("iocs", []))
    return Response(
        csv_text,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=CASE_{case_id:04d}_iocs.csv"}
    )


@app.route("/cases/<int:case_id>/export/json")
def export_json(case_id):
    case = GLOBAL_REPO.get_case_by_id(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    json_text = export_case_to_json(case)
    return Response(
        json_text,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=CASE_{case_id:04d}_report.json"}
    )


# ----------------------------------------------------------------------------
# Watcher Background Control
# ----------------------------------------------------------------------------
@app.route("/watch/start", methods=["POST"])
def watch_start():
    if watcher_state["running"]:
        flash("Watcher is already running.", "error")
        return redirect(url_for("dashboard"))

    imap_server = request.form.get("imap_server", "").strip()
    user = request.form.get("user", "").strip()
    password = request.form.get("password", "")
    folder = request.form.get("folder", "INBOX").strip() or "INBOX"
    interval = int(request.form.get("interval", 30) or 30)

    if not imap_server or not user or not password:
        flash("IMAP server, username, and password are all required to start watching.", "error")
        return redirect(url_for("dashboard"))

    stop_event = threading.Event()
    thread = threading.Thread(
        target=watch_inbox,
        args=(imap_server, user, password, folder, interval, stop_event, watcher_state),
        daemon=True
    )
    watcher_state.update({
        "running": True, "thread": thread, "stop_event": stop_event,
        "config": {"imap_server": imap_server, "user": user, "folder": folder, "interval": interval},
        "error": None
    })
    thread.start()
    flash(f"Started monitoring {user} ({folder}) every {interval}s.", "success")
    return redirect(url_for("dashboard"))


@app.route("/watch/stop", methods=["POST"])
def watch_stop():
    if watcher_state["running"] and watcher_state["stop_event"]:
        watcher_state["stop_event"].set()
    watcher_state.update({"running": False, "thread": None, "stop_event": None})
    flash("Stopped mailbox monitoring.", "success")
    return redirect(url_for("dashboard"))


# ----------------------------------------------------------------------------
# REST API v1 Endpoints
# ----------------------------------------------------------------------------
@app.route("/api/v1/analyze", methods=["POST"])
def api_v1_analyze():
    """POST /api/v1/analyze - Ingest and triage an email via REST API."""
    data = None
    source = "api"

    if request.is_json:
        body = request.get_json()
        raw_text = body.get("raw_text")
        if raw_text:
            msg = parse_email_text(raw_text)
        else:
            return jsonify({"error": "Missing 'raw_text' in JSON request body"}), 400
    elif "eml_file" in request.files:
        f = request.files["eml_file"]
        raw_bytes = f.read()
        try:
            msg = parse_email_bytes(raw_bytes)
        except Exception:
            msg = parse_email_text(raw_bytes.decode("utf-8", errors="replace"))
        source = f"api_upload:{secure_filename(f.filename)}"
    else:
        return jsonify({"error": "Provide raw_text in JSON body or upload eml_file multipart"}), 400

    if msg is None:
        return jsonify({"error": "Could not parse payload as RFC-5322 email"}), 400

    result = analyze_email(msg)
    case_id = GLOBAL_REPO.save_analysis_and_case(result, source=source)
    case = GLOBAL_REPO.get_case_by_id(case_id)
    return jsonify({"success": True, "case_id": case_id, "case": case}), 201


@app.route("/api/v1/cases", methods=["GET"])
def api_v1_list_cases():
    status = request.args.get("status")
    limit = int(request.args.get("limit", 50))
    cases = GLOBAL_REPO.list_cases(limit=limit, status_filter=status)
    return jsonify({"cases": cases, "count": len(cases)})


@app.route("/api/v1/cases/<int:case_id>", methods=["GET"])
def api_v1_get_case(case_id):
    case = GLOBAL_REPO.get_case_by_id(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify({"case": case})


@app.route("/api/v1/cases/<int:case_id>/verdict", methods=["POST"])
def api_v1_update_verdict(case_id):
    body = request.get_json() or {}
    verdict = body.get("verdict")
    reason = body.get("reason", "")
    user = body.get("user", "api_analyst")

    if verdict not in ("CLEAN", "SUSPICIOUS", "PHISHING", "MALICIOUS"):
        return jsonify({"error": "Invalid verdict"}), 400

    success = GLOBAL_REPO.update_case_verdict(case_id, verdict, user=user, reason=reason)
    if not success:
        return jsonify({"error": "Case not found"}), 404
    return jsonify({"success": True, "case_id": case_id, "new_verdict": verdict})


@app.route("/api/v1/cases/<int:case_id>/notes", methods=["POST"])
def api_v1_add_note(case_id):
    body = request.get_json() or {}
    content = body.get("note", "")
    author = body.get("author", "api_analyst")
    if not content:
        return jsonify({"error": "Missing 'note' parameter"}), 400

    success = GLOBAL_REPO.add_case_note(case_id, content, author=author)
    if not success:
        return jsonify({"error": "Case not found"}), 404
    return jsonify({"success": True, "case_id": case_id, "note": content}), 201


@app.route("/api/v1/iocs", methods=["GET"])
def api_v1_iocs():
    ioc_type = request.args.get("type")
    limit = int(request.args.get("limit", 100))
    iocs = GLOBAL_REPO.list_all_iocs(limit=limit, ioc_type=ioc_type)
    return jsonify({"iocs": iocs, "count": len(iocs)})


@app.route("/api/v1/campaigns", methods=["GET"])
def api_v1_campaigns():
    all_cases = [GLOBAL_REPO.get_case_by_id(c["id"]) for c in GLOBAL_REPO.list_cases(limit=100)]
    campaigns = correlate_cases([c for c in all_cases if c])
    return jsonify({"campaigns": campaigns, "count": len(campaigns)})


@app.route("/api/v1/stats", methods=["GET"])
def api_v1_stats():
    return jsonify(GLOBAL_REPO.get_stats())


@app.route("/api/v1/health", methods=["GET"])
def api_v1_health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0",
        "service": "PhishGuard SOC Triage Engine"
    })


@app.route("/api/recent")
def api_recent():
    """Legacy dashboard polling endpoint."""
    return jsonify({
        "analyses": GLOBAL_REPO.list_analyses(limit=50),
        "summary": GLOBAL_REPO.get_stats(),
        "watcher": {
            "running": watcher_state["running"],
            "last_check": watcher_state["last_check"],
            "error": watcher_state["error"]
        }
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
