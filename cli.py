#!/usr/bin/env python3
"""
PhishGuard CLI — Enterprise SOC Analyst Terminal Tool
------------------------------------------------------
Usage:
  python cli.py analyze path/to/email.eml
  python cli.py analyze path/to/email.eml --json report.json --stix stix_bundle.json --sigma rule.yml
  cat email.txt | python cli.py analyze -
  python cli.py cases
  python cli.py case 1
  python cli.py update-verdict 1 MALICIOUS --reason "Confirmed credential harvesting campaign"
  python cli.py add-note 1 "Quarantined email across enterprise exchange"
  python cli.py watch --imap-server imap.gmail.com --user you@gmail.com --password APP_PASSWORD
"""

import sys
import json
import argparse
from typing import Dict, Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from analyzer import parse_email_bytes, parse_email_text, analyze_email
from database.repository import GLOBAL_REPO
from exports.stix_export import export_case_to_stix_bundle
from exports.sigma_export import export_case_to_sigma_rule
from exports.csv_json_export import export_iocs_to_csv

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
DIM = "\033[2m"


def verdict_color(v: str) -> str:
    return {
        "MALICIOUS": RED, "PHISHING": RED, "CRITICAL": RED,
        "SUSPICIOUS": YELLOW, "HIGH": YELLOW, "MEDIUM": YELLOW,
        "CLEAN": GREEN, "LIKELY CLEAN": GREEN, "LIKELY LEGITIMATE": GREEN, "LOW": GREEN, "INFO": CYAN
    }.get(str(v).upper(), RESET)


def print_soc_report(result: Dict[str, Any], case_id: int = None):
    vc = verdict_color(result.get("verdict", "SUSPICIOUS"))
    sec_vc = verdict_color(result.get("severity", "MEDIUM"))

    print(f"\n{BOLD}{'=' * 80}{RESET}")
    print(f"{CYAN}{BOLD}▲ PHISHGUARD SOC EMAIL TRIAGE & FORENSIC REPORT{RESET}")
    if case_id:
        print(f"{BOLD}Case ID:{RESET}   CASE-{case_id:04d}")
    print(f"{BOLD}Subject:{RESET}   {result.get('subject')}")
    print(f"{BOLD}From:{RESET}      {result.get('from_addr')}")
    print(f"{BOLD}Verdict:{RESET}   {vc}{result.get('verdict')}{RESET} | {BOLD}Severity:{RESET} {sec_vc}{result.get('severity')}{RESET} | {BOLD}Score:{RESET} {result.get('score')}/100 | {BOLD}Confidence:{RESET} {result.get('confidence')}")
    if result.get("trust_discount"):
        print(f"{DIM}  (Raw Score: {result.get('raw_score')}, -{result.get('trust_discount')} Verified Sender Trust Discount){RESET}")
    print(f"{BOLD}{'=' * 80}{RESET}")

    # Forensic Risk Pillars
    pillars = result.get("risk_pillars", {})
    if pillars:
        print(f"\n{BOLD}-- Forensic Risk Pillars --{RESET}")
        print(f"  Identity: {pillars.get('identity_risk')}/100  |  URL: {pillars.get('url_risk')}/100  |  Content: {pillars.get('content_risk')}/100")
        print(f"  Attachment: {pillars.get('attachment_risk')}/100  |  Behavioral/Modern: {pillars.get('behavioral_risk')}/100  |  Threat Intel: {pillars.get('threat_intel_risk')}/100")

    # Why Suspicious?
    why = result.get("why_suspicious", [])
    if why:
        print(f"\n{BOLD}{YELLOW}-- Evidence Summary (Why is this suspicious?) --{RESET}")
        for idx, item in enumerate(why, start=1):
            print(f"  {RED}{idx}.{RESET} {item}")

    # Findings Breakdown
    def print_section(title, findings):
        if not findings:
            return
        print(f"\n{BOLD}-- {title} --{RESET}")
        for f in findings:
            flag = f.get("flag")
            mark = f"{RED}[!!]{RESET}" if flag is True else (f"{GREEN}[ok]{RESET}" if flag is False else f"{DIM}[--]{RESET}")
            w = f" {DIM}(+{f.get('weight')}){RESET}" if f.get("weight") else ""
            print(f"  {mark} {f.get('text')}{w}")

    print_section("Sender & Header Forensics", result.get("header_analysis", {}).get("findings", []))
    print_section("Content & Social Engineering", result.get("content_analysis", {}).get("findings", []))
    print_section("Attachment Static Forensics", result.get("attachment_analysis", {}).get("findings", []))
    print_section("Modern Vectors & Evasion", result.get("modern_threats", {}).get("findings", []))

    # URLs
    urls = result.get("url_analysis", [])
    if urls:
        print(f"\n{BOLD}-- URL Forensics (SSRF-Protected Live Analysis) --{RESET}")
        for u in urls:
            uvc = verdict_color(u.get("verdict"))
            print(f"\n  {CYAN}{BOLD}{u.get('url')}{RESET}")
            print(f"  -> Registrable Domain: {u.get('domain')} | Verdict: {uvc}{u.get('verdict')}{RESET} (Score: {u.get('score')})")
            for f in u.get("findings", []):
                flag = f.get("flag")
                mark = f"{RED}[!!]{RESET}" if flag is True else (f"{GREEN}[ok]{RESET}" if flag is False else f"{DIM}[--]{RESET}")
                print(f"     {mark} {f.get('text')}")

    # MITRE ATT&CK
    mitre = result.get("mitre", [])
    if mitre:
        print(f"\n{BOLD}-- MITRE ATT&CK Technique Mappings --{RESET}")
        for m in mitre:
            status_tag = f"{YELLOW}[{m.get('status')}]{RESET}" if "Observed" in m.get("status") else f"{DIM}[{m.get('status')}]{RESET}"
            print(f"  {MAGENTA}{m.get('id')}{RESET} {m.get('name')} {status_tag}")
            print(f"     {DIM}Evidence: {m.get('evidence')}{RESET}")

    # Normalized IOCs
    iocs = result.get("normalized_iocs", [])
    if iocs:
        print(f"\n{BOLD}-- Normalized Indicators of Compromise (IOCs) --{RESET}")
        for i in iocs[:12]:
            print(f"  [{CYAN}{i.get('type')}{RESET}] {i.get('value')} ({DIM}{i.get('source')}{RESET})")

    # Analyst Recommendations
    recs = result.get("recommendations", [])
    if recs:
        print(f"\n{BOLD}{GREEN}-- Recommended SOC Analyst Actions --{RESET}")
        for r in recs:
            print(f"  {r}")
    print()


def cmd_analyze(args):
    if args.path == "-":
        raw = sys.stdin.read()
        msg = parse_email_text(raw)
    else:
        with open(args.path, "rb") as fh:
            data = fh.read()
        try:
            msg = parse_email_bytes(data)
        except Exception:
            msg = parse_email_text(data.decode("utf-8", errors="replace"))

    if msg is None:
        print(f"{RED}Error: Could not parse input as an email message.{RESET}", file=sys.stderr)
        sys.exit(1)

    result = analyze_email(msg)
    case_id = GLOBAL_REPO.save_analysis_and_case(result, source=f"cli:{args.path}")
    print_soc_report(result, case_id)

    # JSON export
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(result, fh, indent=2, default=str)
        print(f"{GREEN}[✓] JSON report written to {args.json}{RESET}")

    # STIX 2.1 export
    if args.stix:
        case_data = GLOBAL_REPO.get_case_by_id(case_id)
        stix_bundle = export_case_to_stix_bundle(case_data)
        with open(args.stix, "w") as fh:
            json.dump(stix_bundle, fh, indent=2)
        print(f"{GREEN}[✓] STIX 2.1 Bundle written to {args.stix}{RESET}")

    # Sigma Rule export
    if args.sigma:
        case_data = GLOBAL_REPO.get_case_by_id(case_id)
        sigma_yaml = export_case_to_sigma_rule(case_data)
        with open(args.sigma, "w") as fh:
            fh.write(sigma_yaml)
        print(f"{GREEN}[✓] Sigma Rule written to {args.sigma}{RESET}")

    # CSV IOC export
    if args.csv:
        csv_data = export_iocs_to_csv(result.get("normalized_iocs", []))
        with open(args.csv, "w") as fh:
            fh.write(csv_data)
        print(f"{GREEN}[✓] IOCs CSV written to {args.csv}{RESET}")


def cmd_cases(args):
    cases = GLOBAL_REPO.list_cases(limit=args.limit, status_filter=args.status)
    print(f"\n{BOLD}{'=' * 85}{RESET}")
    print(f"{'CASE ID':<12} {'SEVERITY':<10} {'STATUS':<15} {'VERDICT':<14} {'SCORE':<7} {'SUBJECT'}")
    print(f"{'-' * 85}")
    for c in cases:
        vc = verdict_color(c.get("verdict"))
        sc = verdict_color(c.get("severity"))
        print(f"{c.get('case_number', ''):<12} {sc}{c.get('severity', ''):<10}{RESET} {c.get('status', ''):<15} {vc}{c.get('verdict', ''):<14}{RESET} {c.get('score', 0):<7} {c.get('title', '')[:35]}")
    print(f"{BOLD}{'=' * 85}{RESET}\n")


def cmd_show_case(args):
    case = GLOBAL_REPO.get_case_by_id(args.case_id)
    if not case:
        print(f"{RED}Case {args.case_id} not found.{RESET}")
        return
    analysis = case.get("analysis", {}).get("result", {})
    print_soc_report(analysis, case.get("id"))


def cmd_update_verdict(args):
    success = GLOBAL_REPO.update_case_verdict(args.case_id, args.verdict, user=args.user, reason=args.reason)
    if success:
        print(f"{GREEN}[✓] Case {args.case_id} verdict updated to {args.verdict}{RESET}")
    else:
        print(f"{RED}Failed to update case {args.case_id}{RESET}")


def cmd_add_note(args):
    success = GLOBAL_REPO.add_case_note(args.case_id, args.note, author=args.author)
    if success:
        print(f"{GREEN}[✓] Note added to Case {args.case_id}{RESET}")
    else:
        print(f"{RED}Failed to add note to case {args.case_id}{RESET}")


def cmd_watch(args):
    from realtime_watch import watch_inbox
    watch_inbox(args.imap_server, args.user, args.password, args.folder, args.interval)


def main():
    parser = argparse.ArgumentParser(description="PhishGuard SOC Triage & Threat Intelligence CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    # Analyze
    p_analyze = sub.add_parser("analyze", help="Analyze an email .eml or stdin")
    p_analyze.add_argument("path", help="Path to .eml file or '-' for stdin")
    p_analyze.add_argument("--json", help="Export analysis report as JSON")
    p_analyze.add_argument("--stix", help="Export case as STIX 2.1 JSON bundle")
    p_analyze.add_argument("--sigma", help="Export detection rule as Sigma YAML")
    p_analyze.add_argument("--csv", help="Export normalized IOCs as CSV")
    p_analyze.set_defaults(func=cmd_analyze)

    # Case list
    p_cases = sub.add_parser("cases", help="List recent SOC triage cases")
    p_cases.add_argument("--limit", type=int, default=30)
    p_cases.add_argument("--status", help="Filter by status (OPEN, TRIAGED, INVESTIGATING, CLOSED)")
    p_cases.set_defaults(func=cmd_cases)

    # Show Case
    p_case = sub.add_parser("case", help="Show full details for a case ID")
    p_case.add_argument("case_id", type=int)
    p_case.set_defaults(func=cmd_show_case)

    # Update Verdict
    p_upd = sub.add_parser("update-verdict", help="Update verdict for a case")
    p_upd.add_argument("case_id", type=int)
    p_upd.add_argument("verdict", choices=["CLEAN", "SUSPICIOUS", "PHISHING", "MALICIOUS"])
    p_upd.add_argument("--user", default="analyst")
    p_upd.add_argument("--reason", default="")
    p_upd.set_defaults(func=cmd_update_verdict)

    # Add Note
    p_note = sub.add_parser("add-note", help="Add analyst note to a case")
    p_note.add_argument("case_id", type=int)
    p_note.add_argument("note", help="Note text content")
    p_note.add_argument("--author", default="analyst")
    p_note.set_defaults(func=cmd_add_note)

    # Watch
    p_watch = sub.add_parser("watch", help="Continuous IMAP mailbox monitor")
    p_watch.add_argument("--imap-server", required=True)
    p_watch.add_argument("--user", required=True)
    p_watch.add_argument("--password", required=True)
    p_watch.add_argument("--folder", default="INBOX")
    p_watch.add_argument("--interval", type=int, default=30)
    p_watch.set_defaults(func=cmd_watch)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
