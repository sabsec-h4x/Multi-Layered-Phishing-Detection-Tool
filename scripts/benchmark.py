#!/usr/bin/env python3
"""
PhishGuard Benchmark Evaluation Suite
-------------------------------------
Evaluates detection accuracy, precision, recall, F1, false positive rate,
and execution latency against benchmark email samples.
"""

import sys
import time
from pathlib import Path
from typing import Dict, Any, List

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer import parse_email_bytes, analyze_email

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def run_benchmark():
    print("=" * 75)
    print("PHISHGUARD FORENSIC ENGINE BENCHMARK EVALUATION")
    print("=" * 75)

    categories = {
        "clean": 0,  # 0 = clean
        "phishing": 1,  # 1 = threat
        "bec": 1,
        "malicious_attachment": 1,
    }

    y_true = []
    y_pred = []
    latencies = []

    for cat, ground_truth in categories.items():
        cat_dir = SAMPLES_DIR / cat
        if not cat_dir.exists():
            continue

        for eml_file in cat_dir.glob("*.eml"):
            with open(eml_file, "rb") as f:
                raw_bytes = f.read()

            start_t = time.perf_counter()
            msg = parse_email_bytes(raw_bytes)
            result = analyze_email(msg)
            elapsed = time.perf_counter() - start_t
            latencies.append(elapsed)

            is_threat = 1 if result["verdict"] in ("PHISHING", "MALICIOUS", "SUSPICIOUS") else 0
            y_true.append(ground_truth)
            y_pred.append(is_threat)

            print(f"[{cat.upper():<20}] {eml_file.name:<30} -> Verdict: {result['verdict']:<12} Score: {result['score']:>3}/100 ({elapsed*1000:.1f}ms)")

    if not y_true:
        print("No sample files found.")
        return

    # Metrics
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    accuracy = (tp + tn) / len(y_true) if y_true else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (tp + fn) if (tp + fn) > 0 else 0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0

    print("\n" + "=" * 75)
    print("BENCHMARK METRICS RESULTS:")
    print("-" * 75)
    print(f"  Total Samples Evaluated: {len(y_true)}")
    print(f"  Accuracy:                {accuracy * 100:.1f}%")
    print(f"  Precision:               {precision * 100:.1f}%")
    print(f"  Recall:                  {recall * 100:.1f}%")
    print(f"  F1 Score:                {f1:.3f}")
    print(f"  False Positive Rate:     {fpr * 100:.1f}%")
    print(f"  False Negative Rate:     {fnr * 100:.1f}%")
    print(f"  Avg Analysis Latency:    {avg_latency * 1000:.1f} ms")
    print("=" * 75)


if __name__ == "__main__":
    run_benchmark()
