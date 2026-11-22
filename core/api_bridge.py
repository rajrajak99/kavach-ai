"""
Kavach AI — Deterministic AST Engine API Bridge
High-speed CLI bridge connecting Next.js / external frontends to SurgicalAnalyzer in sub-16ms.
"""

import sys
import json
import argparse
from typing import Dict, Any

from core.surgical_analyzer import SurgicalAnalyzer
from core.diff_parser import DiffParser


def scan_snippet(code: str, filename: str = "payment_service.py") -> Dict[str, Any]:
    parser = DiffParser()
    analyzer = SurgicalAnalyzer()

    # Determine filename heuristic based on language markers if generic
    if filename in ("snippet.py", "payment_service.py") and ("function " in code or "const " in code or "require(" in code):
        filename = "auth_handler.js"
    elif filename in ("snippet.py", "payment_service.py") and ("#include" in code or "std::" in code):
        filename = "buffer_alloc.cpp"

    diffs = [parser.parse_raw_snippet(filename, code)]
    res = analyzer.generate_pull_request_review(diffs)

    findings_json = []
    for f in res.get("findings", []):
        findings_json.append({
            "line_number": f.line_number,
            "severity": f.severity,
            "category": f.category,
            "cwe_id": f.cwe_id or "CWE-General",
            "problem_code": f.problem_code,
            "fixed_code": f.fixed_code,
            "explanation": f.explanation,
            "github_suggestion_block": getattr(f, "github_suggestion_block", ""),
            "language": getattr(f, "language", "python")
        })

    metrics = res.get("metrics", {"critical": 0, "security": 0, "performance": 0, "total": 0})
    critical_count = metrics.get("critical", 0)
    security_count = metrics.get("security", 0)
    performance_count = metrics.get("performance", 0)

    # Compute Security Posture Grade (0-100)
    base_score = max(0, 100 - (critical_count * 35) - (security_count * 15) - (performance_count * 5))
    if base_score >= 90:
        grade = "A"
        grade_label = "Production Certified • Enterprise Compliant"
        badge_class = "grade-a"
        color = "#22C58B"
    elif base_score >= 70:
        grade = "B"
        grade_label = "Acceptable Risk • Merge Review Advised"
        badge_class = "grade-b"
        color = "#E9A23B"
    else:
        grade = "F"
        grade_label = "Merge Blocked • High Critical Hazard"
        badge_class = "grade-f"
        color = "#F05252"

    cvss_max = 9.8 if critical_count > 0 else (6.5 if security_count > 0 else 0.0)

    return {
        "status": res.get("status", "PASSED"),
        "metrics": metrics,
        "findings": findings_json,
        "syntax_error": res.get("syntax_error"),
        "posture": {
            "score": base_score,
            "grade": grade,
            "grade_label": grade_label,
            "badge_class": badge_class,
            "color": color,
            "cvss_max": cvss_max
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Kavach AI AST API Bridge")
    parser.add_argument("--filename", default="payment_service.py", help="Target filename")
    parser.add_argument("--code", default=None, help="Inline code snippet to analyze")
    args = parser.parse_args()

    if args.code is not None:
        code_input = args.code
    else:
        # Read from stdin
        code_input = sys.stdin.read()

    result = scan_snippet(code_input, args.filename)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
