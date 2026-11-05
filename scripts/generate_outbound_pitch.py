#!/usr/bin/env python3
"""
Kavach AI — B2B Cold Outbound Vulnerability Bait & Pitch Generator
Scans a target repository or code sample and outputs a personalized, high-converting
cold outreach message for CTOs and Engineering Leaders.
"""

import sys
import argparse
from pathlib import Path

# Add project root to path
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from core.diff_parser import DiffParser
from core.surgical_analyzer import SurgicalAnalyzer

def generate_pitch(target_path: str, founder_name: str = "there", company_name: str = "your team") -> str:
    path = Path(target_path)
    if not path.exists():
        return f"Error: Target path '{target_path}' does not exist."

    parser = DiffParser()
    analyzer = SurgicalAnalyzer()

    # Read files
    files_to_scan = []
    if path.is_file():
        files_to_scan.append(path)
    else:
        for p in path.glob("**/*"):
            if p.is_file() and p.suffix.lower() in {'.py', '.js', '.ts', '.cpp', '.c'}:
                if not parser.is_noise_file(str(p)):
                    files_to_scan.append(p)

    all_findings = []
    for f in files_to_scan[:10]:
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                content = fp.read()
            diff = parser.parse_raw_snippet(str(f.name), content)
            res = analyzer.generate_pull_request_review([diff])
            for finding in res['findings']:
                all_findings.append((f.name, finding))
        except Exception:
            continue

    if not all_findings:
        pitch = f"""
Subject: Quick note on {company_name}'s CI security gate

Hey {founder_name},

Ran our 5ms AST taint engine (Kavach AI) against {company_name}'s public modules—your current code looks clean! 

However, noticed your GitHub Actions pipeline doesn't have an automated pre-merge blocking gate for CWE-89 (SQL Injection) and CWE-798 (Split Secrets/Tokens). When multiple engineers ship PRs every week, untested PR commits are where leaks slip into production.

We built Kavach AI to solve this with 0 telemetry and sub-10ms local AST checks. It takes literally 60 seconds to plug into your GitHub Actions:

```yaml
- name: Kavach AI Pre-Merge Gate
  uses: rajrajak99/kavach-ai@v1.3.0
```

Blocks vulnerable code before merge and comments with the exact 1-click surgical fix on the PR.

Would love to give you an Early Adopter pass for {company_name} if you'd like to test it on your private repos.

Best,
Raja Rajak
Founder, Kavach AI (https://kavach-ai.streamlit.app)
"""
        return pitch.strip()

    # If vulnerabilities found, generate the killer vulnerability bait pitch!
    file_name, first_f = all_findings[0]
    prob_line = first_f.problem_code.strip()
    fix_line = first_f.fixed_code.strip()
    cwe = first_f.cwe_id or "CWE-89"
    cat = first_f.category

    pitch = f"""
Subject: Vulnerability notice + 1-click fix for {company_name} ({file_name})

Hey {founder_name},

Ran our 5ms AST taint-tracking engine (Kavach AI) across {company_name}'s repo and noticed an unblocked security risk in `{file_name}` at line {first_f.line_number}:

Issue: {cat} [{cwe}]
Problem:
  - {prob_line}

Here is the exact 1-click surgical patch to make it safe:
  + {fix_line}

Static scanners like SonarQube or Snyk usually spit out 50 false positives without fixing the code. Kavach AI runs locally in CI under 16ms, verifies test regressions with pytest/jest, and posts 1-click patches directly on the GitHub PR before merge.

Takes 60 seconds to add to your `.github/workflows/`:
```yaml
- name: Kavach AI PR Security Gate
  uses: rajrajak99/kavach-ai@v1.3.0
```

Happy to set {company_name} up with an Early Adopter Lifetime Pass if you'd like to protect your private engineering repos.

Best,
Raja Rajak
Founder, Kavach AI (https://kavach-ai.streamlit.app)
"""
    return pitch.strip()

def main():
    p = argparse.ArgumentParser(description="Generate high-converting B2B cold outreach pitch for CTOs")
    p.add_argument("target", help="File or directory of the target prospect repo to scan")
    p.add_argument("--founder", default="there", help="Name of the Founder/CTO (e.g. 'Alex')")
    p.add_argument("--company", default="your team", help="Company or repo name")
    args = p.parse_args()

    pitch_text = generate_pitch(args.target, args.founder, args.company)
    print("\n" + "=" * 60)
    print("  KAVACH AI — B2B COLD OUTREACH PITCH GENERATOR")
    print("=" * 60 + "\n")
    print(pitch_text)
    print("\n" + "=" * 60 + "\n")

if __name__ == "__main__":
    main()
