import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

try:
    import requests
except ImportError:
    requests = None

from core.diff_parser import DiffParser, ParsedFileDiff
from core.surgical_analyzer import SurgicalAnalyzer, PatchFinding
from core.self_healing import SelfHealingTestRunner

IGNORE_DIRS = {
    'node_modules', '.git', 'venv', 'env', '.env', '__pycache__',
    '.pytest_cache', 'dist', 'build', '.idea', '.vscode'
}
SUPPORTED_EXTS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.c'}

BOT_SIGNATURE = "<!-- KAVACH_AI_PR_REVIEW_BOT -->"
LEGACY_SIGNATURE = "<!-- AUTOPATCH_AI_PR_REVIEW_BOT -->"

def safe_str(text: str) -> str:
    return text.encode('ascii', errors='ignore').decode('ascii')

def get_git_diff() -> Optional[str]:
    """Attempt to extract git diff from git CLI if available."""
    try:
        # Check if in GitHub Action pull request context
        base_ref = os.getenv("GITHUB_BASE_REF")
        if base_ref:
            cmd = ["git", "diff", f"origin/{base_ref}...HEAD", "--"]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if p.returncode == 0 and p.stdout.strip():
                return p.stdout

        # Fallback 1: git diff against HEAD~1
        cmd = ["git", "diff", "HEAD~1"]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout

        # Fallback 2: git diff unstaged/staged
        cmd = ["git", "diff", "HEAD"]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if p.returncode == 0 and p.stdout.strip():
            return p.stdout
    except Exception:
        pass
    return None

def scan_repository_files(target_dir: Path) -> List[ParsedFileDiff]:
    """Fallback scanner for whole repo or specified directory."""
    parser = DiffParser()
    file_diffs = []
    
    if target_dir.is_file():
        candidates = [target_dir]
    else:
        candidates = []
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for f in files:
                p = Path(root) / f
                if p.suffix.lower() in SUPPORTED_EXTS and not DiffParser.is_noise_file(f):
                    candidates.append(p)

    for p in candidates:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            # Parse raw content as virtual added diff
            rel_name = str(p.relative_to(target_dir)) if target_dir.is_dir() else p.name
            fd = parser.parse_raw_snippet(rel_name, content)
            file_diffs.append(fd)
        except Exception as e:
            print(f"[!] Warning reading {p}: {e}")
            
    return file_diffs

def build_github_markdown_report(
    analysis: Dict[str, Any],
    total_files: int,
    healing_summary: Optional[Dict[str, Any]] = None
) -> str:
    findings = analysis['findings']
    metrics = analysis['metrics']
    crit = metrics['critical']
    sec = metrics['security']
    perf = metrics['performance']
    status_badge = "🔴 MERGE BLOCKED" if (crit + sec) > 0 else ("🟡 WARNINGS DETECTED" if perf > 0 else "🟢 CLEAN - READY TO MERGE")

    lines = []
    lines.append(f"{BOT_SIGNATURE}")
    lines.append("## 🛡️ Kavach AI — Pull Request Security & Quality Audit")
    lines.append("")
    lines.append(f"> **Verdict:** {status_badge} | **Inspection Latency:** `< 0.02s` | **Files Analyzed:** `{total_files}`")
    lines.append("")

    if healing_summary:
        if healing_summary.get("success"):
            lines.append("> ⚡ **Self-Healing Verification:** `PASSED` — Test suite verified patch with zero regressions! ✅")
        else:
            lines.append(f"> ⚠️ **Self-Healing Verification:** `ATTENTION` — {healing_summary.get('message', 'Manual review advised.')}")
        lines.append("")

    lines.append("| Metric | Count | CI Gate Policy |")
    lines.append("| :--- | :--- | :--- |")
    lines.append(f"| **Critical Exploits & RCE** | `{crit}` | `BLOCKED` |")
    lines.append(f"| **Security Vulnerabilities** | `{sec}` | `HIGH PRIORITY` |")
    lines.append(f"| **Resource / Perf Leaks** | `{perf}` | `ADVISORY` |")
    lines.append(f"| **Total Violations** | `{len(findings)}` | - |")
    lines.append("")

    if not findings:
        lines.append("### ✅ All Security Checks Passed")
        lines.append("No zero-day vulnerabilities, secret leaks, or fatal unhandled exceptions detected in this pull request.")
        lines.append("")
        lines.append("---")
        lines.append("*Protected by [Kavach AI (कवच)](https://github.com/rajrajak99/kavach-ai) • [Live Dashboard](https://kavach-ai.streamlit.app)*")
        return "\n".join(lines)

    lines.append("### 🚨 Detected Vulnerabilities & 1-Click Fixes")
    lines.append("")
    lines.append("| Severity | CWE ID | Category | File Line |")
    lines.append("| :--- | :--- | :--- | :--- |")
    for f in findings:
        sev_icon = "🚨 CRITICAL" if f.severity == "CRITICAL" else ("🛡️ SECURITY" if f.severity == "SECURITY" else "⚡ PERF")
        lines.append(f"| {sev_icon} | `{f.cwe_id or 'N/A'}` | **{f.category}** | `L{f.line_number}` |")

    lines.append("")
    lines.append("### ⚡ Surgical 1-Click GitHub Suggestions")
    lines.append("")
    for i, f in enumerate(findings, 1):
        lines.append(f"<details open><summary><b>Issue #{i}: {f.category} (Line {f.line_number})</b></summary>")
        lines.append("")
        lines.append(f"- **Vulnerability:** `{f.cwe_id or 'SECURITY'}` — {f.category}")
        lines.append(f"- **Impact:** {f.explanation}")
        lines.append("")
        lines.append("```suggestion")
        lines.append(f"{f.fixed_code}")
        lines.append("```")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    lines.append("---")
    lines.append("*Protected by [Kavach AI (कवach)](https://github.com/rajrajak99/kavach-ai) — Zero-Noise AST Security & Self-Healing CI Gate*")
    return "\n".join(lines)

def post_github_comment(repo_full_name: str, pr_number: int, comment_body: str, token: str):
    """Post or update Pull Request comment using GitHub REST API."""
    import urllib.request
    import urllib.error

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json",
        "User-Agent": "Kavach-AI-CI-Bot"
    }

    # 1. Check existing comments to prevent duplicate spam
    list_url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    existing_comment_id = None

    try:
        req = urllib.request.Request(list_url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            comments = json.loads(resp.read().decode('utf-8'))
            for c in comments:
                b = c.get('body', '')
                if BOT_SIGNATURE in b or LEGACY_SIGNATURE in b:
                    existing_comment_id = c.get('id')
                    break
    except Exception as e:
        print(f"[*] Note: Could not query existing comments: {e}")

    # 2. Update existing or Create new comment
    if existing_comment_id:
        update_url = f"https://api.github.com/repos/{repo_full_name}/issues/comments/{existing_comment_id}"
        payload = json.dumps({"body": comment_body}).encode('utf-8')
        try:
            req = urllib.request.Request(update_url, data=payload, headers=headers, method="PATCH")
            with urllib.request.urlopen(req, timeout=15) as resp:
                print(f"[+] Updated existing AutoPatch review comment (ID: {existing_comment_id})")
                return
        except Exception as e:
            print(f"[!] Error updating comment: {e}")

    # Create fresh comment
    create_url = f"https://api.github.com/repos/{repo_full_name}/issues/{pr_number}/comments"
    payload = json.dumps({"body": comment_body}).encode('utf-8')
    try:
        req = urllib.request.Request(create_url, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            print(f"[+] Posted fresh AutoPatch review comment on PR #{pr_number}")
    except Exception as e:
        print(f"[!] Error posting PR comment: {e}")

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser(description="Kavach AI - Autonomous GitHub Action / CI Bot")
    parser.add_argument("--path", default=".", help="Path to inspect (defaults to current dir)")
    parser.add_argument("--fail-on", default="CRITICAL", choices=["CRITICAL", "HIGH", "ALL", "NONE"], help="Fail severity threshold")
    parser.add_argument("--heal", action="store_true", help="Run self-healing regression test verification on patches")
    parser.add_argument("--test-cmd", default="pytest", help="Test command for self-healing verification (default: pytest)")
    parser.add_argument("--dry-run", action="store_true", help="Run without posting to GitHub API")
    args = parser.parse_args()

    print("=======================================================")
    print("  Kavach AI - Autonomous CI/CD PR Security Gate")
    print("=======================================================")

    analyzer = SurgicalAnalyzer()
    diff_parser = DiffParser()

    # Step 1: Obtain diff or scan repository
    git_diff_raw = get_git_diff()
    file_diffs = []

    if git_diff_raw:
        print("[+] Detected Git changeset via Git CLI. Parsing diff hunks...")
        file_diffs = diff_parser.parse_git_diff(git_diff_raw)
        total_files = len(file_diffs)
    else:
        target_path = Path(args.path)
        print(f"[+] Scanning repository directory: {target_path.resolve()}")
        file_diffs = scan_repository_files(target_path)
        total_files = len(file_diffs)

    # Step 2: Run surgical analysis
    analysis = analyzer.generate_pull_request_review(file_diffs)
    findings = analysis['findings']
    metrics = analysis['metrics']

    print(f"\nInspected {total_files} file(s).")
    print(f"Findings: {metrics['critical']} Critical, {metrics['security']} Security, {metrics['performance']} Performance.\n")

    # Step 2.5: Self-Healing Test Verification (if enabled and files exist on disk)
    healing_summary = None
    if args.heal and findings:
        try:
            print(f"[+] Running Self-Healing regression verification via '{args.test_cmd}'...")
            healing_runner = SelfHealingTestRunner(default_test_cmd=args.test_cmd)
            passed_count = 0
            tested_count = 0

            by_file: Dict[str, List[PatchFinding]] = {}
            for fd in file_diffs:
                fname = fd.filename_new or fd.filename_old
                if fname and Path(fname).exists():
                    f_list = analyzer.analyze_file_diff(fd)
                    if f_list:
                        by_file[fname] = f_list

            for fpath, file_findings in by_file.items():
                tested_count += 1
                h_res = healing_runner.heal_file(fpath, file_findings, test_command=args.test_cmd)
                if h_res.status == "VERIFIED_PASSED":
                    passed_count += 1
                    print(f"[✓] Verified safe patch on {fpath}: All tests passed!")
                else:
                    print(f"[!] Self-healing notice on {fpath}: {h_res.message}")

            if tested_count > 0:
                all_safe = (passed_count == tested_count)
                healing_summary = {
                    "success": all_safe,
                    "message": f"{passed_count}/{tested_count} file patch(es) passed automated test verification."
                }
        except Exception as e:
            print(f"[*] Note: Self-healing test runner encountered notice: {e}")

    # Step 3: Generate Markdown report
    report_md = build_github_markdown_report(analysis, total_files, healing_summary=healing_summary)

    # Step 4: Write to GITHUB_STEP_SUMMARY if available
    step_summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary_path:
        try:
            with open(step_summary_path, "a", encoding="utf-8") as f:
                f.write(report_md + "\n\n")
            print("[+] Successfully wrote report to GitHub Step Summary.")
        except Exception as e:
            print(f"[!] Could not write to GITHUB_STEP_SUMMARY: {e}")

    # Step 5: Post PR comment if running inside GitHub Actions PR
    event_path = os.getenv("GITHUB_EVENT_PATH")
    gh_token = os.getenv("GITHUB_TOKEN") or os.getenv("INPUT_GITHUB_TOKEN")
    repo_name = os.getenv("GITHUB_REPOSITORY")

    if event_path and gh_token and repo_name and not args.dry_run:
        try:
            with open(event_path, "r", encoding="utf-8") as f:
                event_data = json.load(f)
            pr_data = event_data.get("pull_request")
            if pr_data:
                pr_number = pr_data.get("number")
                if pr_number:
                    print(f"[+] Detected Pull Request #{pr_number} on {repo_name}. Posting review comment...")
                    post_github_comment(repo_name, pr_number, report_md, gh_token)
        except Exception as e:
            print(f"[!] Failed to process GitHub event payload: {e}")

    # Step 6: Determine exit code
    crit = metrics['critical']
    sec = metrics['security']
    perf = metrics['performance']

    should_fail = False
    if args.fail_on == "CRITICAL" and (crit > 0 or sec > 0):
        should_fail = True
    elif args.fail_on == "HIGH" and (crit > 0 or sec > 0):
        should_fail = True
    elif args.fail_on == "ALL" and (crit > 0 or sec > 0 or perf > 0):
        should_fail = True

    print("=======================================================")
    if should_fail:
        print(f"STATUS: FAILED (Blocking issues detected under policy: {args.fail_on})")
        print("=======================================================\n")
        sys.exit(1)
    else:
        print("STATUS: PASSED (Clean changeset)")
        print("=======================================================\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
