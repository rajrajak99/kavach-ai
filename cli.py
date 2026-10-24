import os
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.diff_parser import DiffParser
from core.surgical_analyzer import SurgicalAnalyzer
from core.ai_reasoner import AIReasoner
from core.self_healing import SelfHealingTestRunner

IGNORE_DIRS = {
    'node_modules', '.git', 'venv', 'env', '.env', '__pycache__',
    '.pytest_cache', 'dist', 'build', '.idea', '.vscode'
}

SUPPORTED_EXTS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.c'}

def safe_str(text: str) -> str:
    """Strip characters incompatible with Windows console encoding."""
    return text.encode('ascii', errors='ignore').decode('ascii')

def scan_path(
    target_path: str,
    output_patch: Optional[str] = None,
    explain: bool = False,
    heal: bool = False,
    test_cmd: str = "pytest",
    as_json: bool = False
) -> int:
    path = Path(target_path)
    if not path.exists():
        if as_json:
            print(json.dumps({"error": f"Target path '{target_path}' does not exist."}))
        else:
            print(f"Error: Target path '{target_path}' does not exist.")
        return 2

    files_to_scan: List[Path] = []
    if path.is_file():
        files_to_scan.append(path)
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for f in files:
                ext = Path(f).suffix.lower()
                if ext in SUPPORTED_EXTS and not DiffParser.is_noise_file(f):
                    files_to_scan.append(Path(root) / f)

    if not as_json:
        print("\n=======================================================")
        print("  AutoPatch CLI - Static Security & Quality Inspector")
        print("=======================================================")
        print(f"Target: {path.resolve()}")
        print(f"Files to inspect: {len(files_to_scan)}")
        if explain:
            print("AI Threat Intelligence Mode: ACTIVE")
        if heal:
            print(f"Self-Healing Mode: ACTIVE (Verification Command: '{test_cmd}')")
        print()

    parser = DiffParser()
    analyzer = SurgicalAnalyzer()
    reasoner = AIReasoner() if explain else None
    healing_runner = SelfHealingTestRunner(default_test_cmd=test_cmd) if heal else None

    total_findings = []
    unified_patches = []
    file_findings_map = {}
    healing_results = []

    for file_p in files_to_scan:
        try:
            with open(file_p, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            diff = parser.parse_raw_snippet(str(file_p), content)
            res = analyzer.generate_pull_request_review([diff])
            if res['findings']:
                file_findings_map[file_p] = res['findings']
                if not as_json:
                    print(f"[-] {file_p}: {len(res['findings'])} issue(s) detected")
                for finding in res['findings']:
                    total_findings.append((file_p, finding))
                    unified_patches.append(f"# {file_p} line {finding.line_number}: {finding.category}\n{finding.github_suggestion_block}\n")
                    if not as_json:
                        cat_safe = safe_str(finding.category)
                        prob_safe = safe_str(finding.problem_code)
                        fix_safe = safe_str(finding.fixed_code)
                        print(f"    Line {finding.line_number} [{finding.severity}] {cat_safe} ({finding.cwe_id or 'HIGH'})")
                        print(f"      Current: {prob_safe}")
                        print(f"      Fix:     {fix_safe}")
                        
                        if explain and reasoner:
                            intel = reasoner.analyze_threat(
                                category=finding.category,
                                problem_code=finding.problem_code,
                                fixed_code=finding.fixed_code,
                                cwe_id=finding.cwe_id,
                                language=finding.language
                            )
                            print(f"      [AI Threat Intel] CVSS {intel.cvss_score} | {intel.attack_vector[:90]}...")
                            print(f"      [Exploit Scenario] {intel.exploit_scenario.replace(chr(10), ' | ')[:100]}...")
                        print()

                # Execute Self-Healing if requested
                if heal and healing_runner:
                    h_res = healing_runner.heal_file(
                        str(file_p),
                        res['findings'],
                        test_command=test_cmd,
                        working_dir=str(path.parent if path.is_file() else path)
                    )
                    healing_results.append(h_res)
                    if not as_json:
                        if h_res.status == "VERIFIED_PASSED":
                            print(f"    [+] [SELF-HEALING] VERIFIED & LOCKED: {h_res.message}")
                        elif "ROLLBACK" in h_res.status:
                            print(f"    [!] [SELF-HEALING] ATOMIC ROLLBACK: {h_res.message}")
                        print()

        except Exception as e:
            if not as_json:
                print(f"[!] Error scanning {file_p}: {e}")

    crit_count = sum(1 for _, f in total_findings if f.severity == 'CRITICAL')
    sec_count = sum(1 for _, f in total_findings if f.severity == 'SECURITY')
    perf_count = sum(1 for _, f in total_findings if f.severity == 'PERFORMANCE')

    if as_json:
        output_data = {
            "target": str(path.resolve()),
            "total_files": len(files_to_scan),
            "total_findings": len(total_findings),
            "summary": {
                "critical": crit_count,
                "security": sec_count,
                "performance": perf_count
            },
            "findings": [
                {
                    "file": str(file_p),
                    "line": finding.line_number,
                    "severity": finding.severity,
                    "category": finding.category,
                    "cwe_id": finding.cwe_id,
                    "language": finding.language,
                    "problem_code": finding.problem_code,
                    "fixed_code": finding.fixed_code,
                    "explanation": finding.explanation
                }
                for file_p, finding in total_findings
            ],
            "healing": [
                {
                    "file": h.target_file,
                    "status": h.status,
                    "patches_applied": h.patches_applied,
                    "message": h.message,
                    "duration_seconds": round(h.duration_seconds, 3)
                }
                for h in healing_results
            ] if heal else []
        }
        print(json.dumps(output_data, indent=2))
        return 0 if (crit_count == 0 and sec_count == 0) else 1

    print("-------------------------------------------------------")
    print(f"SUMMARY: {len(total_findings)} Total Issues Detected across {len(files_to_scan)} files.")
    print(f"  Critical Crashes:  {crit_count}")
    print(f"  Security Hazards:  {sec_count}")
    print(f"  Performance Leaks: {perf_count}")

    if heal and healing_results:
        print("  Self-Healing Verification:")
        for hr in healing_results:
            print(f"    - {Path(hr.target_file).name}: {hr.status} ({hr.patches_applied} patches applied)")

    if output_patch and unified_patches:
        with open(output_patch, "w", encoding="utf-8") as pf:
            pf.write("\n".join(unified_patches))
        print(f"\n[+] Unified patch exported to: {output_patch}")
        print(f"    Apply locally with: git apply {output_patch}")

    print("=======================================================\n")

    if crit_count > 0 or sec_count > 0:
        print("Status: FAILED (Merge Blocked due to Critical/Security hazards)\n")
        return 1
    elif perf_count > 0:
        print("Status: PASSED WITH WARNINGS\n")
        return 0
    else:
        print("Status: PASSED (Clean repository)\n")
        return 0

def main():
    p = argparse.ArgumentParser(description="AutoPatch Enterprise CLI Code Reviewer & Auto-Patcher")
    p.add_argument("path", help="File or directory path to inspect")
    p.add_argument("--patch", dest="patch_file", default="autopatch.patch", help="Output .patch file destination")
    p.add_argument("--explain", "--ai", dest="explain", action="store_true", help="Generate deep threat intelligence and exploit attack vectors")
    p.add_argument("--heal", "--self-heal", dest="heal", action="store_true", help="Enable autonomous patch application with test verification & atomic rollback")
    p.add_argument("--test-cmd", dest="test_cmd", default="pytest", help="Test runner command for self-healing verification (default: 'pytest')")
    p.add_argument("--json", dest="as_json", action="store_true", help="Output results in JSON format for IDE/CI integrations")
    args = p.parse_args()

    exit_code = scan_path(
        args.path,
        output_patch=args.patch_file,
        explain=args.explain,
        heal=args.heal,
        test_cmd=args.test_cmd,
        as_json=args.as_json
    )
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
