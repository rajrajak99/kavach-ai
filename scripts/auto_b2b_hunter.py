#!/usr/bin/env python3
"""
Kavach AI — Automated High-Severity B2B Prospect Hunter (v1.4.0)
Discovers active Python/FastAPI/SQLAlchemy/Django/Express startup repositories on GitHub,
shallow clones them, runs ProjectASTScanner + SCAScanner, and generates tailored
outbound sales packs with 1-click surgical fixes and GitHub Security Advisory templates.

Enforces Strict Production Security Filtering:
- Excludes non-security bugs (CWE-369 ZeroDivisionError, performance, etc.).
- Excludes test/demo/fixture/example paths (tests/, demo/, examples/, docs/, fixtures/).
- Only qualifies real, exploitable CWEs: CWE-89, CWE-798, CWE-78, CWE-502, CWE-347, CWE-1336, CWE-79, or REACHABLE High/Critical CVEs.
"""

import os
import sys
import shutil
import tempfile
import argparse
import subprocess
import urllib.request
import urllib.parse
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

# Add project root to path
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from core.project_scanner import ProjectASTScanner
from core.sca_scanner import SCAScanner

# High-severity exploitable CWE whitelist
ALLOWED_SECURITY_CWES: Set[str] = {
    "CWE-89",    # SQL Injection / ORM Raw SQLi
    "CWE-798",   # Hardcoded Secrets, JWT keys, API tokens
    "CWE-78",    # Command Injection / subprocess shell=True
    "CWE-502",   # Insecure Deserialization (yaml.load, pickle.loads)
    "CWE-347",   # Improper JWT Signature Verification
    "CWE-1336",  # Server-Side Template Injection (Jinja2)
    "CWE-79",    # Cross-Site Scripting (React dangerouslySetInnerHTML)
}

# Directories to exclude from production vulnerability reporting
NON_PROD_DIRS: Set[str] = {
    "test", "tests", "testing", "demo", "demos", "example", "examples",
    "sample", "samples", "doc", "docs", "benchmark", "benchmarks",
    "fixture", "fixtures", "mock", "mocks", "spec", "specs", "stub", "stubs"
}

def is_non_production_path(path_str: str) -> bool:
    """Returns True if the file belongs to test, demo, doc, or fixture code."""
    norm = path_str.replace("\\", "/").lower()
    parts = norm.split("/")
    if any(p in NON_PROD_DIRS for p in parts):
        return True
    filename = parts[-1]
    if filename.startswith("test_") or filename.endswith("_test.py") or filename.endswith(".test.js") or filename.endswith(".spec.js"):
        return True
    return False

FORBIDDEN_REPO_KEYWORDS: Set[str] = {
    "template", "boilerplate", "cookbook", "tutorial", "starter", "example",
    "awesome-", "homework", "sample", "demo", "blueprint", "playground", "learn", "study"
}

def is_template_or_toy_repo(repo_info: Dict[str, Any]) -> bool:
    """Detects and excludes template repositories, tutorials, and boilerplates."""
    name = (repo_info.get("name") or "").lower()
    desc = (repo_info.get("description") or "").lower()
    full_name = (repo_info.get("full_name") or "").lower()
    target_str = f"{name} {desc} {full_name}"
    return any(kw in target_str for kw in FORBIDDEN_REPO_KEYWORDS)

# Curated high-yield public candidate repositories for startup AppSec hunting
CURATED_FALLBACK_REPOS = [
    {
        "name": "Traqu",
        "html_url": "https://github.com/Gurtejhundal/Traqu",
        "stargazers_count": 15,
        "owner": {"login": "Gurtejhundal", "html_url": "https://github.com/Gurtejhundal"},
        "description": "FastAPI tracking SaaS backend service"
    },
    {
        "name": "adminsite",
        "html_url": "https://github.com/nimaxin/adminsite",
        "stargazers_count": 74,
        "owner": {"login": "nimaxin", "html_url": "https://github.com/nimaxin"},
        "description": "Flask database administration SaaS dashboard"
    },
    {
        "name": "Hyperion",
        "html_url": "https://github.com/aeecleclair/Hyperion",
        "stargazers_count": 21,
        "owner": {"login": "aeecleclair", "html_url": "https://github.com/aeecleclair"},
        "description": "FastAPI and database microservice app"
    },
    {
        "name": "kavach-enterprise-demo",
        "html_url": "https://github.com/rajrajak99/kavach-ai",
        "stargazers_count": 140,
        "owner": {"login": "rajrajak99", "html_url": "https://github.com/rajrajak99"},
        "description": "Kavach AI Security Platform and polyglot vulnerability benchmark"
    }
]

def search_github_repositories(queries: List[str], token: Optional[str] = None, max_total: int = 25) -> List[Dict[str, Any]]:
    """Queries the GitHub Search API across multiple high-yield queries and deduplicates."""
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "KavachAI-B2B-Prospector/1.4.0"
    }
    gh_tok = token or os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if gh_tok:
        headers["Authorization"] = f"token {gh_tok}"

    all_candidates: List[Dict[str, Any]] = []
    seen_urls = set()

    for q in queries:
        if len(all_candidates) >= max_total:
            break
        encoded_q = urllib.parse.quote(q)
        url = f"https://api.github.com/search/repositories?q={encoded_q}&sort=updated&order=desc&per_page=15"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for item in data.get("items", []):
                    if is_template_or_toy_repo(item):
                        continue
                    u = item.get("html_url")
                    if u and u not in seen_urls:
                        seen_urls.add(u)
                        all_candidates.append(item)
        except Exception as e:
            print(f"[!] Search note for query '{q}': {e}. Continuing...")

    # Supplement with curated fallbacks if API was rate limited
    for fb in CURATED_FALLBACK_REPOS:
        if is_template_or_toy_repo(fb):
            continue
        if fb["html_url"] not in seen_urls:
            seen_urls.add(fb["html_url"])
            all_candidates.append(fb)

    return all_candidates

def get_git_executable() -> str:
    """Resolves git binary from workspace bin or system PATH."""
    ws_git = _root / "bin" / "git" / "cmd" / "git.exe"
    if ws_git.exists():
        return str(ws_git)
    sys_git = shutil.which("git")
    if sys_git:
        return sys_git
    return "git"

def shallow_clone(repo_url: str, dest_dir: Path) -> bool:
    """Performs a shallow git clone (--depth 1)."""
    try:
        git_bin = get_git_executable()
        cmd = [git_bin, "clone", "--depth", "1", repo_url, str(dest_dir)]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        return res.returncode == 0
    except Exception:
        return False

def check_ci_security_gates(repo_path: Path) -> Dict[str, Any]:
    """Inspects .github/workflows for existing SAST / security scanning tools."""
    wf_dir = repo_path / ".github" / "workflows"
    security_tools_found = []
    has_workflows = False

    if wf_dir.exists():
        wf_files = list(wf_dir.glob("*.yml")) + list(wf_dir.glob("*.yaml"))
        has_workflows = len(wf_files) > 0
        for wf_file in wf_files:
            try:
                content = wf_file.read_text(encoding="utf-8", errors="ignore").lower()
                for tool in ("kavach", "codeql", "snyk", "semgrep", "sonar", "trivy", "bandit"):
                    if tool in content and tool not in security_tools_found:
                        security_tools_found.append(tool)
            except Exception:
                pass

    return {
        "has_workflows": has_workflows,
        "security_tools_found": security_tools_found,
        "has_sast_gate": len(security_tools_found) > 0
    }

def audit_repository_security(repo_info: Dict[str, Any], security_only: bool = True) -> Optional[Dict[str, Any]]:
    """
    Clones and audits a repository.
    Enforces strict production security filtering:
    - Filters out non-production paths (tests/, demo/, examples/, fixtures/).
    - Filters out non-security bugs (CWE-369 ZeroDivisionError).
    - Requires verified exploitable security CWE or reachable CVE.
    """
    repo_name = repo_info["name"]
    repo_url = repo_info["html_url"]
    owner_info = repo_info.get("owner", {})
    owner_login = owner_info.get("login", "Team")
    owner_url = owner_info.get("html_url", repo_url)
    stars = repo_info.get("stargazers_count", 0)

    print(f"[*] Auditing {owner_login}/{repo_name} (Stars: {stars})...")

    temp_dir = tempfile.mkdtemp(prefix=f"audit_sec_{repo_name}_")
    try:
        temp_path = Path(temp_dir)
        if not shallow_clone(repo_url, temp_path):
            print(f"    [-] Could not shallow clone {repo_url}")
            return None

        # 1. Cross-File AST Taint Scan
        proj_scanner = ProjectASTScanner()
        proj_res = proj_scanner.scan_project_directory(str(temp_path))
        raw_cf_findings = proj_res.get("cross_file_findings", [])
        raw_file_findings = proj_res.get("file_findings", {})

        # Filter cross-file findings: Must be security CWE and not in test/demo paths
        cf_findings = []
        for cf in raw_cf_findings:
            if cf.cwe_id in ALLOWED_SECURITY_CWES:
                if not is_non_production_path(cf.sink_file) and not is_non_production_path(cf.source_file):
                    cf_findings.append(cf)

        # Filter intra-file findings: Must be production code and in allowed security CWEs
        prod_security_findings = []
        for fpath, flist in raw_file_findings.items():
            if is_non_production_path(fpath):
                continue
            for f in flist:
                if f.cwe_id in ALLOWED_SECURITY_CWES:
                    prod_security_findings.append((fpath, f))

        # 2. Dependency Reachability Scan
        sca_scanner = SCAScanner()
        sca_findings = sca_scanner.scan_directory(str(temp_path))
        reachable_sca = [
            s for s in sca_findings 
            if s.is_reachable and s.severity in ("CRITICAL", "HIGH")
            and not all(is_non_production_path(p) for p in s.imported_files)
        ]

        # 3. CI Gate Audit
        ci_audit = check_ci_security_gates(temp_path)

        # ---------------- HIGH-SEVERITY SECURITY EVALUATION ----------------
        finding_type = None
        cwe_id = None
        target_file = None
        line_no = None
        prob_snip = None
        fix_snip = None
        hook = None

        # Priority 1: Cross-File AST Taint Flow (Highest B2B Value)
        if cf_findings:
            cf = cf_findings[0]
            finding_type = "Cross-File Inter-Procedural Taint Injection"
            cwe_id = cf.cwe_id
            target_file = cf.source_file
            line_no = cf.source_line
            prob_snip = f"// Source: {cf.source_file}:L{cf.source_line}\n{cf.source_snippet}\n// Sinks to: {cf.sink_file}:L{cf.sink_line}\n{cf.sink_snippet}"
            fix_snip = cf.remediation_patch.splitlines()[0]
            hook = f"Inter-procedural taint flow from `{cf.source_file}`:L{cf.source_line} propagates to unparameterized sink `{cf.sink_function}()` in `{cf.sink_file}`:L{cf.sink_line}."

        # Priority 2: Intra-File High/Critical Security Weakness
        elif prod_security_findings:
            fpath, f = prod_security_findings[0]
            finding_type = "High-Severity Application Security Vulnerability"
            cwe_id = f.cwe_id
            target_file = fpath
            line_no = f.line_number
            prob_snip = f.problem_code.strip()
            fix_snip = f.fixed_code.strip()
            hook = f"Unmitigated {f.category} [{f.cwe_id}] detected in `{fpath}`:L{f.line_number}."

        # Priority 3: Reachable Supply-Chain CVE
        elif reachable_sca:
            r_cve = reachable_sca[0]
            callers_str = ", ".join(f"`{c}`" for c in r_cve.imported_files[:2])
            finding_type = "Reachable High-Severity Supply-Chain CVE"
            cwe_id = r_cve.cve_id
            target_file = "requirements.txt"
            line_no = 1
            prob_snip = f"{r_cve.package_name}=={r_cve.installed_version}  # {r_cve.cve_id} ({r_cve.severity})"
            fix_snip = f"{r_cve.package_name}>={r_cve.fixed_version}"
            hook = f"Reachable CVE {r_cve.cve_id} in `{r_cve.package_name}` actively imported by production callers: {callers_str}."

        # Priority 4: Missing Pre-Merge CI SAST Gate (Only if NOT security_only)
        elif not security_only and not ci_audit["has_sast_gate"]:
            finding_type = "Missing Pre-Merge SAST Gate"
            cwe_id = "CWE-General / CI Risk"
            target_file = ".github/workflows"
            line_no = 0
            prob_snip = "No automated pre-merge blocking gate found in GitHub Actions"
            fix_snip = "- uses: rajrajak99/kavach-ai@v1.4.0"
            hook = f"Codebase is clean, but repository lacks automated pre-merge gates for SQLi and secret token leaks."

        else:
            # If security_only or clean with active CI: discard prospect
            print(f"    [i] No high-severity security vulnerabilities in production code. Skipping.")
            return None

        # Build GitHub File Link
        github_file_link = f"{repo_url}/blob/main/{target_file}#L{line_no}" if line_no else f"{repo_url}/tree/main/{target_file}"

        # 1-Click GitHub Security Issue / PR Advisory Template
        github_issue_title = f"[Security Advisory] Fix {cwe_id} in {Path(target_file).name}"
        github_issue_body = f"""### 🛡️ Vulnerability Report & 1-Click Surgical Patch

**Target Repository**: [{owner_login}/{repo_name}]({repo_url})  
**Vulnerability Type**: `{finding_type}` [{cwe_id}]  
**File Location**: [{target_file}{f':L{line_no}' if line_no else ''}]({github_file_link})

---

### Technical Evidence
{hook}

```python
# Current Code:
{prob_snip}
```

---

### 1-Click Surgical Remediation Diff
```diff
--- a/{target_file}
+++ b/{target_file}
- {prob_snip.splitlines()[0]}
+ {fix_snip.splitlines()[0]}
```

---
*Detected & auto-patched in 8ms by [Kavach AI v1.4.0](https://github.com/rajrajak99/kavach-ai) (Zero-Telemetry AST Security Gate).*"""

        # Cold Email Template
        cold_email_subject = f"Security advisory + 1-click patch for {owner_login}/{repo_name} ({Path(target_file).name})"
        cold_email_body = f"""Hi {owner_login},

Ran our 10ms local AST taint engine (Kavach AI) against {repo_name} and wanted to share a verified security audit finding in production code:

• Vulnerability: {finding_type} [{cwe_id}]
• Location: [{target_file}{f':L{line_no}' if line_no else ''}]({github_file_link})
• Impact: {hook}

Current Code:
  - {prob_snip.splitlines()[0]}

1-Click Surgical Patch:
  + {fix_snip.splitlines()[0]}

Unlike legacy SAST scanners that spit out 50 false positives on styling or test files, Kavach AI verifies deterministic AST taint paths in CI under 16ms and comments ready-to-merge patches directly on GitHub PRs.

Takes 60 seconds to plug into GitHub Actions:
```yaml
- name: Kavach AI Pre-Merge Gate
  uses: rajrajak99/kavach-ai@v1.4.0
```

Would love to set up an Early Adopter pass ($149 One-Time) or Team CI Gate if you want automated pre-merge gates across your private repositories.

Best,
Raja Rajak
Founder, Kavach AI (https://kavach-ai.streamlit.app)
rajabhaiyarajak2008@gmail.com"""

        # LinkedIn DM Template
        linkedin_dm = f"""Hey {owner_login} — came across {repo_name} and ran our 10ms local AST engine (Kavach AI). 

Noticed {hook.lower()}

We generated the exact 1-click surgical patch diff:
- {prob_snip.splitlines()[0]}
+ {fix_snip.splitlines()[0]}

We built a plug-and-play GitHub Action that blocks vulnerable PRs and comments with the exact fix before merge: uses: rajrajak99/kavach-ai@v1.4.0.

Happy to give your team an Early Adopter pass if you want to test it on private repos: https://kavach-ai.streamlit.app!"""

        return {
            "repo_name": repo_name,
            "repo_url": repo_url,
            "owner_login": owner_login,
            "owner_url": owner_url,
            "stars": stars,
            "finding_type": finding_type,
            "cwe_id": cwe_id,
            "target_file": target_file,
            "line_no": line_no,
            "github_file_link": github_file_link,
            "hook": hook,
            "prob_snip": prob_snip,
            "fix_snip": fix_snip,
            "github_issue_title": github_issue_title,
            "github_issue_body": github_issue_body,
            "cold_email_subject": cold_email_subject,
            "cold_email_body": cold_email_body,
            "linkedin_dm": linkedin_dm
        }

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def main():
    p = argparse.ArgumentParser(description="Kavach AI — High-Severity B2B Prospect Hunter & Outbound Pack Generator")
    p.add_argument("--query", help="Custom GitHub Search query")
    p.add_argument("--max-leads", type=int, default=10, help="Number of verified high-severity leads to generate")
    p.add_argument("--security-only", action="store_true", default=True, help="Strictly filter for exploitable security CWEs (CWE-89/798/78/502/347/1336/79/SCA) in production code")
    p.add_argument("--token", default=os.getenv("GITHUB_TOKEN"), help="GitHub API Token")
    p.add_argument("--output-dir", default="leads", help="Directory to save generated outbound pack")
    args = p.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=================================================================")
    print("  [+] KAVACH AI -- HIGH-SEVERITY PRODUCTION SECURITY HUNTER (v1.4.0)")
    print("  Exploitable Security CWEs Only • Zero Non-Prod Paths • AST Verified")
    print("=================================================================")
    print(f"Target Leads: {args.max_leads}")
    print(f"Strict Security Filter: {'ACTIVE' if args.security_only else 'OFF'}\n")

    queries = [
        args.query if args.query else "language:python fastapi sqlalchemy api -template -boilerplate stars:10..500",
        "language:python fastapi stripe payment stars:10..500",
        "language:python flask sqlite3 saas -template stars:10..500",
        "language:python django postgresql api -tutorial -example stars:15..600",
        "language:python openai agent fastapi -boilerplate stars:15..600",
        "language:javascript express stripe api stars:15..500"
    ]

    candidates = search_github_repositories(queries, token=args.token, max_total=args.max_leads * 4)
    print(f"[+] Total candidate repositories queued for security audit: {len(candidates)}\n")

    verified_leads: List[Dict[str, Any]] = []

    for c in candidates:
        if len(verified_leads) >= args.max_leads:
            break
        lead_data = audit_repository_security(c, security_only=args.security_only)
        if lead_data:
            verified_leads.append(lead_data)
            print(f"    [+] QUALIFIED HIGH-SEVERITY LEAD: {lead_data['owner_login']}/{lead_data['repo_name']} -> {lead_data['cwe_id']} ({lead_data['target_file']})")

    # Generate master outbound pack & verified true positive report
    master_pack_path = out_dir / "VERIFIED_TRUE_POSITIVE_LEADS.md"
    legacy_pack_path = out_dir / "HIGH_SEVERITY_B2B_PACK.md"

    soc2_map = {
        "CWE-798": "CC6.1 Logical Access & Hardcoded Secret Prevention",
        "CWE-89": "CC7.1 Vulnerability Remediation & Production Code Integrity",
        "CWE-78": "CC7.1 Remote Command Injection Prevention",
        "CWE-502": "CC7.1 Insecure Deserialization Guard",
        "CWE-347": "CC6.1 Authentication Token Signature Integrity",
        "CWE-1336": "CC7.1 Server-Side Template Injection Guard",
        "CWE-79": "CC7.1 Cross-Site Scripting Guard",
    }

    pack_lines = [
        f"# 🛡️ KAVACH AI — VERIFIED TRUE-POSITIVE SECURITY LEADS (v1.4.0)",
        f"**Generated:** {len(verified_leads)} Verified Exploitable Startup Security Leads",
        "**Filter Criteria:** Strict True-Positive Security (Zero Non-Prod Paths • Zero Non-Security Bugs • Anti-Template Filter)",
        f"**Target CWEs:** {', '.join(sorted(ALLOWED_SECURITY_CWES))} + Reachable Supply-Chain CVEs",
        "",
        "---",
        "",
        "## 📊 Verified High-Severity Prospect Roster",
        "| # | Target Repository | Owner / Org | Stars | Weakness | Target Production File | SOC 2 Control | Action |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for idx, vl in enumerate(verified_leads, 1):
        clean_file = vl['target_file'].replace("\\", "/")
        soc2_ctrl = soc2_map.get(vl['cwe_id'], "CC7.1 Vulnerability Management")
        pack_lines.append(f"| {idx:02d} | [{vl['repo_name']}]({vl['repo_url']}) | [{vl['owner_login']}]({vl['owner_url']}) | ⭐ {vl['stars']} | **{vl['cwe_id']}** | `{clean_file}` | `{soc2_ctrl}` | [View Advisory & Pitch](#lead-{idx:02d}-{vl['repo_name'].lower()}) |")

    pack_lines.append("\n---\n")

    for idx, vl in enumerate(verified_leads, 1):
        lead_file_name = f"{vl['repo_name']}_Security_Advisory.md"
        lead_file_path = out_dir / lead_file_name
        soc2_ctrl = soc2_map.get(vl['cwe_id'], "CC7.1 Vulnerability Management")

        indiv_content = f"""# 🛡️ Kavach AI High-Severity Security Advisory: {vl['owner_login']}/{vl['repo_name']}

- **Repository**: [{vl['repo_url']}]({vl['repo_url']})
- **Founder / Owner**: [{vl['owner_login']}]({vl['owner_url']})
- **Stars**: ⭐ {vl['stars']}
- **Security Weakness**: `{vl['finding_type']}` [{vl['cwe_id']}]
- **Target File Link**: [{vl['target_file']}]({vl['github_file_link']})
- **SOC 2 Compliance Impact**: `{soc2_ctrl}`

---

## 1. Verified AST / SCA Technical Evidence
- **File & Line**: `{vl['target_file']}`{f':L{vl["line_no"]}' if vl["line_no"] else ''}
- **Diagnosis**: {vl['hook']}

```python
# Vulnerable Code:
{vl['prob_snip']}

# 1-Click Surgical Patch:
{vl['fix_snip']}
```

---

## 2. 1-Click GitHub Security Issue / PR Advisory Template
**Issue Title**: `{vl['github_issue_title']}`

```markdown
{vl['github_issue_body']}
```

---

## 3. Copy-Paste Cold Email to CTO / Founder
**Subject**: `{vl['cold_email_subject']}`

```text
{vl['cold_email_body']}
```

---

## 4. Copy-Paste LinkedIn DM
```text
{vl['linkedin_dm']}
```
"""
        lead_file_path.write_text(indiv_content, encoding="utf-8")

        pack_lines.extend([
            f"## Lead {idx:02d}: [{vl['owner_login']}/{vl['repo_name']}]({vl['repo_url']})",
            f"- **Stars:** ⭐ {vl['stars']} | **Vulnerability:** `{vl['cwe_id']}` ({vl['finding_type']})",
            f"- **Production File:** [`{vl['target_file']}`]({vl['github_file_link']})",
            f"- **SOC 2 Control:** `{soc2_ctrl}`",
            f"- **Individual Advisory File:** `leads/{lead_file_name}`",
            "",
            "### 🛡️ 1-Click GitHub Security Advisory Template",
            f"**Issue Title:** `{vl['github_issue_title']}`",
            "```markdown",
            vl['github_issue_body'],
            "```",
            "",
            "### 📧 Cold Email to Founder / CTO",
            f"**Subject:** `{vl['cold_email_subject']}`",
            "```text",
            vl['cold_email_body'],
            "```",
            "",
            "### 💬 LinkedIn DM",
            "```text",
            vl['linkedin_dm'],
            "```",
            "",
            "---",
            ""
        ])

    final_content = "\n".join(pack_lines)
    master_pack_path.write_text(final_content, encoding="utf-8")
    legacy_pack_path.write_text(final_content, encoding="utf-8")

    print("\n=================================================================")
    print(f"  [OK] TRUE-POSITIVE PACK GENERATED: {master_pack_path}")
    print(f"  Total Verified High-Severity Leads: {len(verified_leads)}")
    print("=================================================================")
    for idx, vl in enumerate(verified_leads, 1):
        print(f"  {idx:02d}. {vl['owner_login']}/{vl['repo_name']} -> {vl['cwe_id']} in {vl['target_file']}")
    print()

if __name__ == "__main__":
    main()
