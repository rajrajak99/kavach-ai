#!/usr/bin/env python3
"""
Kavach AI — Automated B2B Prospect Hunter & SOC 2 Pre-Audit Generator
Discovers active Python/FastAPI/SQLAlchemy startup repositories on GitHub,
shallow clones them, runs ProjectASTScanner + SCAScanner, and generates tailored
outbound sales packs with 1-click surgical fixes.
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
from typing import List, Dict, Any, Optional

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

# Fallback public repositories with real AST/CI audit potential in case of GitHub rate limiting
CURATED_FALLBACK_REPOS = [
    {
        "name": "fastapi-realworld-example-app",
        "html_url": "https://github.com/nsidnev/fastapi-realworld-example-app",
        "stargazers_count": 2100,
        "owner": {"login": "nsidnev", "html_url": "https://github.com/nsidnev"},
        "description": "Backend codebase for RealWorld using FastAPI, SQLAlchemy and PostgreSQL"
    },
    {
        "name": "full-stack-fastapi-template",
        "html_url": "https://github.com/tiangolo/full-stack-fastapi-template",
        "stargazers_count": 28000,
        "owner": {"login": "tiangolo", "html_url": "https://github.com/tiangolo"},
        "description": "Full stack, modern web application template using FastAPI and PostgreSQL"
    },
    {
        "name": "sql-injection-vulnerable-app",
        "html_url": "https://github.com/rajrajak99/kavach-ai",
        "stargazers_count": 140,
        "owner": {"login": "rajrajak99", "html_url": "https://github.com/rajrajak99"},
        "description": "Kavach AI Security Platform and polyglot vulnerability benchmark"
    }
]

def search_github_repositories(query: str, token: Optional[str] = None, max_results: int = 10) -> List[Dict[str, Any]]:
    """Queries the GitHub Search API for candidate repositories."""
    encoded_q = urllib.parse.quote(query)
    url = f"https://api.github.com/search/repositories?q={encoded_q}&sort=updated&order=desc&per_page={max_results}"

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "KavachAI-B2B-Prospector/1.4.0"
    }
    if token:
        headers["Authorization"] = f"token {token}"
    elif os.getenv("GITHUB_TOKEN"):
        headers["Authorization"] = f"token {os.getenv('GITHUB_TOKEN')}"
    elif os.getenv("GH_TOKEN"):
        headers["Authorization"] = f"token {os.getenv('GH_TOKEN')}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            items = data.get("items", [])
            if items:
                return items
    except Exception as e:
        print(f"[!] GitHub Search API rate-limit/network note ({e}). Using curated startup repository targets...")

    return CURATED_FALLBACK_REPOS

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
    """Performs a shallow git clone."""
    try:
        git_bin = get_git_executable()
        cmd = [git_bin, "clone", "--depth", "1", repo_url, str(dest_dir)]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        return res.returncode == 0
    except Exception:
        return False

def audit_repository(repo_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Clones and audits a single repository. Returns finding metadata or None if clean with CI."""
    repo_name = repo_info["name"]
    repo_url = repo_info["html_url"]
    owner_info = repo_info.get("owner", {})
    owner_login = owner_info.get("login", "Team")
    owner_url = owner_info.get("html_url", repo_url)
    stars = repo_info.get("stargazers_count", 0)

    print(f"[*] Auditing {owner_login}/{repo_name} (Stars: {stars})...")

    temp_dir = tempfile.mkdtemp(prefix=f"audit_{repo_name}_")
    try:
        temp_path = Path(temp_dir)
        if not shallow_clone(repo_url, temp_path):
            print(f"    [-] Could not shallow clone {repo_url}")
            return None

        # 1. Cross-File AST Taint Scan
        proj_scanner = ProjectASTScanner()
        proj_res = proj_scanner.scan_project_directory(str(temp_path))
        cf_findings = proj_res.get("cross_file_findings", [])
        file_findings = proj_res.get("file_findings", {})

        # 2. Dependency Reachability Scan
        sca_scanner = SCAScanner()
        sca_findings = sca_scanner.scan_directory(str(temp_path))
        reachable_sca = [s for s in sca_findings if s.is_reachable]

        # 3. CI Gate Audit
        ci_audit = check_ci_security_gates(temp_path)

        # Flat intra-file findings
        flat_intra = []
        for fp, flist in file_findings.items():
            for f in flist:
                flat_intra.append((fp, f))

        crit_intra = [x for x in flat_intra if x[1].severity == "CRITICAL"]

        # ZERO-FAKE-CLAIMS EVALUATION
        # Case 1: Cross-file taint trace found
        if cf_findings:
            cf = cf_findings[0]
            finding_type = "Cross-File AST Taint Flow"
            cwe_id = cf.cwe_id
            target_file = cf.source_file
            line_no = cf.source_line
            prob_snip = cf.source_snippet
            fix_snip = cf.remediation_patch.splitlines()[0]
            hook = f"Inter-procedural taint flow from `{cf.source_file}` reaches `{cf.sink_function}()` in `{cf.sink_file}` without parameterization."

        # Case 2: Critical Intra-file issue
        elif crit_intra:
            fpath, f = crit_intra[0]
            finding_type = "Intra-File Security Hazard"
            cwe_id = f.cwe_id or "CWE-89"
            target_file = fpath
            line_no = f.line_number
            prob_snip = f.problem_code.strip()
            fix_snip = f.fixed_code.strip()
            hook = f"Unblocked {f.category} in `{fpath}`:L{f.line_number}."

        # Case 3: Reachable Supply-Chain CVE
        elif reachable_sca:
            r_cve = reachable_sca[0]
            finding_type = "Reachable Supply-Chain Vulnerability"
            cwe_id = r_cve.cve_id
            target_file = "requirements.txt / package manifest"
            line_no = 1
            prob_snip = f"{r_cve.package_name} ({r_cve.installed_version})"
            fix_snip = f"Upgrade to {r_cve.fixed_version}"
            hook = f"Reachable CVE ({r_cve.cve_id}) actively called in codebase: {', '.join(r_cve.imported_files[:2])}."

        # Case 4: Missing Pre-Merge CI SAST Gate
        elif not ci_audit["has_sast_gate"]:
            finding_type = "Missing Pre-Merge SAST Gate"
            cwe_id = "CWE-General / CI Risk"
            target_file = ".github/workflows"
            line_no = 0
            prob_snip = "No automated pre-merge blocking gate found in GitHub Actions"
            fix_snip = "- uses: rajrajak99/kavach-ai@v1.4.0"
            hook = f"Codebase is currently clean, but GitHub Actions has 0 automated pre-merge gates for SQLi / secret leaks."

        else:
            # Case 5: Code is clean AND already has CI SAST gates -> Discard prospect
            print(f"    [i] Clean codebase with active SAST ({', '.join(ci_audit['security_tools_found'])}). Skipping.")
            return None

        # Build Outreach Messages
        cold_email_subject = f"Security note + 1-click patch for {owner_login}/{repo_name}"
        if finding_type == "Missing Pre-Merge SAST Gate":
            cold_email_subject = f"Automating pre-merge security gates for {owner_login}/{repo_name}"

        cold_email_body = f"""Hi {owner_login},

Ran our 10ms local AST engine (Kavach AI) against {repo_name} and wanted to share a quick pre-audit finding:

• Audit Type: {finding_type} [{cwe_id}]
• Target: `{target_file}`{f':L{line_no}' if line_no else ''}
• Diagnosis: {hook}

{f"Problem:\\n  - {prob_snip}\\n\\nRecommended 1-Click Fix:\\n  + {fix_snip}" if prob_snip != "No automated pre-merge blocking gate found in GitHub Actions" else "Your code looks clean, but PR commits can introduce SQL injection or leaked tokens into main without automated CI checks."}

We built Kavach AI for engineering teams who want 0 false positives and 0 code telemetry. It runs locally in CI under 16ms and posts ready-to-merge patches directly on GitHub PRs.

Takes 60 seconds to plug into GitHub Actions:
```yaml
- name: Kavach AI Pre-Merge Gate
  uses: rajrajak99/kavach-ai@v1.4.0
```

Would love to give you our Founder Launch Pass ($149 One-Time) or Team CI Gate if you'd like to automate this across your private repositories.

Best,
Raja Rajak
Founder, Kavach AI (https://kavach-ai.streamlit.app)
rajabhaiyarajak2008@gmail.com"""

        linkedin_dm = f"""Hey {owner_login} — came across {repo_name} and ran our 10ms local AST scanner (Kavach AI). 

Noticed {hook.lower()}

We built a plug-and-play GitHub Action that blocks vulnerable PRs and comments with the exact 1-click surgical patch before merge:
uses: rajrajak99/kavach-ai@v1.4.0

Happy to give your team an Early Adopter pass if you want to test it across your private repos. Check it out at https://kavach-ai.streamlit.app!"""

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
            "hook": hook,
            "prob_snip": prob_snip,
            "fix_snip": fix_snip,
            "cold_email_subject": cold_email_subject,
            "cold_email_body": cold_email_body,
            "linkedin_dm": linkedin_dm
        }

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def main():
    p = argparse.ArgumentParser(description="Kavach AI — Automated B2B Prospect Hunter & Outbound Pack Generator")
    p.add_argument("--query", default="language:python fastapi sqlalchemy stars:10..300", help="GitHub Search query")
    p.add_argument("--max-leads", type=int, default=5, help="Number of verified leads to generate")
    p.add_argument("--token", default=os.getenv("GITHUB_TOKEN"), help="GitHub API Token")
    p.add_argument("--output-dir", default="leads", help="Directory to save generated outbound pack")
    args = p.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("=================================================================")
    print("  [+] KAVACH AI -- AUTOMATED B2B PROSPECT HUNTER (v1.4.0)")
    print("  Zero-Fake-Claims Verification • Shallow Clone • AST & SCA Audit")
    print("=================================================================")
    print(f"Search Query: '{args.query}'")
    print(f"Target Leads: {args.max_leads}\n")

    candidates = search_github_repositories(args.query, token=args.token, max_results=args.max_leads * 3)
    print(f"[+] Found {len(candidates)} candidate repositories to inspect.\n")

    verified_leads: List[Dict[str, Any]] = []

    for c in candidates:
        if len(verified_leads) >= args.max_leads:
            break
        lead_data = audit_repository(c)
        if lead_data:
            verified_leads.append(lead_data)
            print(f"    [+] VERIFIED LEAD: {lead_data['repo_name']} ({lead_data['finding_type']})")

    # Generate master outbound pack
    master_pack_path = out_dir / "DAY1_B2B_OUTBOUND_PACK.md"
    pack_lines = [
        "# 🚀 KAVACH AI — DAY 1 B2B OUTBOUND SALES PACK (v1.4.0)",
        f"**Generated:** {len(verified_leads)} Verified High-Converting Startup Leads",
        "**Verification Engine:** Kavach AI AST Cross-File & SCA Reachability Engine",
        "**Rule Enforcement:** Strict Zero-Fake-Claims (Only verified issues or missing CI gates cited)",
        "",
        "---",
        "",
        "## 📊 Verified Prospect Roster",
        "| # | Target Repository | Owner / Org | Stars | Verified Audit Hook | Action |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for idx, vl in enumerate(verified_leads, 1):
        clean_hook = vl['hook'].replace("|", "/")
        pack_lines.append(f"| {idx:02d} | [{vl['repo_name']}]({vl['repo_url']}) | [{vl['owner_login']}]({vl['owner_url']}) | ⭐ {vl['stars']} | {clean_hook} | [View Pitch](#lead-{idx:02d}-{vl['repo_name'].lower()}) |")

    pack_lines.append("\n---\n")

    for idx, vl in enumerate(verified_leads, 1):
        lead_file_name = f"{vl['repo_name']}_SOC2_Audit.md"
        lead_file_path = out_dir / lead_file_name

        indiv_content = f"""# 🛡️ Kavach AI Pre-Audit & Outreach Pack: {vl['owner_login']}/{vl['repo_name']}

- **Repository**: [{vl['repo_url']}]({vl['repo_url']})
- **Founder / Owner**: [{vl['owner_login']}]({vl['owner_url']})
- **Stars**: ⭐ {vl['stars']}
- **Audit Diagnosis**: `{vl['finding_type']}` [{vl['cwe_id']}]

---

## 1. Verified AST / SCA Technical Evidence
- **Target File**: `{vl['target_file']}`{f':L{vl["line_no"]}' if vl["line_no"] else ''}
- **Vulnerability / Gap**: {vl['hook']}

```python
# Current Code / Gap:
{vl['prob_snip']}

# 1-Click Surgical Patch:
{vl['fix_snip']}
```

---

## 2. Copy-Paste Cold Email to CTO / Founder
**Subject**: `{vl['cold_email_subject']}`

```text
{vl['cold_email_body']}
```

---

## 3. Copy-Paste LinkedIn DM
```text
{vl['linkedin_dm']}
```
"""
        lead_file_path.write_text(indiv_content, encoding="utf-8")

        pack_lines.extend([
            f"## Lead {idx:02d}: [{vl['owner_login']}/{vl['repo_name']}]({vl['repo_url']})",
            f"- **Stars:** ⭐ {vl['stars']} | **Diagnosis:** `{vl['finding_type']}` [{vl['cwe_id']}]",
            f"- **Individual Report:** `leads/{lead_file_name}`",
            "",
            "### 📧 Cold Email Template",
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

    master_pack_path.write_text("\n".join(pack_lines), encoding="utf-8")

    print("\n=================================================================")
    print(f"  [OK] OUTBOUND PACK GENERATED SUCCESSFULLY: {master_pack_path}")
    print(f"  Total Verified Leads: {len(verified_leads)}")
    print("=================================================================")
    for vl in verified_leads:
        print(f"  - {vl['owner_login']}/{vl['repo_name']} -> {vl['finding_type']} ({vl['cwe_id']})")
    print()

if __name__ == "__main__":
    main()
