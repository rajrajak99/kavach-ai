"""
Kavach AI — Software Composition Analysis (SCA) & AST Reachability Engine
Parses requirements.txt, pyproject.toml, and package.json; checks against
known advisory databases; and performs AST reachability to determine if the
vulnerable package is actively imported in production code.
"""

import re
import ast
import json
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Set

@dataclass
class SCAReachabilityFinding:
    package_name: str
    installed_version: str
    fixed_version: str
    cve_id: str
    severity: str
    is_reachable: bool
    reachability_status: str
    imported_files: List[str]
    advisory_title: str
    remediation_advice: str

class SCAScanner:
    """
    Offline Supply Chain & Reachability Analyzer that eliminates false alarms
    by cross-referencing manifest CVEs against AST import nodes.
    """

    # Curated offline advisory database of high-severity CVEs
    ADVISORY_DB = {
        # Python dependencies
        "requests": {
            "vulnerable_below": "2.31.0",
            "cve": "CVE-2023-32681",
            "severity": "HIGH",
            "title": "Proxy-Authorization Header Leakage on HTTP Redirect",
            "fix": "requests>=2.31.0"
        },
        "urllib3": {
            "vulnerable_below": "2.0.7",
            "cve": "CVE-2023-45803",
            "severity": "HIGH",
            "title": "Request Body / Cookie Leakage on Cross-Origin Redirect",
            "fix": "urllib3>=2.0.7"
        },
        "pyyaml": {
            "vulnerable_below": "5.4.0",
            "cve": "CVE-2020-14343",
            "severity": "CRITICAL",
            "title": "Arbitrary Code Execution via FullLoader / Custom Tags",
            "fix": "pyyaml>=5.4.1"
        },
        "django": {
            "vulnerable_below": "3.2.25",
            "cve": "CVE-2024-27351",
            "severity": "CRITICAL",
            "title": "Regular Expression Denial of Service (ReDoS)",
            "fix": "django>=4.2.11"
        },
        "flask": {
            "vulnerable_below": "2.2.5",
            "cve": "CVE-2023-30861",
            "severity": "HIGH",
            "title": "Cookie Session Disclosure / Header Injection",
            "fix": "flask>=2.3.2"
        },
        "cryptography": {
            "vulnerable_below": "41.0.6",
            "cve": "CVE-2023-49083",
            "severity": "MEDIUM",
            "title": "NULL Pointer Dereference in PKCS7 Parsing",
            "fix": "cryptography>=41.0.7"
        },
        "jinja2": {
            "vulnerable_below": "3.1.3",
            "cve": "CVE-2024-22195",
            "severity": "HIGH",
            "title": "Cross-Site Scripting (XSS) via xmlattr Filter",
            "fix": "jinja2>=3.1.4"
        },
        "pillow": {
            "vulnerable_below": "10.2.0",
            "cve": "CVE-2023-50447",
            "severity": "CRITICAL",
            "title": "Arbitrary Code Execution via ImageMath Environment Injection",
            "fix": "pillow>=10.2.0"
        },
        # Node.js / JavaScript dependencies
        "jsonwebtoken": {
            "vulnerable_below": "9.0.0",
            "cve": "CVE-2022-23529",
            "severity": "CRITICAL",
            "title": "Arbitrary Code Execution via Untrusted Key Objects",
            "fix": "jsonwebtoken>=9.0.0"
        },
        "lodash": {
            "vulnerable_below": "4.17.21",
            "cve": "CVE-2021-23337",
            "severity": "HIGH",
            "title": "Command Injection via template Functions",
            "fix": "lodash>=4.17.21"
        },
        "express": {
            "vulnerable_below": "4.19.2",
            "cve": "CVE-2024-29041",
            "severity": "MEDIUM",
            "title": "Open Redirect via Malformed URL Encoded Path",
            "fix": "express>=4.19.2"
        },
        "axios": {
            "vulnerable_below": "1.6.0",
            "cve": "CVE-2023-45857",
            "severity": "HIGH",
            "title": "Cross-Site Request Forgery via Insecure Header Handling",
            "fix": "axios>=1.6.0"
        },
        # Go dependencies
        "github.com/gin-gonic/gin": {
            "vulnerable_below": "1.9.1",
            "cve": "CVE-2023-29401",
            "severity": "HIGH",
            "title": "Memory Exhaustion / Uncontrolled Resource Consumption in Form Multipart Parsing",
            "fix": "github.com/gin-gonic/gin>=v1.9.1"
        },
        "golang.org/x/crypto": {
            "vulnerable_below": "0.17.0",
            "cve": "CVE-2023-48795",
            "severity": "HIGH",
            "title": "Terrapin Attack: Prefix Truncation in SSH Channel State Machine",
            "fix": "golang.org/x/crypto>=v0.17.0"
        },
        "google.golang.org/grpc": {
            "vulnerable_below": "1.53.0",
            "cve": "CVE-2023-44487",
            "severity": "CRITICAL",
            "title": "HTTP/2 Rapid Reset Denial of Service (RST_STREAM Flooding)",
            "fix": "google.golang.org/grpc>=v1.53.0"
        }
    }

    def scan_dependencies_and_reachability(
        self,
        manifest_files: Dict[str, str],
        code_files: Dict[str, str]
    ) -> List[SCAReachabilityFinding]:
        """
        Parses declared dependencies from manifests and searches code_files AST
        to classify reachability.
        """
        declared_pkgs = self._parse_manifests(manifest_files)
        if not declared_pkgs:
            return []

        # Find all imported modules across code_files
        imported_map = self._extract_ast_imports(code_files)

        findings: List[SCAReachabilityFinding] = []
        for pkg, ver in declared_pkgs.items():
            pkg_lower = pkg.lower().replace("-", "_")
            # Check if this package exists in advisory DB
            for adv_pkg, adv_info in self.ADVISORY_DB.items():
                if adv_pkg.replace("-", "_") == pkg_lower:
                    is_vuln = self._is_version_vulnerable(ver, adv_info["vulnerable_below"])
                    if is_vuln:
                        # Check AST reachability
                        imported_locations = imported_map.get(pkg_lower, [])
                        # Also check without underscores
                        if not imported_locations:
                            imported_locations = imported_map.get(adv_pkg, [])

                        is_reachable = len(imported_locations) > 0
                        status_str = (
                            "🚨 REACHABLE IN AST (Active Exploit Path)"
                            if is_reachable
                            else "🛡️ UNREACHABLE IN CODE (Dormant Library)"
                        )

                        finding = SCAReachabilityFinding(
                            package_name=pkg,
                            installed_version=ver or "Unspecified",
                            fixed_version=adv_info["fix"],
                            cve_id=adv_info["cve"],
                            severity=adv_info["severity"],
                            is_reachable=is_reachable,
                            reachability_status=status_str,
                            imported_files=imported_locations,
                            advisory_title=adv_info["title"],
                            remediation_advice=f"Upgrade '{pkg}' to {adv_info['fix']} in package manifest."
                        )
                        findings.append(finding)

        return findings

    def scan_project_dict(self, file_contents: Dict[str, str]) -> List[SCAReachabilityFinding]:
        """
        Scans a dictionary mapping file paths to file contents for vulnerable dependencies
        and correlates AST imports.
        """
        manifests = {}
        codes = {}
        for fname, content in file_contents.items():
            lower = fname.lower()
            if any(m in lower for m in ("requirements", "pyproject.toml", "package.json", "go.mod")):
                manifests[fname] = content
            if any(lower.endswith(ext) for ext in (".py", ".js", ".jsx", ".ts", ".tsx", ".go")):
                codes[fname] = content
        return self.scan_dependencies_and_reachability(manifests, codes)

    def scan_directory(self, dir_path: str) -> List[SCAReachabilityFinding]:
        """
        Walks a directory, identifies manifest files and code files, and performs
        SCA reachability analysis.
        """
        p = Path(dir_path)
        manifests = {}
        codes = {}
        for f in p.rglob("*"):
            if f.is_file() and not any(part.startswith(".") or part in ("node_modules", "venv", ".venv", "dist", "build", "__pycache__") for part in f.parts):
                lower = f.name.lower()
                try:
                    content = f.read_text(encoding="utf-8", errors="replace")
                    rel = str(f.relative_to(p)).replace("\\", "/")
                    if any(m in lower for m in ("requirements", "pyproject.toml", "package.json", "go.mod")):
                        manifests[rel] = content
                    if any(lower.endswith(ext) for ext in (".py", ".js", ".jsx", ".ts", ".tsx", ".go")):
                        codes[rel] = content
                except Exception:
                    pass
        return self.scan_dependencies_and_reachability(manifests, codes)

    def _parse_manifests(self, manifest_files: Dict[str, str]) -> Dict[str, str]:
        """
        Extracts package name and version from requirements.txt, pyproject.toml, package.json, go.mod.
        """
        declared: Dict[str, str] = {}

        for fname, content in manifest_files.items():
            lower_name = fname.lower()
            if "requirements" in lower_name and lower_name.endswith(".txt"):
                for line in content.splitlines():
                    clean = line.strip().split("#")[0].strip()
                    if clean and not clean.startswith("-"):
                        m = re.match(r'^([a-zA-Z0-9_\-\.]+)(?:[=><~^!]+([0-9a-zA-Z_\-\.]+))?', clean)
                        if m:
                            pkg_name = m.group(1).strip()
                            pkg_ver = m.group(2).strip() if m.group(2) else ""
                            declared[pkg_name] = pkg_ver

            elif lower_name.endswith("pyproject.toml"):
                # Simple extraction of dependencies array
                in_deps = False
                for line in content.splitlines():
                    if "dependencies =" in line or "[project.dependencies]" in line:
                        in_deps = True
                        continue
                    if in_deps and line.startswith("]"):
                        in_deps = False
                    if in_deps:
                        m = re.search(r'[\"\']([a-zA-Z0-9_\-\.]+)(?:[=><~^!]+([0-9a-zA-Z_\-\.]+))?[\"\']', line)
                        if m:
                            declared[m.group(1).strip()] = m.group(2).strip() if m.group(2) else ""

            elif lower_name.endswith("package.json"):
                try:
                    data = json.loads(content)
                    for sec in ("dependencies", "devDependencies"):
                        if sec in data and isinstance(data[sec], dict):
                            for pkg_name, ver_str in data[sec].items():
                                clean_ver = re.sub(r'[\^~>=<v]', '', str(ver_str)).strip()
                                declared[pkg_name] = clean_ver
                except Exception:
                    pass

            elif lower_name.endswith("go.mod"):
                in_require = False
                for line in content.splitlines():
                    clean = line.strip().split("//")[0].strip()
                    if clean.startswith("require ("):
                        in_require = True
                        continue
                    if in_require and clean == ")":
                        in_require = False
                        continue
                    if in_require:
                        parts = clean.split()
                        if len(parts) >= 2:
                            pkg_name = parts[0].strip()
                            pkg_ver = parts[1].strip().lstrip("v")
                            declared[pkg_name] = pkg_ver
                    elif clean.startswith("require "):
                        parts = clean.replace("require ", "").strip().split()
                        if len(parts) >= 2:
                            pkg_name = parts[0].strip()
                            pkg_ver = parts[1].strip().lstrip("v")
                            declared[pkg_name] = pkg_ver

        return declared

    def _extract_ast_imports(self, code_files: Dict[str, str]) -> Dict[str, List[str]]:
        """
        Extracts all imported library root names and maps to list of filenames where imported.
        """
        imported_map: Dict[str, List[str]] = {}

        def record(mod_name: str, file_path: str):
            if not mod_name:
                return
            root = mod_name.split(".")[0].lower().replace("-", "_")
            if root not in imported_map:
                imported_map[root] = []
            if file_path not in imported_map[root]:
                imported_map[root].append(file_path)

            # Also record full import string (crucial for Go import paths like github.com/gin-gonic/gin)
            full_norm = mod_name.lower().strip('"')
            if full_norm not in imported_map:
                imported_map[full_norm] = []
            if file_path not in imported_map[full_norm]:
                imported_map[full_norm].append(file_path)

        for fpath, code in code_files.items():
            if fpath.endswith(".py"):
                try:
                    tree = ast.parse(code)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                record(alias.name, fpath)
                        elif isinstance(node, ast.ImportFrom) and node.module:
                            record(node.module, fpath)
                except Exception:
                    pass
            elif fpath.endswith((".js", ".jsx", ".ts", ".tsx")):
                # Regex match require() or import ... from '...'
                for match in re.finditer(r'(?:require\s*\(\s*[\"\']([^\"\'\./][^\"\'\s]*)[\"\']|from\s*[\"\']([^\"\'\./][^\"\'\s]*)[\"\'])', code):
                    mod = match.group(1) or match.group(2)
                    if mod:
                        record(mod, fpath)
            elif fpath.endswith(".go"):
                for m_single in re.finditer(r'import\s+"([^"]+)"', code):
                    record(m_single.group(1), fpath)
                for m_block in re.finditer(r'import\s*\(\s*([^)]+)\s*\)', code):
                    for line in m_block.group(1).splitlines():
                        m_pkg = re.search(r'"([^"]+)"', line)
                        if m_pkg:
                            record(m_pkg.group(1), fpath)

        return imported_map

    def query_osv_api(
        self,
        package_name: str,
        version: str,
        ecosystem: str = "PyPI"
    ) -> List[Dict[str, Any]]:
        """
        Queries Google's public OSV API (https://api.osv.dev/v1/query) for real-time
        CVE vulnerability records. Falls back safely to empty list on network timeout/offline.
        """
        import urllib.request
        import urllib.error

        url = "https://api.osv.dev/v1/query"
        payload = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "KavachAI-SCA/1.0"}
            )
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("vulns", [])
        except Exception:
            return []

    def _is_version_vulnerable(self, installed_ver: str, safe_below: str) -> bool:
        """
        Checks whether installed_ver < safe_below using semantic comparison.
        If version is unspecified, conservatively treats as vulnerable.
        """
        if not installed_ver:
            return True

        def to_tuple(v_str: str):
            parts = re.split(r'[\.\-]', re.sub(r'[^0-9\.]', '', v_str))
            nums = []
            for p in parts:
                if p.isdigit():
                    nums.append(int(p))
            return tuple(nums) or (0,)

        try:
            return to_tuple(installed_ver) < to_tuple(safe_below)
        except Exception:
            return True
