"""
Kavach AI — Inter-Procedural Cross-File AST Taint Analyzer
Builds project-wide symbol tables, tracks cross-file imports, and traces
data flows across modules (e.g. routes.py -> service.py -> db/queries.py).
"""

import os
import ast
import re
import zipfile
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set, Tuple

from core.diff_parser import DiffParser, ParsedFileDiff
from core.surgical_analyzer import SurgicalAnalyzer, PatchFinding
from core.polyglot.go_scanner import GoScanner
from core.polyglot.ts_scanner import TSScanner
from core.polyglot.terraform_scanner import TerraformScanner

@dataclass
class CrossFileTaintFinding:
    severity: str
    category: str
    source_file: str
    source_line: int
    call_file: str
    call_line: int
    sink_file: str
    sink_line: int
    sink_function: str
    tainted_param: str
    cwe_id: str
    explanation: str
    source_snippet: str
    sink_snippet: str
    remediation_patch: str

@dataclass
class FunctionSinkSignature:
    func_name: str
    file_path: str
    line_number: int
    params: List[str]
    sink_type: str        # 'SQL', 'SUBPROCESS', 'YAML', 'PICKLE'
    sink_line: int
    sink_param: str
    sink_snippet: str
    cwe_id: str

class ProjectASTScanner:
    """
    Project-wide static analyzer that builds cross-file call graphs and
    traces untrusted user input across multiple Python modules and polyglot files.
    """

    SUPPORTED_EXTS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.go', '.tf'}

    def __init__(self):
        self.analyzer = SurgicalAnalyzer()
        self.diff_parser = DiffParser()
        self.go_scanner = GoScanner()
        self.ts_scanner = TSScanner()
        self.tf_scanner = TerraformScanner()

    def scan_project_directory(self, project_dir: str) -> Dict[str, Any]:
        """
        Recursively inspects a directory, running both intra-file surgical checks
        and inter-procedural cross-file taint analysis.
        """
        root_path = Path(project_dir).resolve()
        if not root_path.exists():
            return {
                "success": False,
                "error": f"Directory '{project_dir}' does not exist.",
                "files_scanned": 0,
                "file_findings": {},
                "cross_file_findings": [],
                "metrics": {"critical": 0, "security": 0, "cross_file": 0, "total": 0}
            }

        file_contents: Dict[str, str] = {}
        for p in root_path.rglob("*"):
            if p.is_file():
                ext = p.suffix.lower()
                is_manifest = any(m in p.name.lower() for m in ("requirements", "pyproject.toml", "package.json"))
                if ext in self.SUPPORTED_EXTS or is_manifest:
                    rel = str(p.relative_to(root_path)).replace("\\", "/")
                    if not self.diff_parser.is_noise_file(rel):
                        try:
                            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                                file_contents[rel] = f.read()
                        except Exception:
                            pass

        return self.analyze_file_bundle(file_contents, project_name=root_path.name)

    def scan_zip_archive(self, zip_bytes: bytes, project_name: str = "uploaded_repo") -> Dict[str, Any]:
        """
        Extracts an in-memory zip archive and analyzes its files.
        """
        file_contents: Dict[str, str] = {}
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "project.zip"
            with open(zip_path, "wb") as f:
                f.write(zip_bytes)
            
            try:
                with zipfile.ZipFile(zip_path, 'r') as z:
                    for filename in z.namelist():
                        norm_name = filename.replace("\\", "/")
                        ext = Path(norm_name).suffix.lower()
                        is_manifest = any(m in norm_name.lower() for m in ("requirements", "pyproject.toml", "package.json"))
                        if (ext in self.SUPPORTED_EXTS or is_manifest) and not self.diff_parser.is_noise_file(norm_name):
                            try:
                                content = z.read(filename).decode('utf-8', errors='ignore')
                                file_contents[norm_name] = content
                            except Exception:
                                pass
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Invalid zip archive: {str(e)}",
                    "files_scanned": 0,
                    "file_findings": {},
                    "cross_file_findings": [],
                    "metrics": {"critical": 0, "security": 0, "cross_file": 0, "total": 0}
                }

        return self.analyze_file_bundle(file_contents, project_name=project_name)

    def analyze_file_bundle(self, file_contents: Dict[str, str], project_name: str = "project") -> Dict[str, Any]:
        """
        Executes Pass 1 (Function Sink Indexing) and Pass 2 (Cross-File Taint Tracking)
        alongside intra-file inspections.
        """
        file_findings: Dict[str, List[PatchFinding]] = {}
        total_crit = 0
        total_sec = 0
        total_perf = 0

        # Run intra-file analysis on all code files
        for fpath, code in file_contents.items():
            if not any(fpath.endswith(ext) for ext in self.SUPPORTED_EXTS):
                continue
            diff = self.diff_parser.parse_raw_snippet(fpath, code)
            res = self.analyzer.generate_pull_request_review([diff])
            findings = res.get('findings', [])

            # Polyglot routing
            if fpath.endswith(".go"):
                for gf in self.go_scanner.scan_code(code, file_path=fpath):
                    findings.append(PatchFinding(
                        severity=gf.severity,
                        category=gf.category,
                        line_number=gf.line_number,
                        problem_code=gf.vulnerable_snippet,
                        fixed_code=gf.remediation_patch,
                        explanation=gf.explanation,
                        github_suggestion_block=gf.remediation_patch,
                        cwe_id=gf.cwe_id,
                        language="go"
                    ))
            elif fpath.endswith((".ts", ".tsx")):
                for tf in self.ts_scanner.scan_code(code, file_path=fpath):
                    findings.append(PatchFinding(
                        severity=tf.severity,
                        category=tf.category,
                        line_number=tf.line_number,
                        problem_code=tf.vulnerable_snippet,
                        fixed_code=tf.remediation_patch,
                        explanation=tf.explanation,
                        github_suggestion_block=tf.remediation_patch,
                        cwe_id=tf.cwe_id,
                        language="typescript"
                    ))
            elif fpath.endswith(".tf"):
                for tff in self.tf_scanner.scan_code(code, file_path=fpath):
                    findings.append(PatchFinding(
                        severity=tff.severity,
                        category=tff.category,
                        line_number=tff.line_number,
                        problem_code=tff.vulnerable_snippet,
                        fixed_code=tff.remediation_patch,
                        explanation=tff.explanation,
                        github_suggestion_block=tff.remediation_patch,
                        cwe_id=tff.cwe_id,
                        language="terraform"
                    ))

            if findings:
                file_findings[fpath] = findings
                total_crit += sum(1 for f in findings if f.severity == 'CRITICAL')
                total_sec += sum(1 for f in findings if f.severity in ('SECURITY', 'HIGH'))
                total_perf += sum(1 for f in findings if f.severity == 'PERFORMANCE')

        # ---------------- PASS 1: BUILD FUNCTION SINK SIGNATURES ----------------
        function_signatures: Dict[str, FunctionSinkSignature] = {}
        parsed_trees: Dict[str, ast.AST] = {}

        for fpath, code in file_contents.items():
            if not fpath.endswith(".py"):
                continue
            try:
                tree = ast.parse(code)
                parsed_trees[fpath] = tree
                lines = code.splitlines()

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        func_params = [arg.arg for arg in node.args.args]
                        # Inspect statements inside function for sink execution of parameters
                        for sub in ast.walk(node):
                            if isinstance(sub, ast.Call):
                                sink_info = self._detect_sink_param(sub, func_params, lines)
                                if sink_info:
                                    stype, sline, sparam, ssnippet, cwe = sink_info
                                    sig = FunctionSinkSignature(
                                        func_name=node.name,
                                        file_path=fpath,
                                        line_number=node.lineno,
                                        params=func_params,
                                        sink_type=stype,
                                        sink_line=sline,
                                        sink_param=sparam,
                                        sink_snippet=ssnippet,
                                        cwe_id=cwe
                                    )
                                    # Index by both bare func_name and module.func_name
                                    function_signatures[node.name] = sig
                                    mod_key = Path(fpath).stem + "." + node.name
                                    function_signatures[mod_key] = sig
            except Exception:
                continue

        # ---------------- PASS 2: CALL GRAPH & CROSS-FILE TAINT TRACE ----------------
        cross_file_findings: List[CrossFileTaintFinding] = []

        for fpath, tree in parsed_trees.items():
            lines = file_contents[fpath].splitlines()

            # Track imports: alias -> canonical target function
            imported_functions: Dict[str, str] = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        target = alias.name
                        local_name = alias.asname or alias.name
                        imported_functions[local_name] = target
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        imported_functions[alias.asname or alias.name] = alias.name

            # Look for calls to imported sink functions with tainted arguments
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    callee_name = None
                    if isinstance(node.func, ast.Name):
                        callee_name = node.func.id
                    elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        callee_name = f"{node.func.value.id}.{node.func.attr}"

                    if callee_name:
                        # Resolve imported alias if applicable
                        resolved_key = imported_functions.get(callee_name, callee_name)
                        if resolved_key in function_signatures:
                            sig = function_signatures[resolved_key]
                            # Don't flag cross-file if defined in the same file
                            if sig.file_path == fpath:
                                continue

                            # Check if caller passes dynamic/tainted arguments
                            if node.args:
                                arg0 = node.args[0]
                                is_tainted = self._is_argument_tainted(arg0)
                                if is_tainted:
                                    call_line = node.lineno
                                    call_snippet = lines[call_line - 1].strip() if 0 < call_line <= len(lines) else f"{callee_name}(...)"

                                    finding = CrossFileTaintFinding(
                                        severity="CRITICAL",
                                        category=f"Cross-File Inter-Procedural {sig.sink_type} Injection (Taint Trace)",
                                        source_file=fpath,
                                        source_line=call_line,
                                        call_file=fpath,
                                        call_line=call_line,
                                        sink_file=sig.file_path,
                                        sink_line=sig.sink_line,
                                        sink_function=sig.func_name,
                                        tainted_param=sig.sink_param,
                                        cwe_id=sig.cwe_id,
                                        explanation=(
                                            f"Untrusted input originating in '{fpath}' at line {call_line} is passed into imported "
                                            f"function '{sig.func_name}()' and reaches an unparameterized {sig.sink_type} sink in '{sig.file_path}' at line {sig.sink_line}."
                                        ),
                                        source_snippet=call_snippet,
                                        sink_snippet=sig.sink_snippet,
                                        remediation_patch=(
                                            f"// In {fpath}: Pass clean bound parameters instead of raw tainted string\n"
                                            f"// In {sig.file_path}: Parameterize query sink with placeholders (? or %s)"
                                        )
                                    )
                                    cross_file_findings.append(finding)

        total_crit += len(cross_file_findings)
        total_issues = total_crit + total_sec + total_perf

        return {
            "success": True,
            "project_name": project_name,
            "files_scanned": len(file_contents),
            "file_findings": file_findings,
            "cross_file_findings": cross_file_findings,
            "file_contents": file_contents,
            "metrics": {
                "critical": total_crit,
                "security": total_sec,
                "performance": total_perf,
                "cross_file": len(cross_file_findings),
                "total": total_issues
            }
        }

    def _detect_sink_param(self, call_node: ast.Call, func_params: List[str], lines: List[str]) -> Optional[Tuple[str, int, str, str, str]]:
        """
        Determines if a Call node acts as an unparameterized sink for any function parameter.
        """
        # SQL sinks (cursor.execute, session.execute, raw)
        if isinstance(call_node.func, ast.Attribute) and call_node.func.attr in ("execute", "executemany", "raw", "text"):
            if call_node.args:
                arg0 = call_node.args[0]
                # Static string constants are 100% safe (e.g. cursor.execute("SELECT 1"))
                if isinstance(arg0, ast.Constant):
                    return None
                # SQLAlchemy text("SELECT 1") with static literal is safe
                if isinstance(arg0, ast.Call) and getattr(arg0.func, "id", getattr(arg0.func, "attr", None)) in ("text", "literal_column"):
                    if arg0.args and isinstance(arg0.args[0], ast.Constant):
                        return None

                for p in func_params:
                    # Exclude database connection/session handles
                    if p.lower() in ("db", "session", "conn", "connection", "cursor", "engine", "self", "cls"):
                        continue
                    # Parameter passed directly as SQL string without tuple
                    if (isinstance(arg0, ast.Name) and arg0.id == p) or any(isinstance(sub, ast.Name) and sub.id == p for sub in ast.walk(arg0)):
                        ln = call_node.lineno
                        snip = lines[ln - 1].strip() if 0 < ln <= len(lines) else f"execute({p})"
                        return ("SQL", ln, p, snip, "CWE-89")

        # Subprocess / OS command sinks
        if isinstance(call_node.func, ast.Attribute) and call_node.func.attr in ("system", "popen"):
            if call_node.args:
                for p in func_params:
                    if any(isinstance(sub, ast.Name) and sub.id == p for sub in ast.walk(call_node.args[0])):
                        ln = call_node.lineno
                        snip = lines[ln - 1].strip() if 0 < ln <= len(lines) else f"system({p})"
                        return ("Command", ln, p, snip, "CWE-78")

        if isinstance(call_node.func, ast.Attribute) and call_node.func.attr in ("run", "Popen", "call"):
            has_shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in call_node.keywords)
            if has_shell and call_node.args:
                for p in func_params:
                    if any(isinstance(sub, ast.Name) and sub.id == p for sub in ast.walk(call_node.args[0])):
                        ln = call_node.lineno
                        snip = lines[ln - 1].strip() if 0 < ln <= len(lines) else f"subprocess.{call_node.func.attr}({p}, ...)"
                        return ("Command", ln, p, snip, "CWE-78")

        # Insecure Deserialization sinks
        if isinstance(call_node.func, ast.Attribute) and call_node.func.attr in ("load", "loads"):
            is_deser = False
            if isinstance(call_node.func.value, ast.Name) and call_node.func.value.id in ("pickle", "yaml", "_pickle"):
                is_deser = True
            if is_deser and call_node.args:
                for p in func_params:
                    if any(isinstance(sub, ast.Name) and sub.id == p for sub in ast.walk(call_node.args[0])):
                        ln = call_node.lineno
                        snip = lines[ln - 1].strip() if 0 < ln <= len(lines) else f"deserialize({p})"
                        return ("Deserialization", ln, p, snip, "CWE-502")

        return None

    def _is_argument_tainted(self, arg_node: ast.AST) -> bool:
        """
        Determines whether a call argument carries dynamic/tainted user input
        (f-strings, string concatenations, function calls like request.args.get(), or dynamic variables).
        """
        # Dynamic f-string or concatenation
        if isinstance(arg_node, (ast.JoinedStr, ast.BinOp)):
            return True
        # Request object or input function call
        if isinstance(arg_node, ast.Call):
            return True
        # Attribute access like request.POST, req.body
        if isinstance(arg_node, ast.Attribute):
            return True
        # Variable name (e.g. user_query)
        if isinstance(arg_node, ast.Name):
            return True
        return False
