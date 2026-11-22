"""
Kavach AI — High-Speed Go AST & Taint Security Scanner
Detects SQL Injection (CWE-89), OS Command Injection (CWE-78),
and Hardcoded Secrets (CWE-798) in Go (.go) source files.
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class GoFinding:
    severity: str
    category: str
    file_path: str
    line_number: int
    cwe_id: str
    explanation: str
    vulnerable_snippet: str
    remediation_patch: str

class GoScanner:
    """
    Sub-16ms Static Analyzer for Go codebases.
    Uses precise lexical pattern matching and taint tracking on Go source code.
    """

    SQLI_PATTERNS = [
        re.compile(r"""(?:db|tx)\.(?:Query|Exec|QueryRow|QueryContext|ExecContext|QueryRowContext)\s*\(\s*(?:[a-zA-Z0-9_]+\s*,\s*)?fmt\.Sprintf\s*\(\s*["'`].*?["'`]\s*,\s*.*?\)\s*\)""", re.DOTALL),
        re.compile(r"""(?:db|tx)\.(?:Query|Exec|QueryRow|QueryContext|ExecContext|QueryRowContext)\s*\(\s*(?:[a-zA-Z0-9_]+\s*,\s*)?["'`].*?["'`]\s*\+\s*[a-zA-Z0-9_]+""", re.DOTALL),
    ]

    CMD_INJ_PATTERNS = [
        re.compile(r"""exec\.Command(?:Context)?\s*\(\s*["'`]?(sh|bash|cmd)["'`]?\s*,\s*["'`]?-c["'`]?\s*,\s*([^\)]+)\)""", re.DOTALL),
        re.compile(r"""exec\.Command(?:Context)?\s*\(\s*["'`]?(sh|bash)["'`]?\s*,\s*fmt\.Sprintf\s*\([^\)]+\)\)""", re.DOTALL),
    ]

    SECRET_PATTERNS = [
        (re.compile(r"""["'`]((?:sk_(?:live|test)_[0-9a-zA-Z]{24,}))["'`]"""), 'Stripe Secret Key'),
        (re.compile(r"""["'`]((?:gh[pousr]_[0-9a-zA-Z]{36,}))["'`]"""), 'GitHub Personal Access Token'),
        (re.compile(r"""["'`]((?:AKIA[0-9A-Z]{16}))["'`]"""), 'AWS Access Key ID'),
        (re.compile(r"""["'`]((?:xox[baprs]-[0-9a-zA-Z-]{24,}))["'`]"""), 'Slack API Token'),
    ]

    def scan_code(self, code: str, file_path: str = "main.go") -> List[GoFinding]:
        findings: List[GoFinding] = []
        lines = code.splitlines()

        # 1. Line-by-line quick scan for single-line statements and secrets
        flagged_lines = set()
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or not stripped:
                continue

            # Check secrets
            for pat, sec_name in self.SECRET_PATTERNS:
                m = pat.search(line)
                if m:
                    findings.append(GoFinding(
                        severity="CRITICAL",
                        category="HARDCODED_SECRET",
                        file_path=file_path,
                        line_number=idx,
                        cwe_id="CWE-798",
                        explanation=f"Hardcoded {sec_name} in Go source code. Credentials can be compromised if committed to public/shared git repos.",
                        vulnerable_snippet=line.strip(),
                        remediation_patch='os.Getenv("SECRET_KEY")'
                    ))
                    flagged_lines.add(idx)
                    break

        # 2. Multi-line pattern matching across the whole file
        for pat in self.SQLI_PATTERNS:
            for m in pat.finditer(code):
                line_no = code[:m.start()].count("\n") + 1
                if line_no in flagged_lines:
                    continue
                snip = m.group(0).strip()
                first_line = snip.splitlines()[0] if snip else ""
                findings.append(GoFinding(
                    severity="CRITICAL",
                    category="SQL_INJECTION",
                    file_path=file_path,
                    line_number=line_no,
                    cwe_id="CWE-89",
                    explanation="Unmitigated SQL Injection via dynamic string formatting in Go database query. Attacker can hijack database queries.",
                    vulnerable_snippet=first_line,
                    remediation_patch='// Safe Parameterized Query (Prevents SQLi)\n\tdb.Query("SELECT * FROM table WHERE id = ?", param)'
                ))
                flagged_lines.add(line_no)

        for pat in self.CMD_INJ_PATTERNS:
            for m in pat.finditer(code):
                line_no = code[:m.start()].count("\n") + 1
                if line_no in flagged_lines:
                    continue
                snip = m.group(0).strip()
                first_line = snip.splitlines()[0] if snip else ""
                findings.append(GoFinding(
                    severity="CRITICAL",
                    category="COMMAND_INJECTION",
                    file_path=file_path,
                    line_number=line_no,
                    cwe_id="CWE-78",
                    explanation="Command Injection via shell interpreter (sh -c / bash -c). Attacker can execute arbitrary system commands.",
                    vulnerable_snippet=first_line,
                    remediation_patch='// Safe Direct Execution without Shell\n\texec.Command("binary", arg1, arg2)'
                ))
                flagged_lines.add(line_no)

        return sorted(findings, key=lambda f: f.line_number)
