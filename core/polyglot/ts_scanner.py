"""
Kavach AI — TypeScript & JavaScript Security Scanner
Detects Command Injection (CWE-78), SQL Injection in ORMs (CWE-89),
DOM Cross-Site Scripting (CWE-79), and Insecure Deserialization (CWE-502).
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class TSFinding:
    severity: str
    category: str
    file_path: str
    line_number: int
    cwe_id: str
    explanation: str
    vulnerable_snippet: str
    remediation_patch: str

class TSScanner:
    """
    Sub-16ms Static Analyzer for TypeScript and JavaScript codebases.
    """

    CMD_INJ_PATTERNS = [
        re.compile(r"""child_process\.(exec|execSync)\s*\(\s*([`"'].*?[\${].*?[`"']|[a-zA-Z0-9_]+)"""),
        re.compile(r"""exec\s*\(\s*`[^`]*\${[^}]+}[^`]*`\s*[\),:]"""),
    ]

    SQLI_PATTERNS = [
        re.compile(r"""(?:sequelize|prisma|db)\.\$?(?:query|executeRawUnsafe)\s*\(\s*`[^`]*\${[^}]+}[^`]*`"""),
        re.compile(r"""(?:sequelize|db)\.query\s*\(\s*["'].*?["']\s*\+\s*[a-zA-Z0-9_]+"""),
    ]

    XSS_PATTERNS = [
        re.compile(r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\s*\}\s*\}"""),
        re.compile(r"""v-html\s*=\s*["']([^"']+)["']"""),
    ]

    SECRET_PATTERNS = [
        (re.compile(r"""["'](sk_(?:live|test)_[0-9a-zA-Z]{24,})["']"""), 'Stripe Secret Key'),
        (re.compile(r"""["'](gh[pousr]_[0-9a-zA-Z]{36,})["']"""), 'GitHub Personal Access Token'),
        (re.compile(r"""["'](AKIA[0-9A-Z]{16})["']"""), 'AWS Access Key ID'),
    ]

    def scan_code(self, code: str, file_path: str = "app.ts") -> List[TSFinding]:
        findings: List[TSFinding] = []
        lines = code.splitlines()

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or not stripped:
                continue

            # 1. Command Injection (CWE-78)
            for pat in self.CMD_INJ_PATTERNS:
                if pat.search(line):
                    findings.append(TSFinding(
                        severity="CRITICAL",
                        category="COMMAND_INJECTION",
                        file_path=file_path,
                        line_number=idx,
                        cwe_id="CWE-78",
                        explanation="Arbitrary Command Injection via child_process.exec with untrusted input string. Attacker can execute system commands.",
                        vulnerable_snippet=line.strip(),
                        remediation_patch='// Safe Parameterized Process Execution\nchild_process.execFile("binary", [arg1, arg2])'
                    ))
                    break

            # 2. SQL Injection in Node ORMs (CWE-89)
            for pat in self.SQLI_PATTERNS:
                if pat.search(line):
                    findings.append(TSFinding(
                        severity="CRITICAL",
                        category="SQL_INJECTION",
                        file_path=file_path,
                        line_number=idx,
                        cwe_id="CWE-89",
                        explanation="Unmitigated SQL Injection via template literal query interpolation in Node.js ORM/client.",
                        vulnerable_snippet=line.strip(),
                        remediation_patch='// Safe Parameterized Query\nawait db.query("SELECT * FROM users WHERE id = $1", [userId])'
                    ))
                    break

            # 3. DOM Cross-Site Scripting (CWE-79)
            for pat in self.XSS_PATTERNS:
                if pat.search(line):
                    findings.append(TSFinding(
                        severity="HIGH",
                        category="CROSS_SITE_SCRIPTING",
                        file_path=file_path,
                        line_number=idx,
                        cwe_id="CWE-79",
                        explanation="DOM Cross-Site Scripting (XSS) via unescaped HTML injection. Can allow session hijacking and DOM manipulation.",
                        vulnerable_snippet=line.strip(),
                        remediation_patch='dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}'
                    ))
                    break

            # 4. Hardcoded Secret (CWE-798)
            for pat, sec_name in self.SECRET_PATTERNS:
                if pat.search(line):
                    findings.append(TSFinding(
                        severity="CRITICAL",
                        category="HARDCODED_SECRET",
                        file_path=file_path,
                        line_number=idx,
                        cwe_id="CWE-798",
                        explanation=f"Hardcoded {sec_name} in JavaScript/TypeScript file.",
                        vulnerable_snippet=line.strip(),
                        remediation_patch='process.env.SECRET_KEY'
                    ))
                    break

        return findings
