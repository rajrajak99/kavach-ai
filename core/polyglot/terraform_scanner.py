"""
Kavach AI — Terraform & Infrastructure as Code (IaC) Security Scanner
Detects Open S3 Buckets, Wildcard Security Groups, and Unencrypted Resources in Terraform (.tf).
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class TerraformFinding:
    severity: str
    category: str
    file_path: str
    line_number: int
    cwe_id: str
    explanation: str
    vulnerable_snippet: str
    remediation_patch: str

class TerraformScanner:
    """
    Fast AST/regex-based IaC security gate for Terraform configurations.
    """

    OPEN_S3_PATTERNS = [
        re.compile(r"""acl\s*=\s*["']public-read(?:-write)?["']"""),
        re.compile(r"""block_public_acls\s*=\s*false"""),
        re.compile(r"""ignore_public_acls\s*=\s*false"""),
    ]

    WILDCARD_SG_PATTERNS = [
        re.compile(r"""cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0/0["']\s*\]"""),
    ]

    UNENCRYPTED_STORAGE = [
        re.compile(r"""encrypted\s*=\s*false"""),
        re.compile(r"""storage_encrypted\s*=\s*false"""),
    ]

    def scan_code(self, code: str, file_path: str = "main.tf") -> List[TerraformFinding]:
        findings: List[TerraformFinding] = []
        lines = code.splitlines()

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue

            # 1. Open S3 Bucket
            for pat in self.OPEN_S3_PATTERNS:
                if pat.search(line):
                    findings.append(TerraformFinding(
                        severity="CRITICAL",
                        category="CLOUD_MISCONFIGURATION",
                        file_path=file_path,
                        line_number=idx,
                        cwe_id="CWE-732",
                        explanation="Publicly readable S3 Bucket access configured in Terraform. Leaves cloud storage exposed to internet.",
                        vulnerable_snippet=line.strip(),
                        remediation_patch='acl = "private"\n  block_public_acls = true'
                    ))
                    break

            # 2. Wildcard Ingress Security Group
            for pat in self.WILDCARD_SG_PATTERNS:
                if pat.search(line):
                    findings.append(TerraformFinding(
                        severity="HIGH",
                        category="CLOUD_MISCONFIGURATION",
                        file_path=file_path,
                        line_number=idx,
                        cwe_id="CWE-284",
                        explanation="Security Group allows unrestricted ingress from 0.0.0.0/0 on sensitive ports.",
                        vulnerable_snippet=line.strip(),
                        remediation_patch='cidr_blocks = [var.vpc_cidr_block] # Restrict to internal VPC'
                    ))
                    break

            # 3. Unencrypted Storage
            for pat in self.UNENCRYPTED_STORAGE:
                if pat.search(line):
                    findings.append(TerraformFinding(
                        severity="HIGH",
                        category="INSECURE_CONFIGURATION",
                        file_path=file_path,
                        line_number=idx,
                        cwe_id="CWE-311",
                        explanation="Storage volume configured with encryption disabled. Violates SOC 2 CC6.1 and HIPAA encryption mandates.",
                        vulnerable_snippet=line.strip(),
                        remediation_patch='encrypted = true'
                    ))
                    break

        return findings
