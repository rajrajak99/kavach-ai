"""
Kavach AI — CISO Multi-Repo Risk & Compliance Control Plane
Aggregates security posture across 500+ repositories and outputs executive
SOC 2 / ISO 27001 / HIPAA continuous compliance evidence.
"""

from typing import List, Dict, Any
from dataclasses import dataclass, field

@dataclass
class RepoRiskProfile:
    repo_name: str
    total_files: int
    critical_findings: int
    high_findings: int
    is_ci_gate_active: bool
    soc2_cc6_1_status: str
    soc2_cc7_1_status: str

class CISOCompliancePlane:
    """
    Centralized Enterprise Risk Control Plane.
    Calculates organization-wide security index (0-100%).
    """

    def __init__(self, organization_name: str):
        self.organization_name = organization_name
        self.repos: List[RepoRiskProfile] = []

    def register_repo_scan(
        self,
        repo_name: str,
        total_files: int,
        critical_count: int,
        high_count: int,
        has_ci_gate: bool = True
    ) -> RepoRiskProfile:
        cc6_status = "PASS" if critical_count == 0 else "FAIL"
        cc7_status = "PASS" if high_count == 0 else "ACTION_REQUIRED"
        
        profile = RepoRiskProfile(
            repo_name=repo_name,
            total_files=total_files,
            critical_findings=critical_count,
            high_findings=high_count,
            is_ci_gate_active=has_ci_gate,
            soc2_cc6_1_status=cc6_status,
            soc2_cc7_1_status=cc7_status
        )
        self.repos.append(profile)
        return profile

    def compute_organization_score(self) -> Dict[str, Any]:
        """Computes aggregate CISO Executive Index (0 to 100%)."""
        if not self.repos:
            return {"score": 100, "grade": "A+", "total_repos": 0, "status": "NO_REPOS_TRACKED"}

        total_critical = sum(r.critical_findings for r in self.repos)
        total_high = sum(r.high_findings for r in self.repos)
        unprotected_repos = sum(1 for r in self.repos if not r.is_ci_gate_active)

        # Base score 100, penalize for vulnerabilities and missing CI gates
        score = 100 - (total_critical * 10) - (total_high * 3) - (unprotected_repos * 5)
        score = max(0, min(100, score))

        if score >= 90:
            grade = "A (Enterprise Ready)"
        elif score >= 75:
            grade = "B (Good Posture)"
        elif score >= 60:
            grade = "C (Remediation Needed)"
        else:
            grade = "F (High Breach Risk)"

        return {
            "organization": self.organization_name,
            "total_repos_audited": len(self.repos),
            "aggregate_score": score,
            "security_grade": grade,
            "total_critical_vulnerabilities": total_critical,
            "total_high_vulnerabilities": total_high,
            "soc2_compliance_rate": f"{round((sum(1 for r in self.repos if r.soc2_cc6_1_status == 'PASS') / len(self.repos)) * 100, 1)}%",
            "executive_status": "Audit Ready" if score >= 85 else "Remediate Criticals"
        }
