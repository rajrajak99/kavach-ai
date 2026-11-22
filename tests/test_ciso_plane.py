import pytest
from core.ciso_plane import CISOCompliancePlane

def test_ciso_compliance_plane_scoring():
    plane = CISOCompliancePlane("Acme Global Enterprises")
    plane.register_repo_scan("backend-api", total_files=100, critical_count=0, high_count=0, has_ci_gate=True)
    plane.register_repo_scan("frontend-app", total_files=80, critical_count=0, high_count=1, has_ci_gate=True)
    plane.register_repo_scan("billing-svc", total_files=50, critical_count=1, high_count=2, has_ci_gate=True)

    summary = plane.compute_organization_score()
    assert summary["organization"] == "Acme Global Enterprises"
    assert summary["total_repos_audited"] == 3
    assert summary["total_critical_vulnerabilities"] == 1
    assert summary["total_high_vulnerabilities"] == 3
    assert summary["aggregate_score"] == 81
    assert summary["security_grade"] == "B (Good Posture)"
    assert summary["executive_status"] == "Remediate Criticals"

def test_ciso_compliance_plane_all_clean():
    plane = CISOCompliancePlane("Secure Corp")
    plane.register_repo_scan("clean-repo", total_files=50, critical_count=0, high_count=0, has_ci_gate=True)
    summary = plane.compute_organization_score()
    assert summary["aggregate_score"] == 100
    assert summary["executive_status"] == "Audit Ready"
    assert summary["soc2_compliance_rate"] == "100.0%"
