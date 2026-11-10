"""
Unit tests for Kavach AI Competitor Displacement Hunter (scripts/competitor_poacher.py)
Verifies competitor footprint detection (Snyk, Semgrep, SonarQube),
deduplication logic, pricing economics, and 1-click compose link generation.
"""

import os
import sys
import tempfile
import urllib.parse
from pathlib import Path

# Add project root to path
_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from scripts.competitor_poacher import (
    CompetitorPoacher,
    CompetitorFootprint,
    TargetAuditFinding,
    mask_secrets,
    is_deliverable_email,
    is_non_production_path
)

def test_competitor_footprint_detection_snyk():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        (root / ".snyk").write_text("# Snyk policy", encoding="utf-8")
        poacher = CompetitorPoacher()
        footprint = poacher.detect_competitor_footprints(root)
        assert footprint is not None
        assert footprint.primary_tool == "Snyk"
        assert footprint.pricing_estimate_yr == 6000
        assert footprint.savings_vs_kavach_yr == 5010
        assert footprint.savings_percent == 83.5

def test_competitor_footprint_detection_semgrep():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        wf_dir = root / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "semgrep.yml").write_text("uses: returntocorp/semgrep-action@v1", encoding="utf-8")
        poacher = CompetitorPoacher()
        footprint = poacher.detect_competitor_footprints(root)
        assert footprint is not None
        assert footprint.primary_tool == "Semgrep"
        assert footprint.pricing_estimate_yr == 4800
        assert footprint.savings_vs_kavach_yr == 3810
        assert footprint.savings_percent == 79.4

def test_competitor_footprint_detection_sonar():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        (root / "sonar-project.properties").write_text("sonar.projectKey=demo", encoding="utf-8")
        poacher = CompetitorPoacher()
        footprint = poacher.detect_competitor_footprints(root)
        assert footprint is not None
        assert footprint.primary_tool == "SonarQube"
        assert footprint.savings_vs_kavach_yr == 4410
        assert footprint.savings_percent == 81.7

def test_deduplication_ledger_filtering():
    with tempfile.TemporaryDirectory() as tmp_dir:
        ledger = Path(tmp_dir) / "LEDGER.md"
        ledger.write_text("""
| 1 | Airbyte (airbytehq/airbyte) | Tolik | tolik@airbyte.io | CWE-89 |
| 2 | Supabase (supabase/supabase) | Paul | security@supabase.io | CWE-78 |
""", encoding="utf-8")
        poacher = CompetitorPoacher(ledger_path=ledger)
        assert poacher.is_already_contacted("airbytehq/airbyte") is True
        assert poacher.is_already_contacted("unknown/project", "security@supabase.io") is True
        assert poacher.is_already_contacted("uncontacted/repo", "new@startup.io") is False

def test_compose_url_formatting_and_user_index():
    poacher = CompetitorPoacher()
    footprint = CompetitorFootprint(
        primary_tool="Semgrep",
        indicator_files=[".semgrep.yml"],
        pricing_estimate_yr=4800,
        savings_vs_kavach_yr=3810,
        savings_percent=79.4,
        seat_tax_cost_per_seat=480
    )
    finding = TargetAuditFinding(
        category_type="AST_CODE",
        severity="CRITICAL",
        rule_or_cwe="CWE-78",
        title="Remote Command Injection",
        file_path="routes/deploy.py",
        line_number=42,
        vulnerable_code="subprocess.call(cmd, shell=True)",
        remediation_patch="subprocess.run(shlex.split(cmd), check=True)",
        explanation="Untrusted input passed directly to shell interpreter."
    )
    lead = poacher.generate_pitch_and_links(
        repo_slug="acme/cloud-api",
        company_name="Acme Cloud",
        homepage="https://acme.io",
        competitor=footprint,
        maintainer_name="Alice Founder",
        maintainer_email="alice@acme.io",
        finding=finding
    )
    assert "mail.google.com/mail/u/2/" in lead.one_click_compose_url
    assert "to=alice%40acme.io" in lead.one_click_compose_url
    assert "Semgrep" in lead.one_click_compose_url
    assert "3%2C810" in lead.one_click_compose_url or "3810" in lead.one_click_compose_url
    assert "CWE-78" in lead.one_click_compose_url

def test_secret_masking_in_pitch():
    raw_secret = 'AWS_SECRET = \'' + 'AKIA' + '1234567890ABCDEF\'' + ' and stripe = \'' + 'sk_live_' + '123456789012345678901234\''
    masked = mask_secrets(raw_secret)
    assert "AKIA***" in masked
    assert "AKIA1234567890ABCDEF" not in masked
    assert "sk_live_***" in masked

def test_non_prod_directory_filtering():
    assert is_non_production_path("tests/unit/test_auth.py") is True
    assert is_non_production_path("fixtures/mock_db.py") is True
    assert is_non_production_path("demo/sample_app.py") is True
    assert is_non_production_path("apps/api/controllers/auth.py") is False
    assert is_non_production_path("src/core/database.ts") is False

def test_deliverable_email_validation():
    assert is_deliverable_email("founder@getacme.com") is True
    assert is_deliverable_email("cto@enterprise.io") is True
    assert is_deliverable_email("12345+bot@users.noreply.github.com") is False
    assert is_deliverable_email("dependabot[bot]@github.com") is False
    assert is_deliverable_email("invalid-email") is False
